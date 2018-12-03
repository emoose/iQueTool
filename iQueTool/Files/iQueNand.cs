using System;
using System.Collections.Generic;
using System.Text;
using iQueTool.Structs;
using System.IO;

namespace iQueTool.Files
{
    public class iQueNand
    {
        public const int BLOCK_SZ = 0x4000;

        public const int NUM_SK_BLOCKS = 4;
        public const int NUM_FAT_BLOCKS = 0x10;
        public const int NUM_SYS_AREA_BLOCKS = 0x40; // 0x100000 bytes, but theres some SKSAs that are larger??
        public const int NUM_SYS_AREA_BLOCKS_DEV = 0x100; // largest SKSA is 0xE9 blocks, so I guess dev units probably had 0x100 for SKSA area

        public const int NUM_BLOCKS_IN_FAT = 0x1000;
        public const int NUM_FS_ENTRIES = 0x199;
        public const int FS_HEADER_ADDR = 0x3FF4;

        public const int MAGIC_BBFS = 0x42424653;
        public const int MAGIC_BBFL = 0x4242464C;

        public const short FAT_BLOCK_FREE = 0;
        public const short FAT_BLOCK_LAST = -1; // 0xffff for last block in chain (this block doesn't point to another)
        public const short FAT_BLOCK_BAD = -2; // 0xfffe for bad blocks
        public const short FAT_BLOCK_RESERVED = -3; // 0xfffd for SK/SA (reserved) blocks

        private IO io;
        public string FilePath;
        public int InodesOffset = 0; // only public ique dump is sorta mangled, inodes start 0x10 bytes away from where they should for some reason
        public bool SkipVerifyFsChecksums = false;

        public List<int> FsBlocks;
        public List<int> FsBadBlocks;

        // todo: put next 3 fields in an iQueNandFs class?
        public List<BbFat16> FsHeaders;
        // read table as signed so we can treat end-of-chain and sys-allocated blocks as negative numbers
        // if there were more than 0x8000 blocks in a nand we really shouldn't do this, but luckily there aren't
        public List<List<short>> FsAllocationTables;
        public List<List<BbInode>> FsInodes;

        public BbFat16 MainFs;
        public int MainFsBlock;
        public int MainFsIndex = -1;

        public List<BbInode> ModifiedInodes;
        public List<short> ModifiedAllocTable;

        public List<BbInode> MainFsInodes
        {
            get
            {
                if (MainFsIndex < 0)
                    return null;

                return FsInodes[MainFsIndex];
            }
        }

        public List<short> MainFsAllocTable
        {
            get
            {
                if (MainFsIndex < 0)
                    return null;

                return FsAllocationTables[MainFsIndex];
            }
        }

        // different sections/files of the NAND
        public iQueKernel SKSA;

        public bool HasPrivateData = false;
        public iQuePrivateData PrivateData; // depot.sys
        
        public iQueArrayFile<OSBbSaGameMetaData> Tickets; // ticket.sys
        public iQueArrayFile<BbCrlHead> CRL; // crl.sys
        public iQueCertCollection Certs; // cert.sys

        public iQueNand(string filePath)
        {
            FilePath = filePath;
            io = new IO(filePath);
        }

        public void SeekToBlock(int blockIdx)
        {
            io.Stream.Position = blockIdx * BLOCK_SZ;
        }

        public int GetInodeIdx(string fileName)
        {
            if (MainFsIndex < 0)
                return -1;

            for(int i = 0; i < MainFsInodes.Count; i++)
                if(MainFsInodes[i].NameString.ToLower() == fileName.ToLower())
                    return i;

            return -1;
        }

        public short[] GetBlockChain(short blockIdx, int maxBlocks = int.MaxValue)
        {
            var chain = new List<short>();
            var curBlock = blockIdx;

            do
            {
                chain.Add(curBlock);
                curBlock = MainFsAllocTable[curBlock];
            }
            while (curBlock >= 0 && (maxBlocks == int.MaxValue || chain.Count < maxBlocks)); // if curBlock is negative (eg 0xFFFD or 0xFFFF) stop following the chain

            return chain.ToArray();
        }

        public int GetNextGoodBlock(int blockNum)
        {
            for (int i = blockNum + 1; i < NUM_BLOCKS_IN_FAT; i++)
                if (MainFsAllocTable[i] != FAT_BLOCK_BAD)
                    return i;

            return -1;
        }

        public byte[] GetSKSAData()
        {
            using (var ms = new MemoryStream())
            {
                var sksa = new IO(ms);

                // read SK data
                io.Stream.Position = 0;
                sksa.Writer.Write(io.Reader.ReadBytes(NUM_SK_BLOCKS * BLOCK_SZ));

                int lastDataBlock = 0;
                int curDataBlock = NUM_SK_BLOCKS;

                // read SA1 metadata area
                int sa1MetadataBlock = curDataBlock;
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                byte[] sa1MetaDataBytes = io.Reader.ReadBytes(BLOCK_SZ);

                var sa1Metadata = Shared.BytesToStruct<BbContentMetadataHead>(sa1MetaDataBytes);
                sa1Metadata.EndianSwap();

                sksa.Writer.Write(sa1MetaDataBytes);

                // get next good block after SA1 metadata (which will be SA1 final block)
                curDataBlock = GetNextGoodBlock(curDataBlock);
                int sa1FinalDataBlock = curDataBlock;

                int numDataBlocks = (int)(sa1Metadata.ContentSize / BLOCK_SZ);
                byte[] sa1Data = new byte[sa1Metadata.ContentSize];
                for (int i = numDataBlocks - 1; i >= 0; i--)
                {
                    io.Stream.Position = curDataBlock * BLOCK_SZ;
                    byte[] curData = io.Reader.ReadBytes(BLOCK_SZ);
                    Array.Copy(curData, 0, sa1Data, i * BLOCK_SZ, BLOCK_SZ);

                    lastDataBlock = curDataBlock;
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                }
                sksa.Writer.Write(sa1Data);

                // read SA2 metadata area
                int sa2MetadataBlock = curDataBlock;
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                byte[] sa2MetadataBytes = io.Reader.ReadBytes(BLOCK_SZ);

                var sa2Metadata = Shared.BytesToStruct<BbContentMetadataHead>(sa2MetadataBytes);
                sa2Metadata.EndianSwap();

                if(sa2Metadata.AuthorityString.StartsWith("Root")) // if SA2 is valid...
                {
                    sksa.Writer.Write(sa2MetadataBytes);

                    // get next good block after SA2 metadata (which will be SA2 final block)
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                    int sa2FinalDataBlock = curDataBlock;

                    numDataBlocks = (int)(sa2Metadata.ContentSize / BLOCK_SZ);
                    byte[] sa2Data = new byte[sa2Metadata.ContentSize];
                    for (int i = numDataBlocks - 1; i >= 0; i--)
                    {
                        io.Stream.Position = curDataBlock * BLOCK_SZ;
                        byte[] curData = io.Reader.ReadBytes(BLOCK_SZ);
                        Array.Copy(curData, 0, sa2Data, i * BLOCK_SZ, BLOCK_SZ);

                        lastDataBlock = curDataBlock;
                        curDataBlock = GetNextGoodBlock(curDataBlock);
                    }
                    sksa.Writer.Write(sa2Data);
                }

                return ms.ToArray();
            }
        }

        public bool SetSKSAData(string sksaPath)
        {
            return SetSKSAData(File.ReadAllBytes(sksaPath));
        }

        public bool SetSKSAData(byte[] sksaData)
        {
            var sksa = new iQueKernel(sksaData);
            sksa.Read();

            // write SK data
            io.Stream.Position = 0;
            io.Writer.Write(sksa.SKData);

            int lastDataBlock = -1;
            int curDataBlock = NUM_SK_BLOCKS;

            // write SA1 ticket area
            int sa1TicketBlock = curDataBlock;
            io.Stream.Position = curDataBlock * BLOCK_SZ;
            io.Writer.Write(new byte[BLOCK_SZ]);
            io.Stream.Position = curDataBlock * BLOCK_SZ;
            io.Writer.Write(sksa.SA1SigArea.GetBytes());

            // get next good block after SA1 ticket (which will be SA1 final block)
            curDataBlock = GetNextGoodBlock(curDataBlock);
            int sa1FinalDataBlock = curDataBlock;

            int numDataBlocks = (int)(sksa.SA1SigArea.ContentMetadata.ContentSize / BLOCK_SZ);
            for (int i = numDataBlocks - 1; i >= 0; i--)
            {
                byte[] data = new byte[BLOCK_SZ];
                Array.Copy(sksa.SA1Data, i * BLOCK_SZ, data, 0, BLOCK_SZ);

                io.Stream.Position = curDataBlock * BLOCK_SZ;
                io.Writer.Write(data);

                lastDataBlock = curDataBlock;
                curDataBlock = GetNextGoodBlock(curDataBlock);
            }

            if (sksa.SA2IsValid)
            {
                // write SA2 ticket area
                int sa2TicketBlock = curDataBlock;
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                io.Writer.Write(new byte[BLOCK_SZ]);
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                io.Writer.Write(sksa.SA2SigArea.GetBytes());

                // get next good block after SA2 ticket (which will be SA2 final block)
                curDataBlock = GetNextGoodBlock(curDataBlock);
                int sa2FinalDataBlock = curDataBlock;

                numDataBlocks = (int)(sksa.SA2SigArea.ContentMetadata.ContentSize / BLOCK_SZ);
                for (int i = numDataBlocks - 1; i >= 0; i--)
                {
                    byte[] data = new byte[BLOCK_SZ];
                    Array.Copy(sksa.SA2Data, i * BLOCK_SZ, data, 0, BLOCK_SZ);

                    io.Stream.Position = curDataBlock * BLOCK_SZ;
                    io.Writer.Write(data);

                    lastDataBlock = curDataBlock;
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                }
            }

            io.Stream.Flush();

            Console.WriteLine("Updated SKSA!");
            Console.WriteLine("Wrote updated nand to " + FilePath);

            // reload this.SKSA
            SKSA = new iQueKernel(GetSKSAData());
            SKSA.Read();

            return true;
        }

        public bool Read()
        {
            var numBlocks = (int)(io.Stream.Length / BLOCK_SZ);

            if(numBlocks != NUM_BLOCKS_IN_FAT)
                return false; // invalid image

            var ret = ReadFilesystem();
            if (!ret)
                return false; // failed to find valid FAT

            SKSA = new iQueKernel(GetSKSAData());
            SKSA.Read();

            int idx = GetInodeIdx("cert.sys");
            if (idx >= 0)
            {
                var data = FileRead(MainFsInodes[idx]);
                Certs = new iQueCertCollection(data);
                if (iQueCertCollection.MainCollection == null)
                    iQueCertCollection.MainCollection = new iQueCertCollection(data); // MainCollection wasn't loaded already, so lets try loading it from this nand (yolo)
            }

            idx = GetInodeIdx("depot.sys");
            HasPrivateData = idx >= 0;
            if(HasPrivateData)
            {
                var data = FileRead(MainFsInodes[idx]);
                PrivateData = Shared.BytesToStruct<iQuePrivateData>(data);
                //PrivateData.EndianSwap();
            }

            idx = GetInodeIdx("ticket.sys");
            if(idx >= 0)
            {
                var data = FileRead(MainFsInodes[idx]);
                Tickets = new iQueArrayFile<OSBbSaGameMetaData>(data);
                for (int i = 0; i < Tickets.Count; i++)
                    Tickets[i] = Tickets[i].EndianSwap();
            }

            idx = GetInodeIdx("crl.sys");
            if (idx >= 0)
            {
                var data = FileRead(MainFsInodes[idx]);
                CRL = new iQueArrayFile<BbCrlHead>(data);
                foreach (var crl in CRL)
                    crl.EndianSwap();
            }

            // todo:
            // recrypt.sys
            // timer.sys
            // sig.db

            return true;
        }

        public void RepairFsChecksum(int fatBlockIdx)
        {
            io.Stream.Position = fatBlockIdx * BLOCK_SZ;

            ushort sum = 0;
            for (int i = 0; i < 0x1FFF; i++)
                sum += io.Reader.ReadUInt16().EndianSwap();

            ushort res = (ushort)(0xCAD7 - sum);
            io.Stream.Position = (fatBlockIdx * BLOCK_SZ) + 0x3FFE;
            io.Writer.Write(res.EndianSwap()); // todo: reload FS / change FsHeaders[x].CheckSum
        }

        public void RepairFsChecksums()
        {
            foreach (var block in FsBlocks)
                RepairFsChecksum(block);
        }

        public bool VerifyFsChecksum(BbFat16 fatHeader, int fatBlockIdx)
        {
            io.Stream.Position = (fatBlockIdx * BLOCK_SZ);

            ushort sum = 0;
            for (int i = 0; i < 0x1FFF; i++)
                sum += io.Reader.ReadUInt16().EndianSwap();

            sum += fatHeader.CheckSum; // should be EndianSwap'd already by ReadFilesystem
            return sum == 0xCAD7;
        }

        public bool VerifyFsChecksum(int fsIndex)
        {
            if (fsIndex < 0 || fsIndex >= FsHeaders.Count || fsIndex >= FsBlocks.Count)
                return false;

            var fatHeader = FsHeaders[fsIndex];
            var fatBlockIdx = FsBlocks[fsIndex];

            return VerifyFsChecksum(fatHeader, fatBlockIdx);
        }

        public byte[] GenerateSpareData(bool blockSpare, byte[] oldSpare = null)
        {
            int pageSkip = blockSpare ? 0x1F : 0; // block-spares only include the last page of each block

            using (var fixedStream = new MemoryStream())
            {
                var numPages = io.Stream.Length / 0x200;
                var numSpareEntries = blockSpare ? io.Stream.Length / 0x4000 : numPages;
                var spareEntriesPerBlock = blockSpare ? 1 : 0x20;

                if (oldSpare != null)
                    fixedStream.Write(oldSpare, 0, oldSpare.Length);
                else
                {
                    // init empty spare
                    for (int i = 0; i < (numSpareEntries * 0x10); i++)
                        fixedStream.WriteByte(0xFF);
                }

                // fix SA-area spare bytes (first 3 bytes of spare, only set for SA1/SA2 blocks)
                {
                    // write 0xFF as SAData for the SK
                    fixedStream.Position = 0;
                    for(int blockNum = 0; blockNum < NUM_SK_BLOCKS; blockNum++)
                    {
                        for(int page = 0; page < spareEntriesPerBlock; page++)
                        {
                            fixedStream.WriteByte(0xFF);
                            fixedStream.WriteByte(0xFF);
                            fixedStream.WriteByte(0xFF);
                            fixedStream.Position += (0x10 - 3);
                        }
                    }

                    int lastDataBlock = -1;
                    int curDataBlock = NUM_SK_BLOCKS;

                    int sa1TicketBlock = curDataBlock;

                    // get next good block after SA1 ticket (which will be SA1 final block)
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                    int sa1FinalDataBlock = curDataBlock;

                    // loop through SA1 in reverse and write SA data block SAData fields
                    int numDataBlocks = (int)(SKSA.SA1SigArea.ContentMetadata.ContentSize / BLOCK_SZ);
                    for (int i = numDataBlocks - 1; i >= 0; i--)
                    {
                        lastDataBlock = curDataBlock;
                        curDataBlock = GetNextGoodBlock(curDataBlock);
                        if (i > 0)
                        {
                            fixedStream.Position = (curDataBlock * spareEntriesPerBlock) * 0x10;
                            for (int page = 0; page < spareEntriesPerBlock; page++)
                            {
                                fixedStream.WriteByte((byte)lastDataBlock);
                                fixedStream.WriteByte((byte)lastDataBlock);
                                fixedStream.WriteByte((byte)lastDataBlock);
                                fixedStream.Position += (0x10 - 3);
                            }
                        }
                    }

                    // write SA1 ticket block SAData
                    fixedStream.Position = (sa1TicketBlock * spareEntriesPerBlock) * 0x10;
                    for (int page = 0; page < spareEntriesPerBlock; page++)
                    {
                        fixedStream.WriteByte((byte)lastDataBlock);
                        fixedStream.WriteByte((byte)lastDataBlock);
                        fixedStream.WriteByte((byte)lastDataBlock);
                        fixedStream.Position += (0x10 - 3);
                    }

                    // write SA1 final data block SAData (points to SA2 ticket block, or 0xFF)
                    byte sa1FinalSAData = 0xFF;
                    if (SKSA.SA2IsValid)
                        sa1FinalSAData = (byte)curDataBlock;

                    fixedStream.Position = (sa1FinalDataBlock * spareEntriesPerBlock) * 0x10;
                    for (int page = 0; page < spareEntriesPerBlock; page++)
                    {
                        fixedStream.WriteByte((byte)sa1FinalSAData);
                        fixedStream.WriteByte((byte)sa1FinalSAData);
                        fixedStream.WriteByte((byte)sa1FinalSAData);
                        fixedStream.Position += (0x10 - 3);
                    }

                    // if we have SA2, fix up the SAData for that too
                    if(SKSA.SA2IsValid)
                    { 
                        // write SA2 ticket area
                        int sa2TicketBlock = curDataBlock;

                        // get next good block after SA2 ticket (which will be SA2 final block)
                        curDataBlock = GetNextGoodBlock(curDataBlock);
                        int sa2FinalDataBlock = curDataBlock;

                        // loop through SA2 in reverse and write SA2 data block SAData fields
                        numDataBlocks = (int)(SKSA.SA2SigArea.ContentMetadata.ContentSize / BLOCK_SZ);
                        for (int i = numDataBlocks - 1; i >= 0; i--)
                        {
                            lastDataBlock = curDataBlock;
                            curDataBlock = GetNextGoodBlock(curDataBlock);
                            if (i > 0)
                            {
                                fixedStream.Position = (curDataBlock * spareEntriesPerBlock) * 0x10;
                                for (int page = 0; page < spareEntriesPerBlock; page++)
                                {
                                    fixedStream.WriteByte((byte)lastDataBlock);
                                    fixedStream.WriteByte((byte)lastDataBlock);
                                    fixedStream.WriteByte((byte)lastDataBlock);
                                    fixedStream.Position += (0x10 - 3);
                                }
                            }
                        }

                        // write SA2 ticket block SAData (points to first SA2 data block)
                        fixedStream.Position = (sa2TicketBlock * spareEntriesPerBlock) * 0x10;
                        for (int page = 0; page < spareEntriesPerBlock; page++)
                        {
                            fixedStream.WriteByte((byte)lastDataBlock);
                            fixedStream.WriteByte((byte)lastDataBlock);
                            fixedStream.WriteByte((byte)lastDataBlock);
                            fixedStream.Position += (0x10 - 3);
                        }

                        // write SA2 final data block SAData (0xFF)
                        fixedStream.Position = (sa2FinalDataBlock * spareEntriesPerBlock) * 0x10;
                        for (int page = 0; page < spareEntriesPerBlock; page++)
                        {
                            fixedStream.WriteByte((byte)0xFF);
                            fixedStream.WriteByte((byte)0xFF);
                            fixedStream.WriteByte((byte)0xFF);
                            fixedStream.Position += (0x10 - 3);
                        }
                    }
                }

                // fix ECC bytes
                int spareNum = 0;
                for (int pageNum = pageSkip; pageNum < numPages; pageNum += (pageSkip + 1), spareNum++)
                {
                    fixedStream.Position = spareNum * 0x10;
                    fixedStream.Position += 6;
                    fixedStream.WriteByte((byte)(blockSpare ? 0 : 0xFF)); // block-spare has 0x00 at 6th byte in spare

                    fixedStream.Position += 1; // 0x8 into spare (ECC area)

                    io.Stream.Position = (pageNum * 0x200);
                    byte[] pageData = io.Reader.ReadBytes(0x200);
                    byte[] ecc = iQueBlockSpare.Calculate512Ecc(pageData);
                    fixedStream.Write(ecc, 0, 8);
                }

                // null out badblock spares based on badblock entries in the FAT
                if(MainFsAllocTable != null)
                {
                    for(int blockNum = 0; blockNum < NUM_BLOCKS_IN_FAT; blockNum++)
                    {
                        if (MainFsAllocTable[blockNum] != FAT_BLOCK_BAD)
                            continue;

                        for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                        {
                            fixedStream.Position = ((blockNum * spareEntriesPerBlock) + blockPageNum) * 0x10;
                            for (int i = 0; i < 0x10; i++)
                                fixedStream.WriteByte(0);
                        }
                    }
                }

                return fixedStream.ToArray();
            }
        }

        public override string ToString()
        {
            return ToString(false);
        }

        public string ToString(bool formatted, bool fsInfoOnly = true, bool allFsInfo = false)
        {
            var b = new StringBuilder();
            b.AppendLine("iQueNand:");

            b.AppendLine($"MainFs (0x{(MainFsBlock * BLOCK_SZ):X} / block {MainFsBlock}):");
            b.AppendLine($"  SeqNo: {MainFs.SeqNo}");
            b.AppendLine($"  CheckSum: {MainFs.CheckSum}");
            b.AppendLine($"  NumFiles: {MainFsInodes.FindAll(s => s.Type == 1).Count}");
            b.AppendLine();
            for(int i = 0; i < MainFsInodes.Count; i++)
            {
                if (MainFsInodes[i].Type != 1)
                    continue;
                b.AppendLine("  " + MainFsInodes[i].ToString(i));
            }

            if(allFsInfo)
            {
                for(int i = 0; i < FsHeaders.Count; i++)
                {
                    if (FsBlocks[i] == MainFsBlock)
                        continue;

                    b.AppendLine();

                    b.AppendLine($"Fs-{i} (0x{(FsBlocks[i] * BLOCK_SZ):X} / block {FsBlocks[i]})");
                    b.AppendLine($"  SeqNo: {FsHeaders[i].SeqNo}");
                    b.AppendLine($"  CheckSum: {FsHeaders[i].CheckSum}");
                    b.AppendLine($"  NumFiles: {FsInodes[i].FindAll(s => s.Type == 1).Count}");
                    b.AppendLine();
                    for (int y = 0; y < FsInodes[i].Count; y++)
                    {
                        if (FsInodes[i][y].Type != 1)
                            continue;
                        b.AppendLine("  " + FsInodes[i][y].ToString(y));
                    }
                }
            }

            if (fsInfoOnly)
                return b.ToString();

            b.AppendLine();

            if (HasPrivateData)
                b.AppendLine(PrivateData.ToString(formatted, "iQuePrivateData (depot.sys)"));
            else
                b.AppendLine("Failed to read iQuePrivateData struct from depot.sys :(");

            if (SKSA != null)
            {
                b.AppendLine(SKSA.ToString(formatted));

                b.AppendLine();
            }

            if (Tickets != null)
            {
                b.AppendLine($"Num tickets: {Tickets.Count}");
                for (int i = 0; i < Tickets.Count; i++)
                    b.AppendLine(Tickets[i].ToString(formatted, $"iQueTitleData-{i}"));
            }
            else
                b.AppendLine("Failed to read iQueTitleData array from ticket.sys :(");

            if (CRL != null)
                b.AppendLine(CRL.ToString(formatted));
            else
                b.AppendLine("Failed to read iQueCertificateRevocation array from crl.sys :(");

            if (Certs != null)
                b.AppendLine(Certs.ToString(formatted));
            else
                b.AppendLine("Failed to read iQueCertificate array from cert.sys :(");

            return b.ToString();
        }

        public void CreateModifiedInodes()
        {
            if (ModifiedInodes != null)
                return;

            ModifiedInodes = new List<BbInode>();
            foreach(var node in MainFsInodes)
            {
                var newNode = new BbInode();
                ModifiedInodes.Add(newNode.Copy(node));
            }

            ModifiedAllocTable = new List<short>();
            foreach(var alloc in MainFsAllocTable)
            {
                ModifiedAllocTable.Add(alloc);
            }

            var newSeqNo = MainFs.SeqNo + 1;

            MainFs = new BbFat16();
            MainFs.Magic = MAGIC_BBFS;
            MainFs.SeqNo = newSeqNo;
            MainFs.Link = 0;
            MainFs.CheckSum = 0;

            FsHeaders.Add(MainFs);
            FsInodes.Add(ModifiedInodes);
            FsAllocationTables.Add(ModifiedAllocTable);

            MainFsIndex = FsHeaders.Count - 1;
        }

        public byte[] GetChainData(short[] chain)
        {
            var data = new byte[chain.Length * 0x4000];

            for (int i = 0; i < chain.Length; i++)
            {
                io.Stream.Position = chain[i] * BLOCK_SZ;

                int numRead = BLOCK_SZ;

                var blockData = io.Reader.ReadBytes(numRead);
                Array.Copy(blockData, 0, data, i * BLOCK_SZ, numRead);
            }

            return data;
        }

        public byte[] FileRead(BbInode inode)
        {
            var data = new byte[inode.Size];
            var chain = GetBlockChain(inode.BlockIdx);

            for (int i = 0; i < chain.Length; i++)
            {
                io.Stream.Position = chain[i] * BLOCK_SZ;

                int numRead = BLOCK_SZ;
                if (i + 1 == chain.Length)
                    numRead = (int)(inode.Size % BLOCK_SZ);
                if (numRead == 0)
                    numRead = BLOCK_SZ;

                var blockData = io.Reader.ReadBytes(numRead);
                Array.Copy(blockData, 0, data, i * BLOCK_SZ, numRead);
            }

            return data;
        }

        public bool FileDelete(string fileName)
        {
            BbInode foundNode = new BbInode();
            bool found = false;
            foreach(var node in MainFsInodes)
            {
                if(node.NameString == fileName)
                {
                    foundNode = node;
                    found = true;
                }
            }

            if (!found)
                return false;

            // make sure we have a modified inodes collection ready...
            CreateModifiedInodes();

            // find node in modified inodes..
            found = false;
            foreach (var node in ModifiedInodes)
            {
                if (node.NameString == fileName)
                {
                    foundNode = node;
                    found = true;
                }
            }
            if (!found)
                return false;

            // deallocate all blocks used by the file
            var chain = GetBlockChain(foundNode.BlockIdx);
            foreach(var block in chain)
                ModifiedAllocTable[block] = FAT_BLOCK_FREE;

            // remove file from inode collection
            ModifiedInodes.Remove(foundNode);

            return true;
        }

        public bool FileDelete(BbInode node)
        {
            var name = node.NameString;
            return FileDelete(name);
        }

        public short[] TryAllocateBlocks(int numBlocks)
        {
            var blockList = new List<short>();

            for(int i = 0; i < numBlocks; i++)
            {
                bool foundUnused = false;
                for(short block = NUM_SYS_AREA_BLOCKS; block < NUM_BLOCKS_IN_FAT; block++)
                {
                    if(MainFsAllocTable[block] == FAT_BLOCK_FREE && !blockList.Contains(block))
                    {
                        // found one!
                        blockList.Add(block);
                        foundUnused = true;
                        break;
                    }
                }

                if(!foundUnused)
                    return null; // couldn't find enough unused blocks :(
            }

            // make sure we have a modified alloc table ready...
            CreateModifiedInodes();

            for (int i = 0; i < blockList.Count; i++)
            {
                var blockNum = blockList[i];
                var nextBlock = FAT_BLOCK_LAST;
                if (i < blockList.Count - 1)
                    nextBlock = blockList[i + 1];

                ModifiedAllocTable[blockNum] = nextBlock;
            }

            return blockList.ToArray();
        }

        public bool FileWrite(string fileName, byte[] fileData, ref BbInode newNode)
        {
            newNode = new BbInode();
            newNode.NameString = fileName;
            newNode.Type = 1;
            newNode.Size = (uint)fileData.Length;

            // remove any existing file with this name
            FileDelete(newNode.NameString);

            // make sure we have a modified inodes collection ready...
            CreateModifiedInodes();

            int numBlocks = (fileData.Length + (BLOCK_SZ - 1)) / BLOCK_SZ;
            var blockList = TryAllocateBlocks(numBlocks);
            if (blockList == null)
                return false; // couldn't find enough unused blocks :(
            
            // start writing the file data!
            for(int i = 0; i < numBlocks; i++)
            {
                int dataOffset = i * BLOCK_SZ;
                int numWrite = BLOCK_SZ;
                if (dataOffset + numWrite > fileData.Length)
                    numWrite = fileData.Length % BLOCK_SZ;

                SeekToBlock(blockList[i]);
                io.Stream.Write(fileData, dataOffset, numWrite);
            }
            newNode.BlockIdx = blockList[0];

            // add new inode to inode list...
            // make seperate inode to provided one, to make sure nothing can change after adding it to inode list

            var realNewNode = new BbInode();
            realNewNode.Copy(newNode);
            ModifiedInodes.Add(realNewNode);

            var chain = GetBlockChain(newNode.BlockIdx);

            // success!
            return true;
        }

        private bool ReadFilesystem()
        {
            FsHeaders = new List<BbFat16>();
            FsBlocks = new List<int>();
            FsBadBlocks = new List<int>();
            FsInodes = new List<List<BbInode>>();
            FsAllocationTables = new List<List<short>>();

            int latestSeqNo = -1;
            for (int i = 0; i < NUM_FAT_BLOCKS; i++)
            {
                var blockNum = (NUM_BLOCKS_IN_FAT - 1) - i; // read FAT area from end to beginning
                SeekToBlock(blockNum);

                io.Stream.Position += FS_HEADER_ADDR;
                var header = io.Reader.ReadStruct<BbFat16>();
                header.EndianSwap();
                if (header.Magic != MAGIC_BBFS) // todo: && header.Magic != MAGIC_BBFL, once we know what BBFL/"linked fats" actually are
                    continue;

                if (!SkipVerifyFsChecksums && InodesOffset == 0) // only care about fs checksum if this is a proper dump and we aren't using hacky InodesOffset hack
                    if (!VerifyFsChecksum(header, blockNum))
                    {
                        FsBadBlocks.Add(blockNum);
                        continue; // bad FS checksum :(
                    }

                FsHeaders.Add(header);
                FsBlocks.Add(blockNum);

                if (header.SeqNo > latestSeqNo)
                {
                    MainFs = header;
                    MainFsBlock = blockNum;
                    MainFsIndex = FsHeaders.Count - 1;
                    latestSeqNo = header.SeqNo;
                }

                io.Stream.Position = blockNum * BLOCK_SZ;
                var allocTable = new List<short>();
                for (int y = 0; y < NUM_BLOCKS_IN_FAT; y++)
                    allocTable.Add((short)(io.Reader.ReadUInt16().EndianSwap()));

                int numEntries = NUM_FS_ENTRIES;
                if (InodesOffset > 0)
                {
                    io.Stream.Position += InodesOffset; // skip weird truncated inode if needed
                    numEntries--; // and now we'll have to read one less entry
                }

                // now begin reading inodes
                var inodes = new List<BbInode>();
                for (int y = 0; y < numEntries; y++)
                {
                    var inode = io.Reader.ReadStruct<BbInode>();
                    inode.EndianSwap();
                    inodes.Add(inode);
                }
                var invalidInodes = new List<int>();
                for (int y = 0; y < inodes.Count; y++)
                    if (!inodes[y].IsValid)
                        invalidInodes.Add(y);

                for(int y = invalidInodes.Count - 1; y >= 0; y--)
                    inodes.RemoveAt(invalidInodes[y]);

                FsAllocationTables.Add(allocTable);
                FsInodes.Add(inodes);
            }

            return latestSeqNo >= 0;
        }

        public bool WriteFilesystem()
        {
            if (ModifiedInodes == null)
                return true; // nothing to write...

            int destBlock = -1;
            int lowestSeqNo = -1;
            int lowestSeqNoBlock = -1;
            for (int i = 0; i < NUM_FAT_BLOCKS; i++)
            {
                var blockNum = (NUM_BLOCKS_IN_FAT - 1) - i; // read FAT area from end to beginning

                // check bad block...
                if (MainFsAllocTable[blockNum] == FAT_BLOCK_BAD)
                    continue;

                SeekToBlock(blockNum);

                io.Stream.Position += FS_HEADER_ADDR;
                var header = io.Reader.ReadStruct<BbFat16>();
                header.EndianSwap();
                if (header.Magic != MAGIC_BBFS) // todo: && header.Magic != MAGIC_BBFL, once we know what BBFL/"linked fats" actually are
                {
                    // no BBFS header here - perfect!
                    destBlock = blockNum;
                    break;
                }
                if(header.SeqNo == MainFs.SeqNo) // if this blocks seqNo is the same as our modded seqNo it's probably from this instance, so lets just overwrite that
                {
                    destBlock = blockNum;
                    break;
                }
                if(lowestSeqNo == -1 || lowestSeqNo > header.SeqNo)
                {
                    lowestSeqNo = header.SeqNo;
                    lowestSeqNoBlock = blockNum;
                }
            }
            
            if (destBlock == -1) // all FS blocks are used, lets overwrite the oldest one
                destBlock = lowestSeqNoBlock;

            if (destBlock == -1)
                return false; // wtf?

            // null out block
            SeekToBlock(destBlock);
            io.Writer.Write(new byte[BLOCK_SZ]);

            SeekToBlock(destBlock);

            // write alloc table...
            for (int i = 0; i < NUM_BLOCKS_IN_FAT; i++)
                io.Writer.Write(ModifiedAllocTable[i].EndianSwap());

            // write inodes...
            foreach(var inode in ModifiedInodes)
            {
                inode.EndianSwap();
                io.Writer.WriteStruct(inode);
                inode.EndianSwap();
            }
            SeekToBlock(destBlock);
            io.Stream.Position += FS_HEADER_ADDR;

            // write FS header...
            MainFs.EndianSwap();
            io.Writer.WriteStruct(MainFs);
            MainFs.EndianSwap();

            // add FS as FS block...
            if (!FsBlocks.Contains(destBlock))
                FsBlocks.Add(destBlock);

            // fix FS checksum...
            RepairFsChecksum(destBlock);

            // complete!
            return true;
        }
    }
}
