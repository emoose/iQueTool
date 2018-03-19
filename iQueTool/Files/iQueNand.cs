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
        public List<iQueFsHeader> FsHeaders;
        // read table as signed so we can treat end-of-chain and sys-allocated blocks as negative numbers
        // if there were more than 0x8000 blocks in a nand we really shouldn't do this, but luckily there aren't
        public List<List<short>> FsAllocationTables;
        public List<List<iQueFsInode>> FsInodes;

        public iQueFsHeader MainFs;
        public int MainFsBlock;
        public int MainFsIndex = -1;

        public List<iQueFsInode> MainFsInodes
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
        
        public iQueArrayFile<iQueTitleData> Tickets; // ticket.sys
        public iQueArrayFile<iQueCertificateRevocation> CRL; // crl.sys
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

                // read SA1 ticket area
                int sa1TicketBlock = curDataBlock;
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                byte[] sa1TicketData = io.Reader.ReadBytes(BLOCK_SZ);

                var sa1Ticket = Shared.BytesToStruct<iQueETicket>(sa1TicketData);
                sa1Ticket.EndianSwap();

                sksa.Writer.Write(sa1TicketData);

                // get next good block after SA1 ticket (which will be SA1 final block)
                curDataBlock = GetNextGoodBlock(curDataBlock);
                int sa1FinalDataBlock = curDataBlock;

                int numDataBlocks = (int)(sa1Ticket.ContentSize / BLOCK_SZ);
                byte[] sa1Data = new byte[sa1Ticket.ContentSize];
                for (int i = numDataBlocks - 1; i >= 0; i--)
                {
                    io.Stream.Position = curDataBlock * BLOCK_SZ;
                    byte[] curData = io.Reader.ReadBytes(BLOCK_SZ);
                    Array.Copy(curData, 0, sa1Data, i * BLOCK_SZ, BLOCK_SZ);

                    lastDataBlock = curDataBlock;
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                }
                sksa.Writer.Write(sa1Data);

                // read SA2 ticket area
                int sa2TicketBlock = curDataBlock;
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                byte[] sa2TicketData = io.Reader.ReadBytes(BLOCK_SZ);

                var sa2Ticket = Shared.BytesToStruct<iQueETicket>(sa2TicketData);
                sa2Ticket.EndianSwap();

                if(sa2Ticket.AuthorityString.StartsWith("Root")) // if SA2 is valid...
                {
                    sksa.Writer.Write(sa2TicketData);

                    // get next good block after SA2 ticket (which will be SA2 final block)
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                    int sa2FinalDataBlock = curDataBlock;

                    numDataBlocks = (int)(sa2Ticket.ContentSize / BLOCK_SZ);
                    byte[] sa2Data = new byte[sa2Ticket.ContentSize];
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
            byte[] spareData = new byte[NUM_SYS_AREA_BLOCKS];
            for (int i = 0; i < spareData.Length; i++)
                spareData[i] = 0xFF;

            var sksa = new iQueKernel(sksaData);
            sksa.Read();

            // write SK data
            io.Stream.Position = 0;
            io.Writer.Write(sksa.SKData);

            int lastDataBlock = 0;
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

            int numDataBlocks = (int)(sksa.SA1SigArea.Ticket.ContentSize / BLOCK_SZ);
            for (int i = numDataBlocks - 1; i >= 0; i--)
            {
                byte[] data = new byte[BLOCK_SZ];
                Array.Copy(sksa.SA1Data, i * BLOCK_SZ, data, 0, BLOCK_SZ);

                io.Stream.Position = curDataBlock * BLOCK_SZ;
                io.Writer.Write(data);

                lastDataBlock = curDataBlock;
                curDataBlock = GetNextGoodBlock(curDataBlock);
                if (i > 0)
                    spareData[curDataBlock] = (byte)lastDataBlock;
            }

            spareData[sa1TicketBlock] = (byte)lastDataBlock; // set SA1 ticket spare to point to first SA1 block

            if (!sksa.SA2IsValid)
                spareData[sa1FinalDataBlock] = 0xFF; // set SA1 final block spare to 0xFF if theres no SA following this
            else
            {
                spareData[sa1FinalDataBlock] = (byte)curDataBlock; // set SA1 final block spare to SA2 ticket block

                // write SA2 ticket area
                int sa2TicketBlock = curDataBlock;
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                io.Writer.Write(new byte[BLOCK_SZ]);
                io.Stream.Position = curDataBlock * BLOCK_SZ;
                io.Writer.Write(sksa.SA2SigArea.GetBytes());

                // get next good block after SA2 ticket (which will be SA2 final block)
                curDataBlock = GetNextGoodBlock(curDataBlock);
                int sa2FinalDataBlock = curDataBlock;

                numDataBlocks = (int)(sksa.SA2SigArea.Ticket.ContentSize / BLOCK_SZ);
                for (int i = numDataBlocks - 1; i >= 0; i--)
                {
                    byte[] data = new byte[BLOCK_SZ];
                    Array.Copy(sksa.SA2Data, i * BLOCK_SZ, data, 0, BLOCK_SZ);

                    io.Stream.Position = curDataBlock * BLOCK_SZ;
                    io.Writer.Write(data);

                    lastDataBlock = curDataBlock;
                    curDataBlock = GetNextGoodBlock(curDataBlock);
                    if(i > 0)
                        spareData[curDataBlock] = (byte)lastDataBlock;
                }

                spareData[sa2TicketBlock] = (byte)lastDataBlock; // set SA2 ticket spare to point to first SA2 block
                spareData[sa2FinalDataBlock] = 0xff; // set SA2 final block spare to 0xFF
            }

            // write out our new SKSA spare data
            // (TODO: fix up GenerateSpareData to work with bad-blocks like the above, so that this wouldn't be needed!)

            using (var spareIO = new IO(FilePath + ".sksa_spare", FileMode.OpenOrCreate))
            {
                for (int i = 0; i < spareData.Length; i++)
                {
                    if (MainFsAllocTable[i] == FAT_BLOCK_BAD)
                    {
                        spareIO.Writer.Write(new byte[0x10]); // bad blocks get no spare data
                        continue;
                    }
                    spareIO.Writer.Write(spareData[i]);
                    spareIO.Writer.Write(spareData[i]);
                    spareIO.Writer.Write(spareData[i]);
                    for (int y = 3; y < 0x10; y++)
                        spareIO.Writer.Write((byte)0xFF); // seems ique_diag/iqahc always send all FF as the spare (except for the 3 SAArea bytes written above), so this should be fine?
                }
            }

            io.Stream.Flush();

            Console.WriteLine("Updated SKSA!");
            Console.WriteLine("Wrote updated nand to " + FilePath);
            Console.WriteLine("Wrote SKSA spare-area to " + FilePath + ".sksa_spare");

            // reload this.SKSA
            SKSA = new iQueKernel(GetSKSAData());
            SKSA.Read();

            return true;
        }

        public byte[] GetInodeData(iQueFsInode inode)
        {
            var data = new byte[inode.Size];
            var chain = GetBlockChain(inode.BlockIdx);

            for(int i = 0; i < chain.Length; i++)
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
                var data = GetInodeData(MainFsInodes[idx]);
                Certs = new iQueCertCollection(data);
                if (iQueCertCollection.MainCollection == null)
                    iQueCertCollection.MainCollection = new iQueCertCollection(data); // MainCollection wasn't loaded already, so lets try loading it from this nand (yolo)
            }

            idx = GetInodeIdx("depot.sys");
            HasPrivateData = idx >= 0;
            if(HasPrivateData)
            {
                var data = GetInodeData(MainFsInodes[idx]);
                PrivateData = Shared.BytesToStruct<iQuePrivateData>(data);
                //PrivateData.EndianSwap();
            }

            idx = GetInodeIdx("ticket.sys");
            if(idx >= 0)
            {
                var data = GetInodeData(MainFsInodes[idx]);
                Tickets = new iQueArrayFile<iQueTitleData>(data);
                for (int i = 0; i < Tickets.Count; i++)
                    Tickets[i] = Tickets[i].EndianSwap();
            }

            idx = GetInodeIdx("crl.sys");
            if (idx >= 0)
            {
                var data = GetInodeData(MainFsInodes[idx]);
                CRL = new iQueArrayFile<iQueCertificateRevocation>(data);
                foreach (var crl in CRL)
                    crl.EndianSwap();
            }

            // todo:
            // recrypt.sys
            // timer.sys
            // sig.db

            return true;
        }

        private bool ReadFilesystem()
        {
            FsHeaders = new List<iQueFsHeader>();
            FsBlocks = new List<int>();
            FsBadBlocks = new List<int>();
            FsInodes = new List<List<iQueFsInode>>();
            FsAllocationTables = new List<List<short>>();

            int latestSeqNo = -1;
            for (int i = 0; i < NUM_FAT_BLOCKS; i++)
            {
                var blockNum = (NUM_BLOCKS_IN_FAT - 1) - i; // read FAT area from end to beginning
                SeekToBlock(blockNum);

                io.Stream.Position += FS_HEADER_ADDR;
                var header = io.Reader.ReadStruct<iQueFsHeader>();
                header.EndianSwap();
                if (header.Magic != MAGIC_BBFS) // todo: && header.Magic != MAGIC_BBFL, once we know what BBFL/"linked fats" actually are
                    continue;

                if(!SkipVerifyFsChecksums && InodesOffset == 0) // only care about fs checksum if this is a proper dump and we aren't using hacky InodesOffset hack
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
                var inodes = new List<iQueFsInode>();
                for (int y = 0; y < numEntries; y++)
                {
                    var inode = io.Reader.ReadStruct<iQueFsInode>();
                    inode.EndianSwap();
                    inodes.Add(inode);
                }

                FsAllocationTables.Add(allocTable);
                FsInodes.Add(inodes);
            }

            return latestSeqNo >= 0;
        }

        public bool VerifyFsChecksum(iQueFsHeader fatHeader, int fatBlockIdx)
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

                // fix SA-area spare bytes
                {
                    var sa1Blk = (byte)(SKSA.SA1Addr / 0x4000);
                    var sa1NumBlks = SKSA.SA1SigArea.Ticket.ContentSize / 0x4000;

                    var sa2Blk = (byte)(SKSA.SA2IsValid ? SKSA.SA2Addr / 0x4000 : -1);

                    // SA1 license spare (writes SA1 end block num)
                    for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                    {
                        fixedStream.Position = ((sa1Blk * spareEntriesPerBlock) + blockPageNum) * 0x10;
                        var sa1EndBlk = (byte)(sa1Blk + sa1NumBlks);
                        for (int i = 0; i < 3; i++)
                            fixedStream.WriteByte(sa1EndBlk);
                    }

                    // SA1 1st block spare (writes block num of next SA license block)
                    for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                    {
                        fixedStream.Position = (((sa1Blk + 1) * spareEntriesPerBlock) + blockPageNum) * 0x10;
                        for (int i = 0; i < 3; i++)
                            fixedStream.WriteByte(sa2Blk);
                    }

                    // SA1 nth block spare (writes block num of n-1 / previous SA data block)
                    for (int curBlk = 2; curBlk <= sa1NumBlks; curBlk++)
                    {
                        var curBlkNum = sa1Blk + curBlk;
                        for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                        {
                            fixedStream.Position = ((curBlkNum * spareEntriesPerBlock) + blockPageNum) * 0x10;
                            for (int i = 0; i < 3; i++)
                                fixedStream.WriteByte((byte)(curBlkNum - 1));
                        }
                    }

                    if (sa2Blk != 0xFF)
                    {
                        var sa2NumBlks = SKSA.SA2SigArea.Ticket.ContentSize / 0x4000;

                        // SA2 license spare (writes SA2 end block num)
                        for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                        {
                            fixedStream.Position = ((sa2Blk * spareEntriesPerBlock) + blockPageNum) * 0x10;
                            var sa2EndBlk = (byte)(sa2Blk + sa2NumBlks);
                            for (int i = 0; i < 3; i++)
                                fixedStream.WriteByte(sa2EndBlk);
                        }

                        // SA2 1st block spare (writes block num of next SA license block)
                        for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                        {
                            fixedStream.Position = (((sa2Blk + 1) * spareEntriesPerBlock) + blockPageNum) * 0x10;
                            for (int i = 0; i < 3; i++)
                                fixedStream.WriteByte(0xFF);
                        }

                        // SA2 nth block spare (writes block num of n-1 / previous SA data block)
                        for (int curBlk = 2; curBlk <= sa2NumBlks; curBlk++)
                        {
                            var curBlkNum = sa2Blk + curBlk;

                            for (int blockPageNum = 0; blockPageNum < spareEntriesPerBlock; blockPageNum++)
                            {
                                fixedStream.Position = ((curBlkNum * spareEntriesPerBlock) + blockPageNum) * 0x10;
                                for (int i = 0; i < 3; i++)
                                    fixedStream.WriteByte((byte)(curBlkNum - 1));
                            }
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

            b.AppendLine($"MainFs (@ 0x{(MainFsBlock * BLOCK_SZ):X}):");
            b.AppendLine($"  SeqNo: {MainFs.SeqNo}");
            b.AppendLine($"  CheckSum: {MainFs.CheckSum}");
            b.AppendLine($"  NumFiles: {MainFsInodes.FindAll(s => s.Valid == 1).Count}");
            b.AppendLine();
            for(int i = 0; i < MainFsInodes.Count; i++)
            {
                if (MainFsInodes[i].Valid != 1)
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

                    b.AppendLine($"Fs-{i} (@ 0x{(FsBlocks[i] * BLOCK_SZ):X})");
                    b.AppendLine($"  SeqNo: {FsHeaders[i].SeqNo}");
                    b.AppendLine($"  CheckSum: {FsHeaders[i].CheckSum}");
                    b.AppendLine($"  NumFiles: {FsInodes[i].FindAll(s => s.Valid == 1).Count}");
                    b.AppendLine();
                    for (int y = 0; y < FsInodes[i].Count; y++)
                    {
                        if (FsInodes[i][y].Valid != 1)
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
    }
}
