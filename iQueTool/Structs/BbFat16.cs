using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace iQueTool.Structs
{
    // FAT header is at (fs_addr + 0x3FF4) in NAND, highest seqno is the best FAT
    // ique_diag seems to go through each block (highest to lowest) and check Magic = *(DWORD*)(blockAddr + 0x3ff4), if Magic is "BBFS" then it checks if the seqno is the highest
    // there's also BBFL for "linked fats", the dump I have doesn't have any of those though, i assume they're for when the FAT overflows
    // also afaik the top section of the nand is reserved for these FATs, so that it doesn't need to scan the entire nand i guess
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct BbFat16
    {
        /* 0x0 */ public uint Magic;
        /* 0x4 */ public int SeqNo;
        /* 0x8 */ public ushort Link;
        /* 0xA */ public ushort CheckSum; // all dwords in (fs+0 : fs+0x2000) added together + this checksum must equal 0xCAD7?

        public void EndianSwap()
        {
            Magic = Magic.EndianSwap();
            SeqNo = SeqNo.EndianSwap();
            Link = Link.EndianSwap();
            CheckSum = CheckSum.EndianSwap();
        }
    }

    // inode table starts at (fs_addr + 0x2000), with 0x199 max entries
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct BbInode
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x8)]
        /* 0x00 */ public char[] Name;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3)]
        /* 0x08 */ public char[] Extension;
        /* 0x0B */ public byte Type;
        /* 0x0C */ public short BlockIdx; // offset = BlockIdx * 0x4000, BlockIdx can sometimes be -1 for some reason?

        /* 0x0E */ public ushort PaddingE; // ique_diag only uses a WORD for the blockidx, so this must just be padding

        /* 0x10 */ public uint Size;

        public string NameString
        {
            get
            {
                if (Name == null && Extension == null)
                    return String.Empty;
                var name = Shared.NullTermCharsToString(Name).Replace("\0", "").Replace("\r", "").Replace("\n", "");
                var ext = Shared.NullTermCharsToString(Extension).Replace("\0", "").Replace("\r", "").Replace("\n", "");
                return $"{name}.{ext}";
            }
            set
            {
                var filename = value;
                var extension = "";
                var extIdx = value.IndexOf(".");

                if(extIdx > -1 && filename.Length > (extIdx+1))
                {
                    extension = filename.Substring(extIdx + 1);
                    filename = filename.Substring(0, extIdx);
                }

                if (filename.Length > 8)
                    filename = filename.Substring(0, 8);
                if (extension.Length > 3)
                    extension = extension.Substring(0, 3);

                // make sure name = 8 chars and extension = 3 chars
                var nameList = new List<char>(filename.ToCharArray());
                var extList = new List<char>(extension.ToCharArray());
                if (nameList.Count < 8)
                    nameList.AddRange(new char[8 - nameList.Count]);
                if (extList.Count < 8)
                    extList.AddRange(new char[3 - extList.Count]);

                Name = nameList.ToArray();
                Extension = extList.ToArray();
            }
        }

        public bool IsValid
        {
            get
            {
                return Type == 1 && BlockIdx != -1;
            }
        }
        
        public BbInode Copy(BbInode source)
        {
            Name = new char[8];
            
            for (int i = 0; i < 8; i++)
                Name[i] = source.Name[i];

            Extension = new char[3];
            for (int i = 0; i < 3; i++)
                Extension[i] = source.Extension[i];

            Type = source.Type;
            BlockIdx = source.BlockIdx;
            PaddingE = source.PaddingE;
            Size = source.Size;

            return this;
        }
        
        public void EndianSwap()
        {
            BlockIdx = (short)((ushort)BlockIdx).EndianSwap();
            PaddingE = PaddingE.EndianSwap();
            Size = Size.EndianSwap();
        }

        public override string ToString()
        {
            return ToString(-1);
        }

        public string ToString(int idx)
        {
            var ret = $"name {NameString} block {BlockIdx} size 0x{Size:X} type {Type}";
            if (Type == 1 && !IsValid)
                ret += " (has 'valid' field set, but uses invalid block idx?)";

            if (idx == -1)
                return ret;
            return $"{idx}: {ret}";
        }
    }
}
