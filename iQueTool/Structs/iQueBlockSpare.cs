using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    // format of the BB-returned block-spare data, which seems slightly different to the actual on-chip page-spare data?
    // seems BB returns only the last page's spare data for each block read (0x20 pages per block), while setting 0x6 to 0x00 for some reason
    // when writing BB is sent all FF as spare data, the unit must be recalcing the ECC itself before writing?
    // spare is returned as all 00 for bad blocks
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueBlockSpare
    {
        public byte Unk0;
        public byte Unk1;
        public byte Unk2;
        public byte Unk3; // always FF?
        public byte Unk4; // always FF?
        public byte BadBlockIndicator; // any bit unset means bad block (each bit is checked seperately.. each bit counts as 4 pages (4 pages = each 2048-byte part?))
        public byte Unk6; // always 00? (0xFF in page spares)
        public byte Unk7; // always FF?

        // next fields are the ECC?
        // is all FF in pages that are either all 00 or all FF (or blocks where the last page is all 00/all FF)
        public byte Unk8;
        public byte Unk9;
        public byte UnkA;
        public byte UnkB; // always FF?
        public byte UnkC; // always FF?
        public byte UnkD;
        public byte UnkE;
        public byte UnkF;
    }
}
