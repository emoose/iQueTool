using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    // set via iQue Club app? (was removed in later sysupdates and replaced with iQue Club inside iQue@Home afaik)
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueUserData
    {
        public int Unk0; // always 1?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x82)]
        public byte[] Unk4;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x2C)]
        public char[] Data86; // password maybe?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x9F)]
        public char[] DataB2;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x11)]
        public char[] Data151; // phone #?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0xF)]
        public char[] Data162; // name?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x7)]
        public char[] Data171;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x5A)]
        public char[] Data178;

        public char Data1D2; // seen 2 and 0

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3E2D)]
        public byte[] Unk1D3;
    }
}
