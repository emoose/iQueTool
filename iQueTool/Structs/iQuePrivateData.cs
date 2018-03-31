using System;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQuePrivateData
    {
        /* 0x0  */ public uint BBID;
        /* 0x4  */ public uint Timestamp;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)]
        /* 0x8  */ public char[] BBModel;

        /* 0x2C */ public uint SecureContentId; // SKSA content id
        /* 0x30 */ public uint CrlVersion;

        public string BBModelString
        {
            get
            {
                return Shared.NullTermCharsToString(BBModel).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public DateTime TimestampDateTime
        {
            get
            {
                return Shared.UnixTimeStampToDateTime(Timestamp);
            }
        }

        public void EndianSwap()
        {
            BBID = BBID.EndianSwap();
            Timestamp = Timestamp.EndianSwap();

            SecureContentId = SecureContentId.EndianSwap();
            CrlVersion = CrlVersion.EndianSwap();
        }

        public byte[] GetBytes()
        {
            EndianSwap(); // back to device endian (BE)
            byte[] bytes = Shared.StructToBytes(this);
            EndianSwap(); // back to native endian (LE)
            return bytes;
        }

        public override string ToString()
        {
            return ToString(false);
        }

        public string ToString(bool formatted, string header = "iQuePrivateData")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            b.AppendLineSpace(fmt + $"BB Model: {BBModelString}");
            b.AppendLineSpace(fmt + $"BBID: 0x{BBID:X}");
            b.AppendLineSpace(fmt + $"Timestamp: {TimestampDateTime} ({Timestamp})");
            b.AppendLineSpace(fmt + $"SecureContentId: {SecureContentId}");
            b.AppendLineSpace(fmt + $"CrlVersion: {CrlVersion}");

            return b.ToString();
        }
    }
}
