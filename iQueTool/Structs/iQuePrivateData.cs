using System;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQuePrivateData
    {
        public uint BBID;
        public uint Timestamp;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)]
        public char[] BBModel;

        public uint SecureContentId; // SKSA content id
        public uint CrlVersion;

        public string BBModelString
        {
            get
            {
                return BBModel == null ? String.Empty : new string(BBModel).Replace("\0", "").Replace("\r", "").Replace("\n", "");
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
