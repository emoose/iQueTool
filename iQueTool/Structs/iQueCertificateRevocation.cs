using System;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueCertificateRevocation
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x200)]
        public byte[] Signature;

        public uint Unk200;
        public uint Unk204;
        public uint Unk208;
        public uint Unk20C;

        public uint Timestamp;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        public char[] Authority;

        public uint Unk254;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        public char[] CertName;

        public string AuthorityString
        {
            get
            {
                return Authority == null ? String.Empty : new string(Authority).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public string CertNameString
        {
            get
            {
                return CertName == null ? String.Empty : new string(CertName).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public DateTime TimestampDateTime
        {
            get
            {
                return Shared.UnixTimeStampToDateTime(Timestamp);
            }
        }

        public iQueCertificateRevocation EndianSwap()
        {
            Unk200 = Unk200.EndianSwap();
            Unk204 = Unk204.EndianSwap();
            Unk208 = Unk208.EndianSwap();
            Unk20C = Unk20C.EndianSwap();

            Timestamp = Timestamp.EndianSwap();

            Unk254 = Unk254.EndianSwap();

            return this;
        }

        public byte[] GetBytes()
        {
            EndianSwap(); // back to ticket-file endian (BE)
            byte[] bytes = Shared.StructToBytes(this);
            EndianSwap(); // back to native endian (LE)
            return bytes;
        }

        public override string ToString()
        {
            return ToString(true);
        }

        public string ToString(bool formatted, string header = "iQueCertificateRevocation")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            b.AppendLineSpace(fmt + $"CertName: {CertNameString}");
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");
            b.AppendLineSpace(fmt + $"Timestamp: {TimestampDateTime} ({Timestamp})");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Unk200: 0x{Unk200:X}");
            b.AppendLineSpace(fmt + $"Unk204: 0x{Unk204:X}");
            b.AppendLineSpace(fmt + $"Unk208: 0x{Unk208:X}");
            b.AppendLineSpace(fmt + $"Unk20C: 0x{Unk20C:X}");
            b.AppendLine();
            b.AppendLineSpace(fmt + $"Unk254: 0x{Unk254:X}");

            return b.ToString();
        }
    }
}
