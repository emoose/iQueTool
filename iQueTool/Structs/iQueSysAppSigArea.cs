using System;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    // SK = secure kernel?
    // SA = system app?
    // SK format:
    // 0x0 - 0x10000: unk (kernel?)
    // 0x10000 - 0x14000: SA1 sigarea
    // 0x14000 - (0x14000 + Signature.ContentSize): SA1
    // (0x14000 + Signature.ContentSize) - (0x14000 + Signature.ContentSize + 0x4000): SA2 sigarea
    // (0x14000 + Signature.ContentSize + 0x4000) - EOF: SA2
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueSysAppSigArea
    {
        public iQueETicket Ticket;
        public iQueCertificate Certificate;
        public iQueCertificate Authority;
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x38)]
        public byte[] Unk8CC;

        public uint RevocationAddr;
        public uint RevocationNameAddr;
        public uint AuthorityAddr;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        public byte[] Unk910;

        public iQueCertificateRevocation Revocation;

        public void EndianSwap()
        {
            Ticket.EndianSwap();
            Certificate.EndianSwap();
            Authority.EndianSwap();

            RevocationAddr = RevocationAddr.EndianSwap();
            RevocationNameAddr = RevocationNameAddr.EndianSwap();
            AuthorityAddr = AuthorityAddr.EndianSwap();

            Revocation.EndianSwap();
        }

        public override string ToString()
        {
            return ToString(false);
        }

        public string ToString(bool formatted, string header = "iQueSysAppSigArea")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            b.AppendLineSpace(fmt + $"RevocationAddr: 0x{RevocationAddr:X}");
            b.AppendLineSpace(fmt + $"RevocationNameAddr: 0x{RevocationNameAddr:X}");
            b.AppendLineSpace(fmt + $"AuthorityAddr: 0x{AuthorityAddr:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk8CC:" + Environment.NewLine + fmt + Unk8CC.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk910:" + Environment.NewLine + fmt + Unk910.ToHexString());

            b.AppendLine();
            b.AppendLine(Ticket.ToString(formatted, header + ".iQueETicket"));
            b.AppendLine();
            b.AppendLine(Certificate.ToString(formatted, header + ".iQueCertificate"));
            b.AppendLine();
            b.AppendLine(Authority.ToString(formatted, header + ".iQueCertificate (Authority)"));
            b.AppendLine();
            b.AppendLine(Revocation.ToString(formatted, header + ".iQueCertificateRevocation"));
            b.AppendLine();

            return b.ToString();
        }
    }
}
