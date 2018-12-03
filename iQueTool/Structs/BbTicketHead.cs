using System;
using System.Runtime.InteropServices;
using System.Text;
using iQueTool.Files;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct BbTicketHead
    {
        /* 0x29AC */ public uint BBID; // matches value inside id.sys, seems to be stored in the iQue unit somewhere, iQue unit ID has to match id.sys ID which has to match BBID field

        // next field seems to determine the type of ticket
        // tid >= 0x8000 is LP (limited play?)
        // tid >= 0x7000 && tid < 0x8000 is a "global ticket"
        // tid < 0x7000 is a permanent ticket
        /* 0x29B0 */ public ushort TicketId; // ticketid? titleid? both terms seem to be used

        /* 0x29B2 */ public ushort TrialType;
        /* 0x29B4 */ public ushort TrialLimit; // number of minutes/launches for this trial
        
        /* 0x29B6 */ public ushort UnusedReserved;

        /* 0x29B8 */ public uint TSCRLVersion; // ticket_crl_version?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x29BC */ public byte[] CMD_IV; // titlekey_iv? isn't this already set in CMD?

        // from iquebrew:
        // ECC public key used with console's ECC private key to derive unique title key encryption key via ECDH
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x29CC */ public byte[] ServerECCKey;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x2A0C */ public char[] Authority; // always an XS (exchange server) cert?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x100)]
        /* 0x2A4C */ public byte[] Signature; // signature? doesn't seem to verify no matter what I try...

        public string AuthorityString
        {
            get
            {
                return Shared.NullTermCharsToString(Authority).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public bool IsTicketLimitedPlay
        {
            get
            {
                return TicketId >= 0x8000;
            }
        }

        public bool IsTicketGlobal
        {
            get
            {
                return TicketId >= 0x7000 && TicketId < 0x8000;
            }
        }

        public bool IsTicketPermanent
        {
            get
            {
                return TicketId < 0x7000;
            }
        }

        public byte[] DecryptedSignature
        {
            get
            {
                if (iQueCertCollection.MainCollection == null)
                    return null;

                BbRsaCert authority;
                if (!iQueCertCollection.MainCollection.GetCertificate(AuthorityString, out authority))
                    return null;

                return Shared.iQueSignatureDecrypt(Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
            }
        }

        public BbTicketHead EndianSwap()
        {
            BBID = BBID.EndianSwap();
            TicketId = TicketId.EndianSwap();

            TrialType = TrialType.EndianSwap();
            TrialLimit = TrialLimit.EndianSwap();

            UnusedReserved = UnusedReserved.EndianSwap();
            TSCRLVersion = TSCRLVersion.EndianSwap();

            return this;
        }

        public string ToString(bool formatted, string header = "BbTicketHead")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            if (UnusedReserved != 0)
                b.AppendLineSpace(fmt + $"UnusedReserved != 0! (0x{UnusedReserved:X4})");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"BBID: 0x{BBID:X}");

            string ticketType = "";
            if (IsTicketGlobal)
                ticketType = "global";
            else if (IsTicketLimitedPlay)
                ticketType = "limited play";
            else if (IsTicketPermanent)
                ticketType = "permanent";

            b.AppendLineSpace(fmt + $"TicketId: 0x{TicketId:X8} ({ticketType} ticket)");

            string trialType = TrialType == 1 ? "launch count" : (TrialType == 2 ? "time-limited" : "time-limited or not trial");

            b.AppendLineSpace(fmt + $"TrialType: {TrialType} ({trialType})");

            b.AppendLineSpace(fmt + $"TSCRLVersion / ticket_crl_version: {TSCRLVersion}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "CMD_IV / titlekey_iv:" + Environment.NewLine + fmt + CMD_IV.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "ServerECCKey:" + Environment.NewLine + fmt + ServerECCKey.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());

            var decSig = DecryptedSignature;
            if (decSig != null)
            {
                b.AppendLine();
                b.AppendLineSpace(fmt + "Expected Hash (decrypted from signature):" + Environment.NewLine + fmt + decSig.ToHexString());
            }

            return b.ToString();
        }
    }
}
