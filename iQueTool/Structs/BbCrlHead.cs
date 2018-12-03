using System;
using System.Runtime.InteropServices;
using System.Text;
using iQueTool.Files;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct BbCrlHead
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x200)]
        /* 0x000 */ public byte[] Signature; // doesn't seem to validate atm... probably checking wrong region

        /* 0x200 */ public uint Type;
        /* 0x204 */ public uint SigType;
        /* 0x208 */ public uint UnusedPadding;
        /* 0x20C */ public uint VersionNumber;

        /* 0x210 */ public uint Timestamp;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x214 */ public char[] Authority;

        /* 0x254 */ public uint NumRevoked;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x258 */ public char[] CertName;

        public string AuthorityString
        {
            get
            {
                return Shared.NullTermCharsToString(Authority).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public string CertNameString
        {
            get
            {
                return Shared.NullTermCharsToString(CertName).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public DateTime TimestampDateTime
        {
            get
            {
                return Shared.UnixTimeStampToDateTime(Timestamp);
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

        public bool IsSignatureValid
        {
            get
            {
                if (iQueCertCollection.MainCollection == null)
                    return false;

                BbRsaCert authority;
                if (!iQueCertCollection.MainCollection.GetCertificate(AuthorityString, out authority))
                    return false;

                byte[] data = Shared.StructToBytes(this);
                byte[] dataNoSig = new byte[0x98];

                Array.Copy(data, 0x200, dataNoSig, 0, 0x98); // remove first 0x200 bytes

                var res = Shared.iQueSignatureVerify(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
                if (res)
                    return true;

                // sig verify failed, try endian swapping
                EndianSwap();
                data = Shared.StructToBytes(this);
                Array.Copy(data, 0x200, dataNoSig, 0, 0x98);
                EndianSwap();

                return Shared.iQueSignatureVerify(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
            }
        }

        public BbCrlHead EndianSwap()
        {
            Type = Type.EndianSwap();
            SigType = SigType.EndianSwap();
            UnusedPadding = UnusedPadding.EndianSwap();
            VersionNumber = VersionNumber.EndianSwap();

            Timestamp = Timestamp.EndianSwap();

            NumRevoked = NumRevoked.EndianSwap();

            return this;
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
            return ToString(true);
        }

        public string ToString(bool formatted, string header = "BbCrlHead")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            if (UnusedPadding != 0)
                b.AppendLineSpace(fmt + $"UnusedPadding != 0! (0x{UnusedPadding:X8})");

            b.AppendLineSpace(fmt + $"CertName: {CertNameString}");
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLineSpace(fmt + $"Type: {Type}");
            b.AppendLineSpace(fmt + $"SigType: {SigType}");
            b.AppendLineSpace(fmt + $"VersionNumber: {VersionNumber}");
            b.AppendLineSpace(fmt + $"Timestamp: {TimestampDateTime} ({Timestamp})");
            b.AppendLineSpace(fmt + $"NumRevoked: {NumRevoked}");

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
