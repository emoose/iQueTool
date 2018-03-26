using System;
using System.Runtime.InteropServices;
using System.Text;
using iQueTool.Files;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueCertificateRevocation
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x200)]
        public byte[] Signature; // doesn't seem to validate atm... probably checking wrong region

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

        public byte[] DecryptedSignature
        {
            get
            {
                if (iQueCertCollection.MainCollection == null)
                    return null;

                iQueCertificate authority;
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

                iQueCertificate authority;
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
            EndianSwap(); // back to device endian (BE)
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

            var decSig = DecryptedSignature;
            if (decSig != null)
            {
                if (decSig[0] == 0)
                {
                    b.AppendLineSpace("!!!!!!!!!!!!!!!!");
                    b.AppendLineSpace("decSig[0] == 0!!");
                    b.AppendLineSpace("LET EMOOSE KNOW!");
                    b.AppendLineSpace("!!!!!!!!!!!!!!!!");
                    b.AppendLine();
                }
                else if (decSig[1] == 0)
                    b.AppendLineSpace(fmt + "!!!! decSig[1] == 0 !!!!");
                else if (decSig[2] == 0)
                    b.AppendLineSpace(fmt + "!!!! decSig[2] == 0 !!!!");
            }

            b.AppendLineSpace(fmt + $"CertName: {CertNameString}");
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");
            b.AppendLineSpace(fmt + $"Timestamp: {TimestampDateTime} ({Timestamp})");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());
            
            if (decSig != null)
            {
                b.AppendLine();
                b.AppendLineSpace(fmt + "Expected Hash (decrypted from signature):" + Environment.NewLine + fmt + decSig.ToHexString());
            }

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
