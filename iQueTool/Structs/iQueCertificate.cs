using System;
using System.Runtime.InteropServices;
using System.Text;
using iQueTool.Files;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueCertificate
    {
        /* 0x000 */ public uint Unk0;
        /* 0x004 */ public uint Unk4; // 0 if signature is 2048-bit, 1 if sig is 4096-bit?
        /* 0x008 */ public uint Unk8; // key-id?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x00C */ public char[] Authority;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x04C */ public char[] CertName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x100)]
        /* 0x08C */ public byte[] PublicKeyModulus;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        /* 0x18C */ public byte[] PublicKeyExponent;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x200)]
        /* 0x190 */ public byte[] Signature; // signature of 0x0 - 0x190 made using Authority key

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
                Array.Resize(ref data, 0x190);

                var res = Shared.VerifyiQueSignature(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
                if (res)
                    return true;

                // sig verify failed, try endian swapping
                EndianSwap();
                data = Shared.StructToBytes(this);
                Array.Resize(ref data, 0x190);
                EndianSwap();

                return Shared.VerifyiQueSignature(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
            }
        }

        public iQueCertificate EndianSwap()
        {
            Unk0 = Unk0.EndianSwap();
            Unk4 = Unk4.EndianSwap();
            Unk8 = Unk8.EndianSwap();

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

        public string ToString(bool formatted, string header = "iQueCertificate")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            b.AppendLineSpace(fmt + $"CertName: {CertNameString} ({(string.IsNullOrEmpty(AuthorityString) ? CertNameString : $"{AuthorityString}-{CertNameString}")})");
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "PublicKeyModulus:" + Environment.NewLine + fmt + PublicKeyModulus.ToHexString());
            b.AppendLineSpace(fmt + "PublicKeyExponent:" + Environment.NewLine + fmt + PublicKeyExponent.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());
            
            b.AppendLine();
            b.AppendLineSpace(fmt + $"Unk0: 0x{Unk0:X}");
            b.AppendLineSpace(fmt + $"Unk4: 0x{Unk4:X}");
            b.AppendLineSpace(fmt + $"Unk8: 0x{Unk8:X}");

            return b.ToString();
        }
    }    
}
