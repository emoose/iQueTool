﻿using System;
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
        

        public iQueCertificate(string authority, string certName, byte[] modulus)
        {
            Unk0 = 0;
            Unk4 = 0;
            Unk8 = 0;
            Authority = authority.ToCharArray();
            CertName = certName.ToCharArray();

            PublicKeyModulus = modulus;
            PublicKeyExponent = new byte[] { 0x00, 0x01, 0x00, 0x01 };
            Signature = new byte[0x200];
        }

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
                Array.Resize(ref data, 0x190);

                var res = Shared.iQueSignatureVerify(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
                if (res)
                    return true;

                // sig verify failed, try endian swapping
                EndianSwap();
                data = Shared.StructToBytes(this);
                Array.Resize(ref data, 0x190);
                EndianSwap();

                return Shared.iQueSignatureVerify(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
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

            if (iQueCertCollection.MainCollection == null)
                b.AppendLineSpace(fmt + $"(Unable to verify RSA signature: cert.sys not found)");
            else
                b.AppendLineSpace(fmt + $"(RSA signature {(IsSignatureValid ? "validated" : "appears invalid")})");

            b.AppendLineSpace(fmt + $"CertName: {CertNameString} ({(string.IsNullOrEmpty(AuthorityString) ? CertNameString : $"{AuthorityString}-{CertNameString}")})");
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "PublicKeyModulus:" + Environment.NewLine + fmt + PublicKeyModulus.ToHexString());
            b.AppendLineSpace(fmt + "PublicKeyExponent:" + Environment.NewLine + fmt + PublicKeyExponent.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());

            var decSig = DecryptedSignature;
            if (decSig != null)
            {
                b.AppendLine();
                b.AppendLineSpace(fmt + "Expected Hash (decrypted from signature):" + Environment.NewLine + fmt + decSig.ToHexString());
            }

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Unk0: 0x{Unk0:X}");
            b.AppendLineSpace(fmt + $"Unk4: 0x{Unk4:X}");
            b.AppendLineSpace(fmt + $"Unk8: 0x{Unk8:X}");

            return b.ToString();
        }
    }    
}
