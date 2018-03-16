using iQueTool.Files;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueETicket
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x8)]
        /* 0x2800 */ public byte[] Unk2800; // always 0?

        /* 0x2808 */ public uint Unk2808; // always 1?

        /* 0x280C */ public uint ContentSize;

        /* 0x2810 */ public uint Unk2810; // 0 for tickets, 1 for SA? maybe title-type? or common-key idx?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x2814 */ public byte[] Unk2814;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        /* 0x2814 */ public byte[] ContentHash; // SHA1 hash of the decrypted content
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x2838 */ public byte[] TitleKey; // appears to be the title key, based on different files having the same value for this field and bytes matching in the encdata

        /* 0x2848 */ public uint Unk2848; // 2 for game tickets, 0 for SA/iQue Club tickets
        /* 0x284C */ public uint Unk284C; // device type maybe? 0 for game tickets, 0x1F7 for normal SAs, 0x1B3 for weird (0 byte/3MB) SAs (but 0x13 for iQue Club ticket..)
        /* 0x2850 */ public uint Unk2850; // access rights? 0x4000 for games, 0xFFFFFFFF for normal SAs, 0xE01 for weird SAs, 0x6001 for iQue Club
        /* 0x2854 */ public uint Unk2854; // always 0? 

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x2858 */ public char[] Authority; // always a CP cert, CP = content publisher?

        /* 0x2898 */ public uint ContentId; // can't be higher than 99999999 ?? if (cid / 0x64) % 0xA == 9, this is "manual" download?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x289C */ public byte[] TitleKeyAlt; // another key? changes between units while signature remains the same, is maybe decrypted in-place with per-box key and then signature verified?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x100)]
        /* 0x28AC */ public byte[] Signature; // signature of 0x0 - 0xAC, verifies fine with the ticket inside SKSA (@ 0x10000), but can't seem to verify tickets inside ticket.sys ;_;

        public string AuthorityString
        {
            get
            {
                return Authority == null ? String.Empty : new string(Authority).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public byte[] DecryptTitleKey(byte[] commonKey, bool useIv = true)
        {
            // unsure if this is decrypting the right field
            // or if titlekey is even encrypted with AES128CBC
            // (seems Wii keys are though so it makes sense for iQue too)

            byte[] iv = new byte[0x10];
            if(useIv)
            {
                // Wii uses 8-byte titleID as IV, so we'll test something similar
                byte[] cid = BitConverter.GetBytes(ContentId);
                Array.Copy(cid, iv, 4);
            }

            using (var aes = new AesManaged())
            {
                aes.Key = commonKey;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                var cipher = aes.CreateDecryptor();
                return cipher.TransformFinalBlock(TitleKey, 0, 0x10);
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
                Array.Resize(ref data, 0xAC);

                var res = Shared.VerifyiQueSignature(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
                if (res)
                    return true;

                // sig verify failed, try endian swapping
                EndianSwap();
                data = Shared.StructToBytes(this);
                Array.Resize(ref data, 0xAC);
                EndianSwap();

                return Shared.VerifyiQueSignature(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
            }
        }

        public bool FakeSign(out byte[] fakeSignedTicket)
        {
            // fake/trucha sign the ticket
            byte[] data = GetBytes();
            Array.Resize(ref data, 0xAC);

            var sha1 = new SHA1Managed();

            byte[] hash = sha1.ComputeHash(data);
            bool success = hash[0] == 0;
            if (!success) // have to change a part of the ticket so that first byte of hash is 0
            {
                for (ulong i = 0; i < ulong.MaxValue; i++)
                {
                    byte[] i_bytes = BitConverter.GetBytes(i);
                    Array.Copy(i_bytes, 0, data, 0x90, 8); // change last 8 chars of the Authority field (assuming that iQue will only use the parts of the Authority field up to the first null..)
                    hash = sha1.ComputeHash(data);
                    if (hash[0] == 0)
                    {
                        success = true;
                        break;
                    }
                }
            }

            if (!success)
            {
                fakeSignedTicket = null;
                return false;
            }

            Array.Resize(ref data, 0x1AC); // add 0x100 bytes, which gives us a nulled out signature field

            fakeSignedTicket = data;
            return true;
        }

        public void EndianSwap()
        {
            Unk2808 = Unk2808.EndianSwap();

            ContentSize = ContentSize.EndianSwap();

            Unk2810 = Unk2810.EndianSwap();

            Unk2848 = Unk2848.EndianSwap();
            Unk284C = Unk284C.EndianSwap();
            Unk2850 = Unk2850.EndianSwap();
            Unk2854 = Unk2854.EndianSwap();

            ContentId = ContentId.EndianSwap();
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

        public string ToString(bool formatted, string header = "iQueETicket")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";
            if (iQueCertCollection.MainCollection == null)
                b.AppendLineSpace(fmt + $"(Unable to verify RSA signature: cert.sys not found)");
            else
                b.AppendLineSpace(fmt + $"(RSA signature {(IsSignatureValid ? "validated" : "appears invalid")})");

            b.AppendLine();

            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLineSpace(fmt + $"ContentId: {ContentId}");
            b.AppendLineSpace(fmt + $"ContentSize: {ContentSize}");
            b.AppendLineSpace(fmt + "ContentHash:" + Environment.NewLine + fmt + ContentHash.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "TitleKey?:" + Environment.NewLine + fmt + TitleKey.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "TitleKeyAlt?:" + Environment.NewLine + fmt + TitleKeyAlt.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk2800:" + Environment.NewLine + fmt + Unk2800.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Unk2808: 0x{Unk2808:X}");
            b.AppendLineSpace(fmt + $"Unk2810: 0x{Unk2810:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk2814:" + Environment.NewLine + fmt + Unk2814.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Unk2848: 0x{Unk2848:X}");
            b.AppendLineSpace(fmt + $"Unk284C: 0x{Unk284C:X}");
            b.AppendLineSpace(fmt + $"Unk2850: 0x{Unk2850:X}");
            b.AppendLineSpace(fmt + $"Unk2854: 0x{Unk2854:X}");

            return b.ToString();
        }
    }
}
