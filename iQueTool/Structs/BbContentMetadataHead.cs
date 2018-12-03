using iQueTool.Files;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct BbContentMetadataHead
    {
        /* 0x2800 */ public uint UnusedPadding; // always 0?

        /* 0x2804 */ public uint CACRLVersion;
        /* 0x2808 */ public uint CPCRLVersion;

        /* 0x280C */ public uint ContentSize;

        /* 0x2810 */ public uint ContentFlags; // 0 for tickets, 1 for SA?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x2814 */ public byte[] TitleKeyIV;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x14)]
        /* 0x2824 */ public byte[] ContentHash; // SHA1 hash of the decrypted content
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x2838 */ public byte[] EncryptionIV; 

        /* 0x2848 */ public uint ExecutionFlags; // 2 for game tickets, 0 for SA/iQue Club tickets
        /* 0x284C */ public uint AccessRights; // 0 for game tickets, 0x1F7 for normal SAs, 0x1B3 for weird (0 byte/3MB) SAs (but 0x13 for iQue Club ticket..)
        /* 0x2850 */ public uint KernelRights; // 0x4000 for games, 0xFFFFFFFF for normal SAs, 0xE01 for weird SAs, 0x6001 for iQue Club
        /* 0x2854 */ public uint BoundBBID; // if non-zero, app can only be ran by this BBID

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x2858 */ public char[] Authority; // always a CP cert, CP = content publisher?

        /* 0x2898 */ public uint ContentId; // can't be higher than 99999999 ?? if (cid / 100) % 10 == 9, this is a game manual

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x289C */ public byte[] TitleKey; // encrypted with common key if SA, or common key + console ECDH key if app

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x100)]
        /* 0x28AC */ public byte[] Signature; // signature of 0x0 - 0xAC, before title key is encrypted with console ECDH key

        public string AuthorityString
        {
            get
            {
                return Shared.NullTermCharsToString(Authority).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public bool IsGameManual
        {
            get
            {
                return TitleId % 10 == 9; // last digit of titleid must be 9
            }
        }

        public uint TitleId
        {
            get
            {
                if (ContentId < 10000)
                    return ContentId / 1000; // 4-digit content id must be SKSA, discard last 3 digits
                return ContentId / 100; // discard last 2 digits (version)
            }
        }

        public uint TitleVersion
        {
            get
            {
                if (ContentId < 10000)
                    return ContentId % 1000; // 4-digit content id must be SKSA, return last 3 digits of content id
                return ContentId % 100; // last 2 digits of content id
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

        public byte[] TicketHash
        {
            get
            {
                byte[] data = GetBytes();
                Array.Resize(ref data, 0xAC);

                var sha1 = new SHA1Managed();
                byte[] hash = sha1.ComputeHash(data);
                return hash;
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
                Array.Resize(ref data, 0xAC);

                var res = Shared.iQueSignatureVerify(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
                if (res)
                    return true;

                // sig verify failed, try endian swapping
                EndianSwap();
                data = Shared.StructToBytes(this);
                Array.Resize(ref data, 0xAC);
                EndianSwap();

                return Shared.iQueSignatureVerify(data, Signature, authority.PublicKeyModulus, authority.PublicKeyExponent);
            }
        }

        public void EndianSwap()
        {
            CACRLVersion = CACRLVersion.EndianSwap();
            CPCRLVersion = CPCRLVersion.EndianSwap();

            ContentSize = ContentSize.EndianSwap();
            ContentFlags = ContentFlags.EndianSwap();

            ExecutionFlags = ExecutionFlags.EndianSwap();
            AccessRights = AccessRights.EndianSwap();
            KernelRights = KernelRights.EndianSwap();
            BoundBBID = BoundBBID.EndianSwap();

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

        public string ToString(bool formatted, string header = "BbContentMetaDataHead")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            if (UnusedPadding != 0)
                b.AppendLineSpace(fmt + $"UnusedPadding != 0! (0x{UnusedPadding:X8})");

            if (iQueCertCollection.MainCollection == null)
                b.AppendLineSpace(fmt + $"(Unable to verify RSA signature: cert.sys not found)");
            else
                b.AppendLineSpace(fmt + $"(RSA signature {(IsSignatureValid ? "validated" : "appears invalid")})");

            b.AppendLine();

            b.AppendLineSpace(fmt + $"ContentId: {ContentId} (title: {TitleId}v{TitleVersion})");
            b.AppendLineSpace(fmt + $"ContentSize: {ContentSize}");
            b.AppendLineSpace(fmt + "ContentHash:" + Environment.NewLine + fmt + ContentHash.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + $"ContentFlags: 0x{ContentFlags:X8}");
            b.AppendLineSpace(fmt + $"ExecutionFlags: 0x{ExecutionFlags:X8}");
            b.AppendLineSpace(fmt + $"AccessRights: 0x{AccessRights:X8}");
            b.AppendLineSpace(fmt + $"KernelRights: 0x{KernelRights:X8}");

            if(BoundBBID != 0) // only output BoundBBID if it's actually set
                b.AppendLineSpace(fmt + $"BoundBBID: {BoundBBID}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "TitleKey:" + Environment.NewLine + fmt + TitleKey.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "TitleKeyIV:" + Environment.NewLine + fmt + TitleKeyIV.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "EncryptionIV:" + Environment.NewLine + fmt + EncryptionIV.ToHexString());

            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Ticket Hash:" + Environment.NewLine + fmt + TicketHash.ToHexString());

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
