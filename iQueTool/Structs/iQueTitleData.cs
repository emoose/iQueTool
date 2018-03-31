using System;
using System.Runtime.InteropServices;
using System.Text;
using iQueTool.Files;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueTitleData
    {
        // unsure if the flags fields below are actually flags
        // they seem to be set to 0x807C0000 if that save storage method is used though

        /* 0x0    */ public uint EepromFlags;
        /* 0x4    */ public uint EepromSize;
        /* 0x8    */ public uint FlashFlags;
        /* 0xC    */ public uint FlashSize;
        /* 0x10   */ public uint SramFlags;
        /* 0x14   */ public uint SramSize;

        /* 0x18   */ public uint Controller1Flags; // controller 1 addon flags? (rumble / controller pak / ???)
        /* 0x1C   */ public uint Controller2Flags; // controller 2 addon flags? (rumble / controller pak / ???)
        /* 0x20   */ public uint Controller3Flags; // controller 3 addon flags? (rumble / controller pak / ???)
        /* 0x24   */ public uint Controller4Flags; // controller 4 addon flags? (rumble / controller pak / ???)
        /* 0x28   */ public uint ControllerPakSize; // saves to a .u0* file if NumU0XFiles > 0?

        /* 0x2C   */ public uint Unk2C; // always 0xB0000000?

        /* 0x30   */ public uint Unk30; // always 1?
        /* 0x34   */ public uint Unk34; // always 0x400000?
        /* 0x38   */ public uint Unk38; // always 0?
        /* 0x3C   */ public uint Unk3C; // always 0?
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3)]
        /* 0x40   */ public byte[] Unk40; // "CAM" for every ticket I've seen 
        /* 0x43   */ public byte NumU0XFiles; // .u01 / .u02? seems to be used in Animal Crossing, maybe RTC related?

        /* 0x44   */ public ushort ThumbImgLength; // can't be more than 0x4000, decompressed length must be exactly 0x1880 bytes!
        /* 0x46   */ public ushort TitleImgLength; // can't be more than 0x10000 (how exactly would that even fit?)

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x27B8)]
        /* 0x48   */ public byte[] ImagesAndTitle; // contains gzipped thumb img, gzipped title img, title name + sometimes an ISBN

        /* 0x2800 */ public iQueETicket Ticket;

        /* 0x29AC */ public uint BBID; // matches value inside id.sys, seems to be stored in the iQue unit somewhere, iQue unit ID has to match id.sys ID which has to match BBID field

        // next field seems to determine the type of ticket
        // tid >= 0x8000 is LP (limited play?)
        // tid >= 0x7000 && tid < 0x8000 is a "global ticket"
        // tid < 0x7000 is a permanent ticket
        /* 0x29B0 */ public ushort TicketId; // ticketid? titleid? both terms seem to be used

        /* 0x29B2 */ public uint TimeLimitMinutes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x6)]
        /* 0x29B6 */ public byte[] Unk29B6; // all 00 in etickets, but set in game tickets? (update: i have no idea what i meant by this)
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
        /* 0x29BC */ public byte[] Unk29BC;

        // next field is weird.. think it's ECC / ECDSA / ECDH related
        // some bytes inside sig.db / recrypt.sys also seem to follow the same format of it, ie:
        // [00 00 0*] [0x1D bytes] [00 00 0*] [another 0x1D bytes]
        // on Wii apparently 233-bit ECC private keys are 0x1E bytes, while the public keys/signatures are 0x3C bytes long, very close to the size of these fields...
        // also note that 233 bits = 0x1D bytes (+1 bit)
        // unfortunately I don't have any wii keys.bin dumps to check out how the ECC keys are formatted, and neither do I have any ECC-signed wii savegames :(
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x29CC */ public byte[] Unk29CC;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x40)]
        /* 0x2A0C */ public char[] Authority; // always an XS (exchange server) cert?

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x100)]
        /* 0x2A4C */ public byte[] Signature; // signature? doesn't seem to verify no matter what I try...

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

        public byte[] ThumbImage
        {
            get
            {
                if (ImagesAndTitle == null)
                    return null;

                var img = new byte[ThumbImgLength];
                Array.Copy(ImagesAndTitle, 0, img, 0, ThumbImgLength);
                return img;
            }
        }
        public byte[] TitleImage
        {
            get
            {
                if (ImagesAndTitle == null)
                    return null;

                var img = new byte[TitleImgLength];
                Array.Copy(ImagesAndTitle, ThumbImgLength, img, 0, TitleImgLength);
                return img;
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

        public byte[] TitleInfoBytes
        {
            get
            {
                if (ImagesAndTitle == null)
                    return null;

                var nameSize = 0x27B8 - ThumbImgLength - TitleImgLength;
                var name = new byte[nameSize];
                Array.Copy(ImagesAndTitle, ThumbImgLength + TitleImgLength, name, 0, nameSize);
                return name;
            }
        }

        public int TitleNameLength
        {
            get
            {
                var bytes = TitleInfoBytes;
                for (int i = 0; i < bytes.Length; i++)
                    if (bytes[i] == 0)
                        return i;

                return -1;
            }
        }

        public int ISBNLength
        {
            get
            {
                var nameLength = TitleNameLength;
                if (nameLength < 0)
                    return -1;

                var bytes = TitleInfoBytes;
                for (int i = nameLength + 1; i < bytes.Length; i++)
                    if (bytes[i] == 0)
                        return i - (nameLength + 1);

                return -1;
            }
        }

        public string TitleName
        {
            get
            {
                var bytes = TitleInfoBytes;
                var size = TitleNameLength;
                if (size <= 0)
                    return String.Empty;
                var nameBytes = new byte[size];
                Array.Copy(bytes, nameBytes, size);

                return Encoding.GetEncoding(936).GetString(nameBytes).Replace("\0", "").Replace("\r", "").Replace("\n", ""); // gb2312 (codepage 936)
            }
        }

        public string ISBN
        {
            get
            {
                var bytes = TitleInfoBytes;
                var nameSize = TitleNameLength;
                if (nameSize < 0)
                    return string.Empty;

                var isbnSize = ISBNLength;
                if (isbnSize <= 0)
                    return String.Empty;

                var isbnBytes = new byte[isbnSize];
                Array.Copy(bytes, nameSize + 1, isbnBytes, 0, isbnSize);

                return Encoding.UTF8.GetString(isbnBytes).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        public string AuthorityString
        {
            get
            {
                return Shared.NullTermCharsToString(Authority).Replace("\0", "").Replace("\r", "").Replace("\n", "");
            }
        }

        // makes a unique string for each bbid/contentid/titleid combination
        public string TicketUID
        {
            get
            {
                return $"{BBID:X}-{Ticket.ContentId}-{TicketId:X}";
            }
        }

        public iQueTitleData EndianSwap()
        { 
            EepromFlags = EepromFlags.EndianSwap();
            EepromSize = EepromSize.EndianSwap();
            FlashFlags = FlashFlags.EndianSwap();
            FlashSize = FlashSize.EndianSwap();
            SramFlags = SramFlags.EndianSwap();
            SramSize = SramSize.EndianSwap();

            Controller1Flags = Controller1Flags.EndianSwap();
            Controller2Flags = Controller2Flags.EndianSwap();
            Controller3Flags = Controller3Flags.EndianSwap();
            Controller4Flags = Controller4Flags.EndianSwap();
            ControllerPakSize = ControllerPakSize.EndianSwap();

            Unk2C = Unk2C.EndianSwap();

            Unk30 = Unk30.EndianSwap();
            Unk34 = Unk34.EndianSwap();
            Unk38 = Unk38.EndianSwap();
            Unk3C = Unk3C.EndianSwap();
            
            ThumbImgLength = ThumbImgLength.EndianSwap();
            TitleImgLength = TitleImgLength.EndianSwap();

            Ticket.EndianSwap();

            BBID = BBID.EndianSwap();
            TicketId = TicketId.EndianSwap();

            TimeLimitMinutes = TimeLimitMinutes.EndianSwap();

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

        public string ToString(bool formatted, string header = "iQueTitleData")
        {
            var b = new StringBuilder();
            if(!string.IsNullOrEmpty(header))
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

            // some stuff to alert me of unks that are different
            if (Unk2C != 0xB0000000)
                b.AppendLineSpace(fmt + "Unk2C != 0xB0000000!");

            if (Unk30 != 1)
                b.AppendLineSpace(fmt + "Unk30 != 1!");
            if (Unk34 != 0x400000)
                b.AppendLineSpace(fmt + "Unk34 != 0x400000!");
            if (Unk38 != 0)
                b.AppendLineSpace(fmt + "Unk38 != 0!");
            if (Unk3C != 0)
                b.AppendLineSpace(fmt + "Unk3C != 0!");

            if (ThumbImgLength > 0x4000)
                b.AppendLineSpace(fmt + "ThumbImgLength > 0x4000! (invalid?)");
            if (TitleImgLength > 0x10000) // unsure how this can even be possible, but it seems to get checked anyway
                b.AppendLineSpace(fmt + "TitleImgLength > 0x10000! (invalid?)");

            if (Ticket.Unk2848 != 2)
                b.AppendLineSpace(fmt + "Ticket.Unk2848 != 2!");
            if (Ticket.Unk284C != 0)
                b.AppendLineSpace(fmt + "Ticket.Unk284C != 0!");
            if (Ticket.Unk2850 != 0x4000)
                b.AppendLineSpace(fmt + "Ticket.Unk2850 != 0x4000!");
            if (Ticket.Unk2854 != 0)
                b.AppendLineSpace(fmt + "Ticket.Unk2854 != 0!");

            if (Ticket.ContentId > 99999999)
                b.AppendLineSpace(fmt + "Ticket.ContentId > 99999999! (invalid?)");
            if (!Unk29B6.IsArrayEmpty())
                b.AppendLineSpace(fmt + "Unk29B6 != null!");

            b.AppendLine();

            b.AppendLineSpace(fmt + $"EepromSize: {EepromSize} bytes (flags: 0x{EepromFlags:X8})");
            b.AppendLineSpace(fmt + $"FlashSize: {FlashSize} bytes (flags: 0x{FlashFlags:X8})");
            b.AppendLineSpace(fmt + $"SramSize: {SramSize} bytes (flags: 0x{SramFlags:X8})");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Controller1Flags: 0x{Controller1Flags:X}");
            b.AppendLineSpace(fmt + $"Controller2Flags: 0x{Controller2Flags:X}");
            b.AppendLineSpace(fmt + $"Controller3Flags: 0x{Controller3Flags:X}");
            b.AppendLineSpace(fmt + $"Controller4Flags: 0x{Controller4Flags:X}");
            b.AppendLineSpace(fmt + $"ControllerPakSize: 0x{ControllerPakSize:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"NumU0XFiles: 0x{NumU0XFiles:X}");
            b.AppendLineSpace(fmt + $"ThumbImgLength: {ThumbImgLength}");
            b.AppendLineSpace(fmt + $"TitleImgLength: {TitleImgLength}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "TitleName: " + TitleName + (!String.IsNullOrEmpty(ISBN) ? $" ({ISBN})" : ""));

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
            b.AppendLineSpace(fmt + $"TimeLimitMinutes: {TimeLimitMinutes}");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"Authority: {AuthorityString}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Signature:" + Environment.NewLine + fmt + Signature.ToHexString());

            if (decSig != null)
            {
                b.AppendLine();
                b.AppendLineSpace(fmt + "Expected Hash (decrypted from signature):" + Environment.NewLine + fmt + decSig.ToHexString());
            }

            b.AppendLine();

            b.AppendLineSpace(fmt + $"Unk2C: 0x{Unk2C:X}");
            b.AppendLineSpace(fmt + $"Unk30: 0x{Unk30:X}");
            b.AppendLineSpace(fmt + $"Unk34: 0x{Unk34:X}");
            b.AppendLineSpace(fmt + $"Unk38: 0x{Unk38:X}");
            b.AppendLineSpace(fmt + $"Unk3C: 0x{Unk3C:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk40:" + Environment.NewLine + fmt + Unk40.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk29B6:" + Environment.NewLine + fmt + Unk29B6.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk29BC:" + Environment.NewLine + fmt + Unk29BC.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(fmt + "Unk29CC:" + Environment.NewLine + fmt + Unk29CC.ToHexString());

            b.AppendLine();
            b.AppendLineSpace(Ticket.ToString(formatted, header + ".iQueETicket"));

            return b.ToString();
        }
    }
}
