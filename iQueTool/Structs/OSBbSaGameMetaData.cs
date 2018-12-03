using System;
using System.Runtime.InteropServices;
using System.Text;
using iQueTool.Files;

namespace iQueTool.Structs
{    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct OSBbSaGameMetaData
    {
        /* 0x00   */ public BbLaunchMetadata LaunchMetadata;
        /* 0x44   */ public ushort ThumbImgLength; // can't be more than 0x4000, decompressed length must be exactly 0x1880 bytes!
        /* 0x46   */ public ushort TitleImgLength; // can't be more than 0x10000 (how exactly would that even fit?)

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x27B8)]
        /* 0x48   */ public byte[] ImagesAndTitle; // contains gzipped thumb img, gzipped title img, title name + sometimes an ISBN

        /* 0x2800 */ public BbContentMetadataHead ContentMetadata;

        /* 0x29AC */ public BbTicketHead Ticket;

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

        // makes a unique string for each bbid/contentid/titleid combination
        public string TicketUID
        {
            get
            {
                return $"{Ticket.BBID:X}-{ContentMetadata.ContentId}-{Ticket.TicketId:X}";
            }
        }

        public OSBbSaGameMetaData EndianSwap()
        {
            LaunchMetadata.EndianSwap();
            
            ThumbImgLength = ThumbImgLength.EndianSwap();
            TitleImgLength = TitleImgLength.EndianSwap();

            ContentMetadata.EndianSwap();
            Ticket.EndianSwap();

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

        public string ToString(bool formatted, string header = "OSBbSaGameMetaData")
        {
            var b = new StringBuilder();
            if(!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            // some stuff to alert me of unks that are different

            if (ThumbImgLength > 0x4000)
                b.AppendLineSpace(fmt + "ThumbImgLength > 0x4000! (invalid?)");
            if (TitleImgLength > 0x10000) // unsure how this can even be possible, but it seems to get checked anyway
                b.AppendLineSpace(fmt + "TitleImgLength > 0x10000! (invalid?)");

            if (ContentMetadata.ContentId > 99999999)
                b.AppendLineSpace(fmt + "Ticket.ContentId > 99999999! (invalid?)");

            b.AppendLine();
            b.AppendLineSpace(LaunchMetadata.ToString(formatted, header + ".LaunchMetadata"));

            b.AppendLineSpace(fmt + $"ThumbImgLength: {ThumbImgLength}");
            b.AppendLineSpace(fmt + $"TitleImgLength: {TitleImgLength}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "TitleName: " + TitleName + (!String.IsNullOrEmpty(ISBN) ? $" ({ISBN})" : ""));

            b.AppendLine();
            b.AppendLineSpace(ContentMetadata.ToString(formatted, header + ".ContentMetadata"));

            b.AppendLine();
            b.AppendLineSpace(Ticket.ToString(formatted, header + ".Ticket"));

            return b.ToString();
        }
    }
}
