using System;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct BbLaunchMetadata
    {
        /* 0x0    */ public uint EepromAddress;
        /* 0x4    */ public uint EepromSize;
        /* 0x8    */ public uint FlashAddress;
        /* 0xC    */ public uint FlashSize;
        /* 0x10   */ public uint SramAddress;
        /* 0x14   */ public uint SramSize;

        /* 0x18   */ public uint ControllerPak0Address; // controller 1 addon flags? (rumble / controller pak / ???)
        /* 0x1C   */ public uint ControllerPak1Address; // controller 2 addon flags? (rumble / controller pak / ???)
        /* 0x20   */ public uint ControllerPak2Address; // controller 3 addon flags? (rumble / controller pak / ???)
        /* 0x24   */ public uint ControllerPak3Address; // controller 4 addon flags? (rumble / controller pak / ???)
        /* 0x28   */ public uint ControllerPakSize; // saves to a .u0* file if NumU0XFiles > 0?

        /* 0x2C   */ public uint RomBase; // always 0xB0000000?
        /* 0x30   */ public uint TvType; // always 1?
        /* 0x34   */ public uint MemSize; // always 0x400000?
        /* 0x38   */ public uint ErrataSize; // always 0?
        /* 0x3C   */ public uint ErrataAddress; // always 0?
        
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3)]
        /* 0x40   */ public byte[] Magic; // "CAM" for every ticket I've seen 
        /* 0x43   */ public byte NumU0XFiles; // .u01 / .u02? seems to be used in Animal Crossing, maybe RTC related?

        public BbLaunchMetadata EndianSwap()
        {
            EepromAddress = EepromAddress.EndianSwap();
            EepromSize = EepromSize.EndianSwap();
            FlashAddress = FlashAddress.EndianSwap();
            FlashSize = FlashSize.EndianSwap();
            SramAddress = SramAddress.EndianSwap();
            SramSize = SramSize.EndianSwap();

            ControllerPak0Address = ControllerPak0Address.EndianSwap();
            ControllerPak1Address = ControllerPak1Address.EndianSwap();
            ControllerPak2Address = ControllerPak2Address.EndianSwap();
            ControllerPak3Address = ControllerPak3Address.EndianSwap();
            ControllerPakSize = ControllerPakSize.EndianSwap();

            RomBase = RomBase.EndianSwap();
            TvType = TvType.EndianSwap();
            MemSize = MemSize.EndianSwap();
            ErrataSize = ErrataSize.EndianSwap();
            ErrataAddress = ErrataAddress.EndianSwap();

            return this;
        }

        public string ToString(bool formatted, string header = "BbLaunchMetadata")
        {
            var b = new StringBuilder();
            if (!string.IsNullOrEmpty(header))
                b.AppendLine($"{header}:");

            string fmt = formatted ? "    " : "";

            if (ErrataSize != 0)
                b.AppendLineSpace(fmt + $"ErrataSize != 0! (0x{ErrataSize:X8})");
            if (ErrataAddress != 0)
                b.AppendLineSpace(fmt + $"ErrataAddress != 0! (0x{ErrataAddress:X8})");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"EepromAddress: 0x{EepromAddress:X8}, size: 0x{EepromSize:X}");
            b.AppendLineSpace(fmt + $"FlashAddress: 0x{FlashAddress:X8}, size: 0x{FlashSize:X}");
            b.AppendLineSpace(fmt + $"SramAddress: 0x{SramAddress:X8}, size: 0x{SramSize:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"ControllerPak0Address: 0x{ControllerPak0Address:X}");
            b.AppendLineSpace(fmt + $"ControllerPak1Address: 0x{ControllerPak1Address:X}");
            b.AppendLineSpace(fmt + $"ControllerPak2Address: 0x{ControllerPak2Address:X}");
            b.AppendLineSpace(fmt + $"ControllerPak3Address: 0x{ControllerPak3Address:X}");
            b.AppendLineSpace(fmt + $"ControllerPakSize: 0x{ControllerPakSize:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + $"RomBase: 0x{RomBase:X8}");
            b.AppendLineSpace(fmt + $"TvType: 0x{TvType:X8}");
            b.AppendLineSpace(fmt + $"MemSize: 0x{MemSize:X8}");

            if (ErrataAddress != 0 || ErrataSize != 0)
            {
                b.AppendLineSpace(fmt + $"ErrataSize: 0x{ErrataSize:X8}");
                b.AppendLineSpace(fmt + $"ErrataAddress: 0x{ErrataAddress:X8}");
            }

            b.AppendLine();
            b.AppendLineSpace(fmt + $"NumU0XFiles: 0x{NumU0XFiles:X}");

            b.AppendLine();
            b.AppendLineSpace(fmt + "Magic:" + Environment.NewLine + fmt + Magic.ToHexString());

            return b.ToString();
        }
    }
}
