using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace iQueTool.Structs
{
    // format of the BB-returned block-spare data, which seems slightly different to the actual on-chip page-spare data?
    // seems BB returns only the last page's spare data for each block read (0x20 pages per block), while setting 0x6 to 0x00 for some reason
    // when writing BB is sent all FF as spare data, the unit must be recalcing the ECC itself before writing?
    // spare is returned as all 00 for bad blocks
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct iQueBlockSpare
    {
        public byte Unk0;
        public byte Unk1;
        public byte Unk2;
        public byte Unk3; // always FF?
        public byte Unk4; // always FF?
        public byte BadBlockIndicator; // any bit unset means bad block (each bit is checked seperately.. each bit counts as 4 pages (4 pages = each 2048-byte part?))
        public byte Unk6; // always 00? (0xFF in page spares)
        public byte Unk7; // always FF?

        // ECC is all FF in pages that are either all 00 or all FF (or blocks where the last page is all 00/all FF)
        
        // ECC for 0x100 - 0x200 of the page
        public byte Ecc2_0;
        public byte Ecc2_1;
        public byte Ecc2_2;

        public byte UnkB; // always FF?
        public byte UnkC; // always FF?

        // ECC for 0x0 - 0x100 of the page
        public byte Ecc1_0; 
        public byte Ecc1_1;
        public byte Ecc1_2;

        // calcs ECC for a 512-byte block, formatted like the iQue ([3-byte ECC(0x100:0x200)] 0xFF 0xFF [3-byte ECC(0:0x100)])
        public static byte[] Calculate512Ecc(byte[] pageData)
        {
            byte[] res = new byte[8];
            res[3] = res[4] = 0xFF;

            byte[] ecc1 = Calculate256Ecc(pageData, 0);
            byte[] ecc2 = Calculate256Ecc(pageData, 0x100);
            Array.Copy(ecc2, 0, res, 0, 3);
            Array.Copy(ecc1, 0, res, 5, 3);

            return res;
        }

        // ECC algo ported from https://github.com/TheBlueMatt/u-boot/blob/master/drivers/mtd/nand/nand_ecc.c
        static byte[] EccPrecalcTable =
        {
            0x00, 0x55, 0x56, 0x03, 0x59, 0x0c, 0x0f, 0x5a, 0x5a, 0x0f, 0x0c, 0x59, 0x03, 0x56, 0x55, 0x00,
            0x65, 0x30, 0x33, 0x66, 0x3c, 0x69, 0x6a, 0x3f, 0x3f, 0x6a, 0x69, 0x3c, 0x66, 0x33, 0x30, 0x65,
            0x66, 0x33, 0x30, 0x65, 0x3f, 0x6a, 0x69, 0x3c, 0x3c, 0x69, 0x6a, 0x3f, 0x65, 0x30, 0x33, 0x66,
            0x03, 0x56, 0x55, 0x00, 0x5a, 0x0f, 0x0c, 0x59, 0x59, 0x0c, 0x0f, 0x5a, 0x00, 0x55, 0x56, 0x03,
            0x69, 0x3c, 0x3f, 0x6a, 0x30, 0x65, 0x66, 0x33, 0x33, 0x66, 0x65, 0x30, 0x6a, 0x3f, 0x3c, 0x69,
            0x0c, 0x59, 0x5a, 0x0f, 0x55, 0x00, 0x03, 0x56, 0x56, 0x03, 0x00, 0x55, 0x0f, 0x5a, 0x59, 0x0c,
            0x0f, 0x5a, 0x59, 0x0c, 0x56, 0x03, 0x00, 0x55, 0x55, 0x00, 0x03, 0x56, 0x0c, 0x59, 0x5a, 0x0f,
            0x6a, 0x3f, 0x3c, 0x69, 0x33, 0x66, 0x65, 0x30, 0x30, 0x65, 0x66, 0x33, 0x69, 0x3c, 0x3f, 0x6a,
            0x6a, 0x3f, 0x3c, 0x69, 0x33, 0x66, 0x65, 0x30, 0x30, 0x65, 0x66, 0x33, 0x69, 0x3c, 0x3f, 0x6a,
            0x0f, 0x5a, 0x59, 0x0c, 0x56, 0x03, 0x00, 0x55, 0x55, 0x00, 0x03, 0x56, 0x0c, 0x59, 0x5a, 0x0f,
            0x0c, 0x59, 0x5a, 0x0f, 0x55, 0x00, 0x03, 0x56, 0x56, 0x03, 0x00, 0x55, 0x0f, 0x5a, 0x59, 0x0c,
            0x69, 0x3c, 0x3f, 0x6a, 0x30, 0x65, 0x66, 0x33, 0x33, 0x66, 0x65, 0x30, 0x6a, 0x3f, 0x3c, 0x69,
            0x03, 0x56, 0x55, 0x00, 0x5a, 0x0f, 0x0c, 0x59, 0x59, 0x0c, 0x0f, 0x5a, 0x00, 0x55, 0x56, 0x03,
            0x66, 0x33, 0x30, 0x65, 0x3f, 0x6a, 0x69, 0x3c, 0x3c, 0x69, 0x6a, 0x3f, 0x65, 0x30, 0x33, 0x66,
            0x65, 0x30, 0x33, 0x66, 0x3c, 0x69, 0x6a, 0x3f, 0x3f, 0x6a, 0x69, 0x3c, 0x66, 0x33, 0x30, 0x65,
            0x00, 0x55, 0x56, 0x03, 0x59, 0x0c, 0x0f, 0x5a, 0x5a, 0x0f, 0x0c, 0x59, 0x03, 0x56, 0x55, 0x00
        };

        // calcs ECC for a 256-byte block
        public static byte[] Calculate256Ecc(byte[] pageData, int offset)
        {
            byte idx, reg1, reg2, reg3, tmp1, tmp2;
            int i;

            /* Initialize variables */
            reg1 = reg2 = reg3 = 0;

            /* Build up column parity */
            for (i = 0; i < 256; i++)
            {
                /* Get CP0 - CP5 from table */
                idx = EccPrecalcTable[pageData[i + offset]];
                reg1 ^= (byte)(idx & 0x3f);

                /* All bit XOR = 1 ? */
                if ((idx & 0x40) == 0x40)
                {
                    reg3 ^= (byte)i;
                    reg2 ^= (byte)~((byte)i);
                }
            }

            /* Create non-inverted ECC code from line parity */
            tmp1 = (byte)((reg3 & 0x80) >> 0); /* B7 -> B7 */
	        tmp1 |= (byte)((reg2 & 0x80) >> 1); /* B7 -> B6 */
	        tmp1 |= (byte)((reg3 & 0x40) >> 1); /* B6 -> B5 */
	        tmp1 |= (byte)((reg2 & 0x40) >> 2); /* B6 -> B4 */
	        tmp1 |= (byte)((reg3 & 0x20) >> 2); /* B5 -> B3 */
	        tmp1 |= (byte)((reg2 & 0x20) >> 3); /* B5 -> B2 */
	        tmp1 |= (byte)((reg3 & 0x10) >> 3); /* B4 -> B1 */
	        tmp1 |= (byte)((reg2 & 0x10) >> 4); /* B4 -> B0 */

	        tmp2 = (byte)((reg3 & 0x08) << 4); /* B3 -> B7 */
	        tmp2 |= (byte)((reg2 & 0x08) << 3); /* B3 -> B6 */
	        tmp2 |= (byte)((reg3 & 0x04) << 3); /* B2 -> B5 */
	        tmp2 |= (byte)((reg2 & 0x04) << 2); /* B2 -> B4 */
	        tmp2 |= (byte)((reg3 & 0x02) << 2); /* B1 -> B3 */
	        tmp2 |= (byte)((reg2 & 0x02) << 1); /* B1 -> B2 */
	        tmp2 |= (byte)((reg3 & 0x01) << 1); /* B0 -> B1 */
	        tmp2 |= (byte)((reg2 & 0x01) << 0); /* B7 -> B0 */

            /* Calculate final ECC code */
            byte[] ecc = new byte[3];
            ecc[0] = (byte)~tmp2;
            ecc[1] = (byte)~tmp1;
            ecc[2] = (byte)(((~reg1) << 2) | 0x03);

	        return ecc;
        }
    }
}
