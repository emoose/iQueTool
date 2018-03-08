using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace iQueTool
{
    class Natives
    {
        [StructLayout(LayoutKind.Sequential)]
        // ReSharper disable once InconsistentNaming
        public struct BCRYPT_PSS_PADDING_INFO
        {
            public BCRYPT_PSS_PADDING_INFO(string pszAlgId, int cbSalt)
            {
                this.pszAlgId = pszAlgId;
                this.cbSalt = cbSalt;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;
            public int cbSalt;
        }

        [DllImport("ncrypt.dll", SetLastError = false)]
        public static extern uint NCryptOpenStorageProvider(out IntPtr phProvider,
                                                      [MarshalAs(UnmanagedType.LPWStr)] string pszProviderName,
                                                      uint dwFlags);

        [DllImport("ncrypt.dll", SetLastError = false)]
        public static extern uint NCryptImportKey(IntPtr hProvider,
                                                  IntPtr hImportKey,
                                                  [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                  IntPtr pParameterList,
                                                  out IntPtr phKey,
                                                  [MarshalAs(UnmanagedType.LPArray)]
                                                  byte[] pbData,
                                                  uint cbData,
                                                  uint dwFlags);

        [DllImport("ncrypt.dll", SetLastError = false)]
        public static extern uint NCryptVerifySignature(IntPtr hKey,
                                                        [In] ref BCRYPT_PSS_PADDING_INFO pPaddingInfo,
                                                        [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbHashValue,
                                                        int cbHashValue,
                                                        [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbSignature,
                                                        int cbSignature,
                                                        uint dwFlags);

        [DllImport("ncrypt.dll", SetLastError = false)]
        public static extern uint NCryptSignHash(IntPtr hKey,
                                                        [In] ref BCRYPT_PSS_PADDING_INFO pPaddingInfo,
                                                        [MarshalAs(UnmanagedType.LPArray)]
                                                        byte[] pbHashValue,
                                                        int cbHashValue,
                                                        [MarshalAs(UnmanagedType.LPArray)]
                                                        byte[] pbSignature,
                                                        int cbSignature,
                                                        [Out] out uint pcbResult,
                                                        int dwFlags);

        [DllImport("ncrypt.dll", SetLastError = false)]
        public static extern uint NCryptSignHash(IntPtr hKey,
                                                        [In] ref BCRYPT_PSS_PADDING_INFO pPaddingInfo,
                                                        [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbHashValue,
                                                        int cbHashValue,
                                                        IntPtr pbSignature,
                                                        int cbSignature,
                                                        [Out] out uint pcbResult,
                                                        uint dwFlags);

        [DllImport("ncrypt.dll", SetLastError = false)]
        public static extern uint NCryptFreeObject(IntPtr hObject);

        internal static RSAParameters GenerateRSAParametersFromPublicKey(byte[] exponent, byte[] modulus)
        {
            return new RSAParameters
            {
                Exponent = exponent,
                Modulus = Swap8(modulus)
            };
        }
        internal static RSAParameters GenerateRSAParametersFromPublicKey(byte[] publicKey)
        {
            //return GenerateRSAParametersFromPublicKey(publicKey, false);
            return new RSAParameters
            {
                Exponent = Swap(GetData(publicKey, 0x00, 0x04)),
                Modulus = Swap8(GetData(publicKey, 0x4, 0x200))
            };
        }

        internal static byte[] GetData(byte[] data, int pos, int length)
        {
            // Create a new output buffer
            byte[] outBuffer = new byte[length];

            // Loop and copy the data
            for (int x = pos, y = 0; x < pos + length; x++, y++)
                outBuffer[y] = data[x];

            // Return our data
            return outBuffer;
        }
        internal static byte[] Swap8(byte[] input)
        {
            byte[] buffer = new byte[input.Length];
            Array.Copy(input, buffer, input.Length);
            for (int x = 0; x < input.Length; x += 8)
                Array.Reverse(buffer, x, 8);

            return Swap(buffer);
        }
        internal static byte[] Swap(byte[] input)
        {
            byte[] buffer = new byte[input.Length];
            Array.Copy(input, buffer, input.Length);
            Array.Reverse(buffer);
            return buffer;
        }

    }
}
