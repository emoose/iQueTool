using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace iQueTool
{
    // ReSharper disable once InconsistentNaming
    public class IO : IDisposable
    {
        public BinaryReader Reader;
        public BinaryWriter Writer;
        public Stream Stream;

        public IO(string filePath)
        {
            Stream = new FileStream(filePath, FileMode.Open);
            InitIo();
        }

        public IO(string filePath, FileMode mode)
        {
            Stream = new FileStream(filePath, mode);
            InitIo();
        }

        public IO(Stream baseStream)
        {
            Stream = baseStream;
            InitIo();
        }

        public void Dispose()
        {
            Stream.Dispose();
        }

        public bool AddBytes(long numBytes)
        {
            const int blockSize = 0x1000;

            long startPos = Stream.Position;
            long startSize = Stream.Length;
            long endPos = startPos + numBytes;
            long endSize = Stream.Length + numBytes;

            Stream.SetLength(endSize);

            long totalWrite = startSize - startPos;

            while (totalWrite > 0)
            {
                int toRead = totalWrite < blockSize ? (int)totalWrite : blockSize;

                Stream.Position = startPos + (totalWrite - toRead);
                var data = Reader.ReadBytes(toRead);

                Stream.Position = startPos + (totalWrite - toRead);
                var blankData = new byte[toRead];
                Writer.Write(blankData);

                Stream.Position = endPos + (totalWrite - toRead);
                Writer.Write(data);

                totalWrite -= toRead;
            }

            Stream.Position = startPos;

            return true;
        }

        public bool DeleteBytes(long numBytes)
        {
            if (Stream.Position + numBytes > Stream.Length)
                return false;

            const int blockSize = 0x1000;

            long startPos = Stream.Position;
            long endPos = startPos + numBytes;
            long endSize = Stream.Length - numBytes;
            long i = 0;

            while (i < endSize)
            {
                long totalRemaining = endSize - i;
                int toRead = totalRemaining < blockSize ? (int)totalRemaining : blockSize;

                Stream.Position = endPos + i;
                byte[] data = Reader.ReadBytes(toRead);

                Stream.Position = startPos + i;
                Writer.Write(data);

                i += toRead;
            }

            Stream.SetLength(endSize);
            return true;
        }

        private void InitIo()
        {
            Reader = new BinaryReader(Stream);
            Writer = new BinaryWriter(Stream);
        }
    }
    public static class Shared
    {
        public static string FindFile(string fileName)
        {
            string test = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName);
            if (File.Exists(test))
                return test;
            string[] drives = Directory.GetLogicalDrives();
            foreach (string drive in drives)
            {
                test = Path.Combine(drive, fileName);
                if (File.Exists(test))
                    return test;
            }
            return String.Empty;
        }

        /// <summary>
        /// Reads in a block from a file and converts it to the struct
        /// type specified by the template parameter
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static T ReadStruct<T>(this BinaryReader reader)
        {
            var size = Marshal.SizeOf(typeof(T));
            // Read in a byte array
            var bytes = reader.ReadBytes(size);

            return BytesToStruct<T>(bytes);
        }

        public static bool WriteStruct<T>(this BinaryWriter writer, T structure)
        {
            byte[] bytes = StructToBytes(structure);

            writer.Write(bytes);

            return true;
        }

        public static T BytesToStruct<T>(byte[] bytes)
        {
            // Pin the managed memory while, copy it out the data, then unpin it
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public static byte[] StructToBytes<T>(T structure)
        {
            var bytes = new byte[Marshal.SizeOf(typeof(T))];

            // Pin the managed memory while, copy in the data, then unpin it
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            Marshal.StructureToPtr(structure, handle.AddrOfPinnedObject(), true);
            handle.Free();

            return bytes;
        }

        public static string ToHexString(this byte[] bytes)
        {
            return bytes.Aggregate("", (current, b) => current + (b.ToString("X2") + " "));
        }

        public static bool IsArrayEmpty(this byte[] bytes)
        {
            return bytes.All(b => b == 0);
        }
        public static bool IsEqualTo(this byte[] byte1, byte[] byte2)
        {
            if (byte1.Length != byte2.Length)
                return false;

            for (int i = 0; i < byte1.Length; i++)
                if (byte1[i] != byte2[i])
                    return false;

            return true;
        }

        public static bool IsFlagSet(this uint flags, uint flag)
        {
            return (flags & flag) == flag;
        }

        public static uint RemoveFlag(this uint flags, uint flag)
        {
            return IsFlagSet(flags, flag) ? ToggleFlag(flags, flag) : flags;
        }

        public static uint ToggleFlag(this uint flags, uint flag)
        {
            return (flags ^ flag);
        }

        public static void AppendLineSpace(this StringBuilder b, string str)
        {
            b.AppendLine(str + " ");
        }

        public static byte[] MorphIv(byte[] iv)
        {
            byte dl = 0;
            var newIv = new byte[0x10];

            for (int i = 0; i < 0x10; i++)
            {
                byte cl = iv[i];
                byte al = cl;
                al = (byte)(al + al);
                al = (byte)(al | dl);
                dl = cl;
                newIv[i] = al;
                dl = (byte)(dl >> 7);
            }
            if (dl != 0)
                newIv[0] = (byte)(newIv[0] ^ 0x87);
            return newIv;
        }

        public static short EndianSwap(this short num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToInt16(data, 0);
        }

        public static int EndianSwap(this int num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToInt32(data, 0);
        }

        public static long EndianSwap(this long num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToInt64(data, 0);
        }

        public static ushort EndianSwap(this ushort num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToUInt16(data, 0);
        }

        public static uint EndianSwap(this uint num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToUInt32(data, 0);
        }

        public static ulong EndianSwap(this ulong num)
        {
            byte[] data = BitConverter.GetBytes(num);
            Array.Reverse(data);
            return BitConverter.ToUInt64(data, 0);
        }

        public static bool iQueSignatureVerify(byte[] data, byte[] signature, byte[] pubKeyModulus, byte[] pubKeyExponent)
        {
            var hash = new SHA1Managed().ComputeHash(data);

            // resize sig in case its too large
            var sig = new byte[pubKeyModulus.Length];
            Array.Copy(signature, sig, pubKeyModulus.Length);

            using (var rsa = new RSACryptoServiceProvider())
            {
                var RSAKeyInfo = new RSAParameters() { Modulus = pubKeyModulus, Exponent = pubKeyExponent };
                rsa.ImportParameters(RSAKeyInfo);

                var RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                RSADeformatter.SetHashAlgorithm("SHA1");

                return RSADeformatter.VerifySignature(hash, sig);
            }
        }

        public static byte[] iQueSignatureDecrypt(byte[] signature, byte[] pubKeyModulus, byte[] pubKeyExponent)
        {
            var dir = Directory.GetCurrentDirectory();
            if (!File.Exists(@"x86\libeay32.dll") || !File.Exists(@"x86\ssleay32.dll"))
                return null; // can't find openssl dlls...

            var sig = new byte[pubKeyModulus.Length];
            Array.Copy(signature, sig, pubKeyModulus.Length);

            var rsa = new OpenSSL.Crypto.RSA();
            rsa.PublicModulus = OpenSSL.Core.BigNumber.FromArray(pubKeyModulus);
            rsa.PublicExponent = OpenSSL.Core.BigNumber.FromArray(pubKeyExponent);

            byte[] decsig = rsa.PublicDecrypt(sig, OpenSSL.Crypto.RSA.Padding.None);

            // seems to use some kind of padding, PKCS1?
            // might be why fakesigning failed to work - our fakesign sig would have bad padding
            // need to find a signature that has retVal[0] below set to 0!
            byte[] retVal = new byte[0x14];
            Array.Copy(decsig, 236, retVal, 0, 0x14);
            return retVal;
        }

        // from https://stackoverflow.com/questions/249760/how-can-i-convert-a-unix-timestamp-to-datetime-and-vice-versa
        public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }
    }
}