using System;
using System.Collections.Generic;
using System.Text;
using iQueTool.Structs;

namespace iQueTool.Files
{
    public class iQueCertCollection : List<iQueCertificate>
    {
        private IO io;
        public string FilePath;

        public static iQueCertCollection MainCollection; // fml...

        public iQueCertCollection(string filePath)
        {
            FilePath = filePath;
            io = new IO(filePath);
            Read();
        }

        public iQueCertCollection(byte[] data)
        {
            io = new IO(new System.IO.MemoryStream(data));
            Read();
        }

        bool Read()
        {
            var numEntries = io.Reader.ReadUInt32().EndianSwap();
            for (uint i = 0; i < numEntries; i++)
            {
                var entry = io.Reader.ReadStruct<iQueCertificate>();
                entry.EndianSwap();
                Add(entry);
            }
            return true;
        }

        public override string ToString()
        {
            return ToString(false);
        }

        public string ToString(bool formatted)
        {
            var b = new StringBuilder();
            b.AppendLine($"Num iQueCertificate entries: {Count}");
            b.AppendLine();
            for (int i = 0; i < Count; i++)
            {
                b.AppendLine(this[i].ToString(formatted, $"iQueCertificate-{i}"));//, i));
            }

            return b.ToString();
        }

        public bool GetCertificate(string certName, out iQueCertificate cert)
        {
            foreach(var c in this)
            {
                if (c.CertNameString.Equals(certName, StringComparison.InvariantCultureIgnoreCase) || $"{c.AuthorityString}-{c.CertNameString}".Equals(certName, StringComparison.InvariantCultureIgnoreCase))
                {
                    cert = c;
                    return true;
                }
            }

            cert = new iQueCertificate();
            return false;
        }
    }
}
