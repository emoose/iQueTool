using System.Collections.Generic;
using System.Text;

namespace iQueTool.Files
{
    public class iQueArrayFile<T> : List<T>
    {
        private IO io;
        public string FilePath;

        public iQueArrayFile(string filePath)
        {
            FilePath = filePath;
            io = new IO(filePath);
            Read();
        }

        public iQueArrayFile(byte[] data)
        {
            io = new IO(new System.IO.MemoryStream(data));
            Read();
        }

        bool Read()
        {
            var numEntries = io.Reader.ReadUInt32().EndianSwap();
            for (uint i = 0; i < numEntries; i++)
            {
                var entry = io.Reader.ReadStruct<T>();
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
            b.AppendLine($"Num {typeof(T).Name} entries: {Count}");
            b.AppendLine();
            for (int i = 0; i < Count; i++)
            {
                b.AppendLine(this[i].ToString());
            }

            return b.ToString();
        }
    }
}
