using System.IO;
using System.Text;
using iQueTool.Structs;

namespace iQueTool.Files
{
    public class iQueKernelFile
    {
        public const int SIGAREA_ADDR = 0x10000;
        public const int SIGAREA_END_ADDR = 0x14000;
        public const int SIGAREA_SZ = 0x4000;

        private long startAddr;
        private IO io;
        public string FilePath;

        public iQueSysAppSigArea SA1SigArea;
        public bool HasSA2 = false;
        public iQueSysAppSigArea SA2SigArea;

        public iQueKernelFile(string filePath)
        {
            FilePath = filePath;
            io = new IO(filePath);
        }

        public iQueKernelFile(IO io)
        {
            this.io = io;
        }

        public bool Read()
        {
            startAddr = io.Stream.Position;
            io.Stream.Position = startAddr + SIGAREA_ADDR;

            SA1SigArea = io.Reader.ReadStruct<iQueSysAppSigArea>();
            SA1SigArea.EndianSwap();

            var sa2pos = startAddr + SIGAREA_END_ADDR + SA1SigArea.TitleData.ContentSize;
            if(sa2pos + SIGAREA_SZ < io.Stream.Length) // make sure this stream contains the SA2 sigarea
            {
                io.Stream.Position = sa2pos;
                SA2SigArea = io.Reader.ReadStruct<iQueSysAppSigArea>();
                SA2SigArea.EndianSwap();
                HasSA2 = true;
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
            b.AppendLineSpace(SA1SigArea.ToString(formatted, "SKSA.SA1SigArea"));
            if(HasSA2)
            {
                b.AppendLine();
                b.AppendLineSpace(SA2SigArea.ToString(formatted, "SKSA.SA2SigArea"));
            }

            return b.ToString();
        }

        public void Extract(string extPath)
        {
            io.Stream.Position = startAddr + SIGAREA_ADDR;
            byte[] sa1sig = io.Reader.ReadBytes(SIGAREA_SZ);
            byte[] sa1 = io.Reader.ReadBytes((int)SA1SigArea.TitleData.ContentSize);

            File.WriteAllBytes(extPath + $".{SA1SigArea.TitleData.ContentId}-sa1sig", sa1sig);
            if(sa1.Length > 0)
                File.WriteAllBytes(extPath + $".{SA1SigArea.TitleData.ContentId}-sa1", sa1);
            if (HasSA2)
            {
                byte[] sa2sig = io.Reader.ReadBytes(SIGAREA_SZ);
                byte[] sa2 = io.Reader.ReadBytes((int)SA2SigArea.TitleData.ContentSize);
                File.WriteAllBytes(extPath + $".{SA2SigArea.TitleData.ContentId}-sa2sig", sa2sig);
                if (sa2.Length > 0)
                    File.WriteAllBytes(extPath + $".{SA2SigArea.TitleData.ContentId}-sa2", sa2);
            }
        }
    }
}
