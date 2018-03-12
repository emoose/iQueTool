using System.IO;
using System.Text;
using iQueTool.Structs;

namespace iQueTool.Files
{
    public class iQueKernel
    {
        public const int SIGAREA_ADDR = 0x10000;
        public const int SIGAREA_END_ADDR = 0x14000;
        public const int SIGAREA_SZ = 0x4000;

        private long startAddr;
        private IO io;
        public string FilePath;

        public long SA1Addr = -1;
        public iQueSysAppSigArea SA1SigArea;
        public long SA2Addr = -1;
        public iQueSysAppSigArea SA2SigArea;

        public bool SA2IsValid
        {
            get
            {
                return SA2Addr > -1 && SA2SigArea.AuthorityAddr == 0x53C;
            }
        }

        public iQueKernel(string filePath)
        {
            FilePath = filePath;
            io = new IO(filePath);
        }

        public iQueKernel(IO io)
        {
            this.io = io;
        }

        public bool Read()
        {
            startAddr = io.Stream.Position;

            SA1Addr = startAddr + SIGAREA_ADDR;
            if (SA1Addr + SIGAREA_SZ >= io.Stream.Length)
            {
                SA1Addr = -1;
                return false;
            }
            io.Stream.Position = SA1Addr;

            SA1SigArea = io.Reader.ReadStruct<iQueSysAppSigArea>();
            SA1SigArea.EndianSwap();

            SA2Addr = SA1Addr + SIGAREA_SZ + SA1SigArea.Ticket.ContentSize;
            if(SA1SigArea.Ticket.ContentSize == 0 || SA2Addr + SIGAREA_SZ >= io.Stream.Length)
            {
                SA2Addr = -1;
                return true; // we read SA1 fine so return true
            }
            
            io.Stream.Position = SA2Addr;
            SA2SigArea = io.Reader.ReadStruct<iQueSysAppSigArea>();
            SA2SigArea.EndianSwap();

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
            if(SA2IsValid)
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
            byte[] sa1 = io.Reader.ReadBytes((int)SA1SigArea.Ticket.ContentSize);

            File.WriteAllBytes(extPath + $".{SA1SigArea.Ticket.ContentId}-sa1sig", sa1sig);
            if(sa1.Length > 0)
                File.WriteAllBytes(extPath + $".{SA1SigArea.Ticket.ContentId}-sa1", sa1);
            if (SA2IsValid)
            {
                byte[] sa2sig = io.Reader.ReadBytes(SIGAREA_SZ);
                byte[] sa2 = io.Reader.ReadBytes((int)SA2SigArea.Ticket.ContentSize);
                File.WriteAllBytes(extPath + $".{SA2SigArea.Ticket.ContentId}-sa2sig", sa2sig);
                if (sa2.Length > 0)
                    File.WriteAllBytes(extPath + $".{SA2SigArea.Ticket.ContentId}-sa2", sa2);
            }
        }
    }
}
