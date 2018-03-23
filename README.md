iQueTool
========

```
iQueTool 0.3: iQue Player file manipulator
Usage  : iquetool.exe [mode] [parameters] [filepath]

Valid modes: nand / tickets / certs / crl / sparefix

General parameters:
   -h (-help) - print iquetool usage
   -i (-info) - print basic info about file
   -wi (-writeinfo) - write detailed info about file to [filepath].txt
   -o (-output) <output-path> - specify output filename/directory

Mode "tickets" / "certs" / "crl":

   -x - extracts all entries from file
   -xi (-extractids) <comma-delimited-ids> - extract entries with these indexes
   -xc (-extractcids) <comma-delimited-cids> - extract entries with these content ids
   -xt (-extracttids) <comma-delimited-tids> - extract entries with these ticket ids

   -n - writes extracted entries into a single array file

Note that by default the extract commands above will extract tickets as seperate files
with the format <output-dir>\ticket-<bbid>-<contentid>-<tid>.dat

Mode "nand":

   -x - extracts all files from NAND
   -xi (-extractids) <comma-delimited-ids> - extract inodes with these indexes
   -xk (-extractkernel) - extract secure-kernel from NAND
   -fs (-showallfs) - shows info about all found FS blocks

   -uk (-updatekernel) <sksa-path> - updates NAND with the given (cache) SKSA
      also takes bad-blocks into account and will work around them
      use -gs afterwards to generate a new spare with proper SAData fields

   -gs (-genspare) <dest-spare.bin-path> - generates block-spare/ECC data for this NAND
   -gp (-fullspare) - will generate page-spare/ECC data (0x20 pages per block) instead

   -sc (-skipchecksums) - skip verifying FS checksums
   -fc (-fixchecksums) - skips verifying & repairs all FS checksums
   -bd (-baddump) - will try reading inodes with a 0x10 byte offset

Mode "sparefix":
   usage: sparefix [spare.bin path] <nand.bin path>
   fixes overdump / raw page-spare dumps to match BB block-spare dumps
   if nand.bin path is specified, will correct the spare data using that nand

   -o (-output) <output-path> - specify output filename (default: [input]_fixed)
   -gp (-fullspare) - disables reducing page-spare data to block-spare

iQue signature verification:
   To enable, drop a cert.sys file (taken from an iQue NAND) next to the iQueTool exe
   Alternatively you can put it at the root of your D: drive
   Also when opening a NAND image the cert.sys will automatically be loaded from it, if not already found locally
```
