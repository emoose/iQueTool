iQueTool
========

```
iQueTool 0.1a: iQue Player file manipulator
Usage  : iquetool.exe [mode] [parameters] [filepath]

Valid modes: nand / tickets / certs / crl

General Parameters:
   -h (-help) - print iquetool usage
   -i (-info) - print basic info about file
   -wi (-writeinfo) - write detailed info about file to [filepath].txt
   -o (-output) <output-path> - specify output filename/directory

Mode "tickets" / "certs" / "crl" Parameters:

   -x - extracts all entries from file
   -xi (-extractids) <comma-delimited-ids> - extract entries with these indexes
   -xc (-extractcids) <comma-delimited-cids> - extract entries with these content ids
   -xt (-extracttids) <comma-delimited-tids> - extract entries with these ticket ids

   -n - writes extracted entries into a single array file

Note that by default the extract commands above will extract tickets as seperate files
with the format <output-dir>\ticket-<bbid>-<contentid>-<tid>.dat

Mode "nand" Parameters:

   -x - extracts all files from NAND
   -xi (-extractids) <comma-delimited-ids> - extract inodes with these indexes
   -xk (-extractkernel) - extract secure-kernel from NAND
   -fs (-showallfs) - shows info about all found FS blocks

   -sc (-skipchecksums) - skip verifying FS checksums
   -bd (-baddump) - will try reading inodes with a 0x10 byte offset

iQue signature verification:
   To enable, drop a cert.sys file (taken from an iQue NAND) next to the iQueTool exe
   Alternatively you can put it at the root of your D: drive
   Also when opening a NAND image the cert.sys will automatically be loaded from it, if not already found locally
```
