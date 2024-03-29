# symseghelper
Helper scripts for windows debugging with symbols for Bochs and IDA Pro (PDB files). Very handy for user mode <--> kernel mode

![bochstvshow](img/bochstvshow.gif)

![names](img/mnames.png)

# Fast and easy way - only names

In Guest: Install windows debugging tools (windbg)

In Guest: install debug symbols

In Guest: execute windbg with command line -logo:
```
"C:\Program Files\Debugging Tools for Windows (x86)\windbg.exe" -logo c:\windbg_syms_output.txt
```

Go to File -> Kernel Debug -> Local

Go to File -> Symbol File Path -> Browse 

Select your symbol path (for me its C:\winsymbols), Select Reload -> OK

List all processes in windbg with:
```
!process 0 0 

...

PROCESS 8982ec20  SessionId: 0  Cid: 056c    Peb: 7ffd7000  ParentCid: 0548
    DirBase: 10a83000  ObjectTable: e18f4320  HandleCount: 237.
    Image: explorer.exe

...
```

Attach to explorer.exe with **.process /p /r** 8976e2d0 (it has a a lot of user mode dlls)
```
.process /p /r 8982ec20
```

type: 
```
.reload -a
```

type:
```
.reload /f
```

Execute in windbg:
```
x /2 *!*
```

Wait and be patient

Close windbg

Clean c:\windbg_syms_output.txt file, removing all lines before
```
lkd> x /2 *!*
```

Something like this should be the file cleaned:

```
7ffe0300 SharedUserData!SystemCallStub
00af1d80 kext!diskspace
00af2af0 kext!DebugExtensionInitialize
00af2bb0 kext!DebugExtensionNotify
00af2ce0 kext!DebugExtensionUninitialize
...
f7ba0a90 Ntfs!LfsAllocateSpanningBuffer
f7b78831 Ntfs!NtfsQueryBasicInfo
f7b85653 Ntfs!NtfsCacheSharedSecurityByDescriptor
```

Ok, move this file (windbg_syms_output.txt) to Host

In Host: Execute
```
windbgsymsparser.py windbg_syms_output.txt bochs_syms_and_ida_names.txt
```

How to use this file in Bochs:

Read [Bochs](#bochs)
 
How to use this file in IDA PRO:

Read [IDA PRO](#ida-pro)

# Hard and slow way - segments and names

Only use this way if you need it

## Demo video hard way

(windbg_output.txt was generated in Guest off the record)

https://youtu.be/7o3JBIzP1bI

## Reqs

in Host:
```
pip install pefile
```

## Editing symseghelper.py

you must edit some variables in symseghelper.py file

in Host: Copy guest system32 folder to host and update:

```
path_guest_system32 = r"C:\dreg\system32"
```

in Host: git clone pdbdump_bochs

```
git clone https://github.com/therealdreg/pdbdump_bochs.git
```

in Host: Update pdbdump paths:
```
filepath_pdbdump32 = r"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe"
filepath_pdbdump64 = r"C:\Users\leno\Desktop\pdbdump_bochs\x64\x64_pdbdump_bochs.exe"
```

in Host: Update windbg_output path:
```
filepath_windbg_output = r"C:\Users\leno\Desktop\symseghelper\windbg_output.txt"
```

windbg_output.txt must be generated in Guest machine use windbg lm command

in Host: Update output paths (these fille will be generated by symseghelper.py parsing windbg_output.txt):
```
filepath_pdbdumpbat = r"C:\Users\leno\Desktop\symseghelper\pdbdumpbat.bat"
filepath_ida_segments = r"C:\Users\leno\Desktop\symseghelper\ida_segments.txt"
filepath_bochs_segments = r"C:\Users\leno\Desktop\symseghelper\bochs_segments.txt"
```

Host & Guest: Download windows debug symbols to the SAME PATH (VERY IMPORTANT)

Example: if you use C:\winsymbols in Guest you must use C:\winsymbols in Host

## Generating a valid windbg_output.txt

Open Guest 

In Guest: Install windows debugging tools (windbg)

In Guest: Open Windbg

Go to File -> Kernel Debug -> Local

Go to File -> Symbol File Path -> Browse 

Select your symbol path (for me its C:\winsymbols), Select Reload -> OK

List all processes in windbg with:
```
!process 0 0 

...

PROCESS 8982ec20  SessionId: 0  Cid: 056c    Peb: 7ffd7000  ParentCid: 0548
    DirBase: 10a83000  ObjectTable: e18f4320  HandleCount: 237.
    Image: explorer.exe

...
```

Attach to explorer.exe with **.process /p /r** 8976e2d0 (it has a a lot of user mode dlls)
```
.process /p /r 8982ec20
```

type: 
```
.reload -a
```

type:
```
.reload /f
```

copy **lm vo** command output to windbg_output.txt
```
lm vo

806d0000 806f0300   hal        (pdb symbols)          c:\winsymbols\dll\halaacpi.pdb
    Loaded symbol image file: halaacpi.dll
    Image path: halaacpi.dll
    Image name: halaacpi.dll
    Timestamp:        Sun Apr 13 11:31:27 2008 (4802517F)
    CheckSum:         00024F17
    ImageSize:        00020300
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
bf800000 bf9c2980   win32k     (pdb symbols)          c:\winsymbols\sys\win32k.pdb
    Loaded symbol image file: \SystemRoot\System32\win32k.sys
    Image path: \SystemRoot\System32\win32k.sys
    Image name: win32k.sys
    Timestamp:        Sun Apr 13 12:29:46 2008 (48025F2A)
    CheckSum:         001CC002
    ImageSize:        001C2980
    File version:     5.1.2600.5512
    Product version:  5.1.2600.5512
    File flags:       0 (Mask 3F)
    File OS:          40004 NT Win32
    File type:        3.7 Driver
    File date:        00000000.00000000
    Translations:     0409.04b0
    CompanyName:      Microsoft Corporation
    ProductName:      Microsoft® Windows® Operating System
    InternalName:     win32k.sys
    OriginalFilename: win32k.sys
    ProductVersion:   5.1.2600.5512
    FileVersion:      5.1.2600.5512 (xpsp.080413-2105)
    FileDescription:  Multi-User Win32 Driver
    LegalCopyright:   © Microsoft Corporation. All rights reserved.
    ....
```

Move windbg_output.txt file to Host

Done!

## Execute scripts

in Host: run symseghelper.py

it generates some files:

### bochs_segments.txt
```
0x00b30000 kext
0x00e40000 odbcint
0x01000000 windbg
0x01400000 ext
...
```

you can use this file in Bochs debugger with ldsym global, example:

```
ldsym global "C:\\Users\\leno\\Desktop\\symseghelper\\bochs_segments.txt"
```

### ida_segments.txt
```
0x00b30000 0x00b66000 1 kext
0x00e40000 0x00e57000 1 odbcint
0x01000000 0x01097000 1 windbg
0x01400000 0x016f9000 1 ext
0x01900000 0x01975000 1 exts
...
```

in Host: Open IDA PRO, start a debug session and go to File -> Script File 

Select idaloadsegs.py

And now idaloadsegs.py ask you for ida_segments.txt, just select ida_segments.txt 

![segments](img/segments.png)

### pdbdumpbat.bat

in Host: You must execute pdbdumpbat.bat to generate bochs_syms_and_ida_names.txt

#### bochs_syms_and_ida_names.txt

```
0x7c801160 kernel32!_imp__NtFindAtom
0x7c825e00 kernel32!c_PmapEntries_apphelp
0x7c863ca4 kernel32!GetThreadTimes
...
```

##### IDA PRO

in Host: Open IDA PRO, start a debug session and go to File -> Script File 

Select idaloadnames.py

And now idaloadnames.py ask you for bochs_syms_and_ida_names.txt, just select bochs_syms_and_ida_names.txt

![names](img/mnames.png)

##### Bochs

in Host: Open Bochs Debugger, start a debug session, Press Ctrl + C (break). Use ldsym global bochs_syms_and_ida_names.txt 

Example:
```
ldsym global "C:\\Users\\leno\\Desktop\\symseghelper\\bochs_syms_and_ida_names.txt"
```

Done!

![betweenrings](img/betweenrings.png)
 
# Related

- https://github.com/therealdreg/pdbdump_bochs
- https://github.com/therealdreg/ida_bochs_windows
- https://github.com/therealdreg/ida_vmware_windows_gdb
