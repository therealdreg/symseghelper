cd %~dp0
del /F /Q bochs_syms_and_ida_names.txt
"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe" -b c:\winsymbols\dll\kernel32.pdb:0x7c800000 PFX:kernel32! >> bochs_syms_and_ida_names.txt 
"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe" -b c:\winsymbols\dll\ntdll.pdb:0x7c900000 PFX:ntdll! >> bochs_syms_and_ida_names.txt 
"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe" -b c:\winsymbols\exe\ntkrnlpa.pdb:0x804d7000 PFX:nt! >> bochs_syms_and_ida_names.txt 
"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe" -b c:\winsymbols\dll\halaacpi.pdb:0x806d0000 PFX:hal! >> bochs_syms_and_ida_names.txt 
"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe" -b c:\winsymbols\sys\atapi.pdb:0xf7451000 PFX:atapi! >> bochs_syms_and_ida_names.txt 
