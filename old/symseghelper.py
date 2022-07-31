#!/usr/bin/env python3

# https://github.com/therealdreg/symseghelper
# Helper scripts for windows debugging with symbols for Bochs and IDA Pro (PDB files). Very handy for user mode <--> kernel mode
# -
# GNU General Public License v3.0
# -
# by David Reguera Garcia aka Dreg
# Twitter @therealdreg
# https://www.fr33project.org
# dreg@fr33project.org
# https://github.com/therealdreg
# -
# WARNING: bullshit code

# pip install pefile

from pathlib import Path
import pprint
import pefile
import os

names_list = [ "nt", "hal", "kernel32", "ntdll", "atapi" ]

# To use all modules uncomment this line: 
#names_list = None

# You must change these values:

filepath_pdbdump32 = r"C:\Users\leno\Desktop\pdbdump_bochs\x32\x32_pdbdump_bochs.exe"
filepath_pdbdump64 = r"C:\Users\leno\Desktop\pdbdump_bochs\x64\x64_pdbdump_bochs.exe"
path_guest_system32 = r"C:\dreg\system32"
filepath_pdbdumpbat = r"C:\Users\leno\Desktop\symseghelper\pdbdumpbat.bat"
filepath_ida_segments = r"C:\Users\leno\Desktop\symseghelper\ida_segments.txt"
filepath_bochs_segments = r"C:\Users\leno\Desktop\symseghelper\bochs_segments.txt"
filepath_windbg_output = r"C:\Users\leno\Desktop\symseghelper\windbg_output.txt"

# end 

filepath_bochs_syms_and_ida_names = "bochs_syms_and_ida_names.txt"

default_seg_type = 1

listit = []
with open(filepath_windbg_output, 'r', errors='ignore') as out:
    newit = {}
    lines = out.readlines()
    for line in lines:
        line = " ".join(line.split())
        if "symbols)" in line.lower():
            if len(newit):
                listit.append(newit)
            newit = {}
            newit["start_addr"] = "0x" + line.split()[0].strip()
            newit["end_addr"] = "0x" + line.split()[1].strip()
            newit["name"] = line.split()[2].strip()
            newit["pdb_path"] = ""
            pos_pdb = ' '.join(line.split()[5:]).strip()
            if pos_pdb.endswith(".pdb"):
                newit["pdb_path"] =  pos_pdb
            else:
                newit["pos_pdb_path"] =  pos_pdb
        elif "mage file:" in line.lower():
            newit["image_file"] = ' '.join(line.split(": ")[1:]).strip()
        elif "mage path:" in line.lower():
            newit["image_path"] = ' '.join(line.split(": ")[1:]).strip()
        elif "mage name:" in line.lower():
            newit["image_name"] = ' '.join(line.split(": ")[1:]).strip()
        elif "ecksum:" in line.lower():
            tmpval = ' '.join(line.split(": ")[1:]).strip()
            if "issing" in tmpval.lower():
                tmpval = "00"
            newit["checksum"] = "0x" +  tmpval
        elif "magesize:" in line.lower():
            newit["image_size"] = "0x" + ' '.join(line.split(": ")[1:]).strip()
    if len(newit):
        listit.append(newit)  
    #pprint.pprint(listit)  
       
def getsgty(file_path, tochecksum, checksig):
    try:
        pe = pefile.PE(file_path)
        if checksig:
            checksum = pe.OPTIONAL_HEADER.CheckSum
            if tochecksum == checksum:
                pass # print("ok checksum found! ", pe.OPTIONAL_HEADER.Magic, checksum, file_path)
            else:
                return 0
        
        if pe.OPTIONAL_HEADER.Magic == 0x20B:
            return 2
        else:
            return 1
    except:
        return 0
    



def rsg(file_name, tochecksum):
    fg = ""
    for root, dirs, files in os.walk(path_guest_system32):
                for file in files:
                    if file.lower() == file_name.lower():
                        fg = os.path.abspath(os.path.join(root, file))
                        seg = getsgty(fg, tochecksum, True)
                        if seg != 0:
                            return seg
                        
    print("not found valid checksum!", file_name)
    if len(fg):
        print("forcing to", fg)
        return getsgty(fg, tochecksum, False)

    return 0

def rsg_dsp(file_name, tochecksum):
    for root, dirs, files in os.walk(path_guest_system32):
                for file in files:
                    if file_name.lower() in file.lower():
                        fg = os.path.abspath(os.path.join(root, file))
                        seg = getsgty(fg, tochecksum, True)
                        if seg != 0:
                            print("ok solved to:", fg)
                            return seg
                        
    print("not found valid checksum!", file_name)

    return 0


if len(listit):
    with open(filepath_ida_segments, 'w+') as out:
        for e in listit:
            tonam = e["image_name"]
            if "hal" == e["name"]:
                tonam = "hal.dll" 
            #pprint.pprint(e)
            segment_type = rsg(tonam, int(e["checksum"], 16))
            if segment_type == 0:
                if len(e["pdb_path"]):
                    tonam = Path(e["pdb_path"]).stem
                elif len(e["pos_pdb_path"]):
                    tonam = Path(e["pos_pdb_path"]).stem
                else:
                    tonam = e["name"]
                print("try again with ", tonam)
                segment_type = rsg_dsp(tonam, int(e["checksum"], 16))
                if segment_type == 0:
                    print("nothing works with:", e["image_name"])
                    segment_type = default_seg_type
            e["segtype"] = segment_type
            outst = f'{e["start_addr"]} {e["end_addr"]} {e["segtype"]} {e["name"]}\n'
            out.write(outst)

    with open(filepath_bochs_segments, 'w+') as out:
        for e in listit:
            outst = f'{e["start_addr"]} {e["name"]}\n'
            out.write(outst)

    with open(filepath_pdbdumpbat, 'w+') as out:
        out.write(r"cd %~dp0")
        out.write(f"\ndel /F /Q {filepath_bochs_syms_and_ida_names}\n")
        for e in listit:
            if len(e["pdb_path"]):
                if names_list is None or e["name"].lower() in names_list:
                    if e["segtype"] == 1:
                        pdbpath = filepath_pdbdump32
                    else:
                        pdbpath = filepath_pdbdump64
                    out.write(f'"{pdbpath}" -b {e["pdb_path"]}:{e["start_addr"]} PFX:{e["name"]}! >> {filepath_bochs_syms_and_ida_names} \n')

    

