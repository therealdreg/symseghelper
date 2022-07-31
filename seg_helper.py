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

import pprint
import os
import sys


class TYPE_L:
    WHITE_LIST = 1
    BLACK_LIST = 2

type_list = TYPE_L.BLACK_LIST
names_list = [ "null" ]

#type_list = TYPE_L.WHITE_LIST
#names_list = [ "nt", "hal", "kernel32", "ntdll", "atapi" ]

# To use all modules uncomment this line: 
#names_list = None

default_seg_type = 1

def check_if_log(mod):
    if names_list is None:
        return True
    elif type_list == TYPE_L.WHITE_LIST:
        if mod in names_list:
            return True
    elif type_list == TYPE_L.BLACK_LIST:
        if mod not in names_list:
            return True
    return False


cred = '''
https://github.com/therealdreg/symseghelper
Helper scripts for windows debugging with symbols for Bochs and IDA Pro (PDB files). Very handy for user mode <--> kernel mode
-
GNU General Public License v3.0
-
by David Reguera Garcia aka Dreg
Twitter @therealdreg
https://www.fr33project.org
dreg@fr33project.org
https://github.com/therealdreg
'''
print(cred)

# I know, I know, ugly and dirty as hell x-)
def get_seg_type(modf):
    seg_type = default_seg_type
    if b"MZ" == modf.read(2):
        print("valid MZ")
        modf.read(0x3A)
        ptr_pe = int.from_bytes(modf.read(4), byteorder='little')
        print("ptr to PE-> ", hex(ptr_pe))
        modf.read(ptr_pe - 0x40)
        if b"PE" == modf.read(2):
            print("valid PE")
            modf.read(0x16)
            optional_hdr = modf.read(92)
            magic = int.from_bytes(optional_hdr[:2], byteorder='little')
            print("magic: ", hex(magic))
            if 0x20B == magic:
                seg_type = 2
                print("PE64")
            else:
                seg_type = 1
                print("PE32")
            checksum = int.from_bytes(optional_hdr[0x40:0x44], byteorder='little')
            print("checksum: ",  hex(checksum))
        else:
            print("not valid PE")
    else:
        print("not valid MZ")
    return seg_type

lm_info = []
with open(sys.argv[1], 'r', errors='ignore') as out:
    new_entry = {}
    lines = out.readlines()
    for line in lines:
        line = " ".join(line.split())
        if "symbols)" in line.lower():
            if len(new_entry):
                lm_info.append(new_entry)
            new_entry = {}
            new_entry["start_addr"] = "0x" + line.split()[0].strip()
            new_entry["end_addr"] = "0x" + line.split()[1].strip()
            new_entry["name"] = line.split()[2].strip()
            new_entry["pdb_path"] = ""
            pos_pdb = ' '.join(line.split()[5:]).strip()
            if pos_pdb.endswith(".pdb"):
                new_entry["pdb_path"] =  pos_pdb
            else:
                new_entry["pos_pdb_path"] =  pos_pdb
        elif "mage file:" in line.lower():
            new_entry["image_file"] = ' '.join(line.split(": ")[1:]).strip()
        elif "mage path:" in line.lower():
            new_entry["image_path"] = ' '.join(line.split(": ")[1:]).strip()
        elif "mage name:" in line.lower():
            new_entry["image_name"] = ' '.join(line.split(": ")[1:]).strip()
        elif "ecksum:" in line.lower():
            tmpval = ' '.join(line.split(": ")[1:]).strip()
            if "issing" in tmpval.lower():
                tmpval = "00"
            new_entry["checksum"] = "0x" +  tmpval
        elif "magesize:" in line.lower():
            new_entry["image_size"] = "0x" + ' '.join(line.split(": ")[1:]).strip()
    if len(new_entry):
        lm_info.append(new_entry)  

with open(sys.argv[3], "w+") as ida_segf:
    with open(sys.argv[4], "w+") as bochs_segf:
        files_found = []
        for root, dirs, files in os.walk(sys.argv[2]):
            for file in files:
                if check_if_log(file.lower()):
                    print(file)
                    print("-------------------")
                    with open(os.path.abspath(os.path.join(root, file)), 'rb') as modf:
                        try:
                            seg_type = get_seg_type(modf)
                            print("seg type: ", seg_type)
                            entry = list(filter(lambda entry: entry['name'].lower() == file.lower(), lm_info))[0]
                            pprint.pprint(entry) 
                            ida_segf.write(entry["start_addr"] + " " + entry["end_addr"] + " " + str(seg_type) + " " + file  +"\n")
                            bochs_segf.write(entry["start_addr"] + " " + file + "\n")
                            bochs_segf.write(entry["end_addr"] + " " + file + "_end" + "\n")
                            files_found.append(file.lower())
                            print(" ")
                        except:
                            print(" ")
                            pass
        if names_list is not None:
            if type_list == TYPE_L.WHITE_LIST:
                not_found = set(names_list) ^ set(files_found)
                if len(not_found):
                    print("\nWARNING: not found info for: ", str(not_found))
