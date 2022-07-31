#!/usr/bin/env python3
# 
# # https://github.com/therealdreg/symseghelper
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

import sys
import re

class TYPE_L:
    WHITE_LIST = 1
    BLACK_LIST = 2

type_list = TYPE_L.BLACK_LIST
names_list = [ "explorer" ]

#type_list = TYPE_L.WHITE_LIST
#names_list = [ "nt", "hal", "kernel32", "ntdll", "atapi" ]

# To use all modules uncomment this line: 
#names_list = None

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

with open(sys.argv[1], 'r', errors='ignore') as inf:
    with open(sys.argv[2], 'w+') as outf:
        for line in inf.readlines():
            if "ERROR: " not in line and "WARNING:" not in line:
                line = re.sub(r'[^\x20-\x7e]','', line)
                line = " ".join(line.split())
                mod = line.split()[1].split("!")[0].lower()
                if check_if_log(mod):
                    outf.write("0x" + line + "\n")
            else:
                print("info: ", line)
    print("done!")
