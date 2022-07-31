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
# -
# for inteli: set ENV VAR PYTHONPATH=C:\Program Files\IDA Pro 7.7\python\3

import ida_kernwin
import idaapi
import ida_name

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


filename = ida_kernwin.ask_file(True, "*.txt", "Select file with symbols info")


with open(filename, 'r', errors='ignore') as inf:
    cnt = inf.readlines()
    for line in cnt:
        base_addr, *name = line.split()
        base_addr = int(base_addr, 16)
        name = " ".join(name)
        idaapi.set_debug_name(base_addr, name)
        idaapi.set_name(
            base_addr,
            name,
            ida_name.SN_NOWARN | ida_name.SN_NOCHECK | ida_name.SN_PUBLIC)
    ida_kernwin.open_names_window(0)
