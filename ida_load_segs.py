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
import idc

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


filename = ida_kernwin.ask_file(True, "*.txt", "Select file with segment info")

with open(filename, 'r', errors='ignore') as inf:
    cnt = inf.readlines()
    for line in cnt:
        base_addr, end_addr, segment_type, *name = line.split()
        base_addr = int(base_addr, 16)
        end_addr = int(end_addr, 16)
        segment_type = int(segment_type)
        name = " ".join(name)
        print(base_addr, end_addr, name)
        idc.AddSeg(
                base_addr,
                end_addr,
                0,
                segment_type,
                idc.saRelByte,
                idc.scPriv,
            )
        idc.set_segm_attr(base_addr, idc.SEGATTR_PERM, 7)
        idc.set_segm_name(base_addr, name)
    ida_kernwin.open_segments_window(0)
