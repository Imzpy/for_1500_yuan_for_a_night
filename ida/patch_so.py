import json

import idc

import ida_name
import idaapi
from keystone import *

ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

patch_info = json.loads(open("D:\desktop\ollvm_python\ida\patch_info.json").read())

for item in patch_info:
    print("patch " + hex(item["addr"]))
    if item.get("sym"):
        target_ea = idc.get_name_ea_simple(item["sym"])
        if target_ea == idc.BADADDR or target_ea == idaapi.BADADDR:
            print("not find " + item["sym"])
            continue
        asm_inst = "bl " + hex(target_ea)
        code = ks.asm(asm_inst, item["addr"], True)[0]
        idaapi.patch_bytes(item["addr"], code)
    else:
        idaapi.patch_bytes(item["addr"], bytes.fromhex(item["code"]))
