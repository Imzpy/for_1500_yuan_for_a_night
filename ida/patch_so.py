import json

import idaapi

patch_info = json.loads(open("D:\desktop\ollvm_python\ida\patch_info.json").read())

for item in patch_info:
    print("patch " + hex(item["addr"]))
    idaapi.patch_bytes(item["addr"], bytes.fromhex(item["code"]))
