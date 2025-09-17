import ida_segment

import ida_search
import idautils
import idc
import idaapi


def patch_to_nop(addr, count):
    nop = b"\x1F\x20\x03\xD5"
    for i in range(0, count):
        idaapi.patch_bytes(addr + i * 4, nop)


def get_asm(addr):
    asm = idc.GetDisasm(addr)
    if asm == "":
        return ""
    return asm[:asm.find(" ")]


def find_large_not_code():
    text_seg = ida_segment.get_segm_by_name(".text")
    start_address = text_seg.start_ea
    end_address = text_seg.end_ea
    cur_addr = start_address
    notCodeList = []
    while cur_addr < end_address:
        # code = idc.GetDisasm(cur_addr)
        isCode = idc.is_unknown(idc.get_full_flags(cur_addr))
        if not isCode:
            notCodeList.append(cur_addr)
            patch_to_nop(cur_addr, 1)
        cur_addr += 4
    return notCodeList


find_large_not_code()
