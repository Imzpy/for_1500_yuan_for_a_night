# -*- coding: utf-8 -*-
"""
IDA Pro 9.0 IDAPython 脚本：自动识别并修复 ARM64 Switch
基于 ida_nalt API (get/set/del_switch_info)。
"""
# 参数名称,含义,类型/示例值（基于您的代码）,备注
# Indirect jump,间接跳转指令的地址。这是 switch 的入口点，通常是 BR reg（ARM64）或 JMP [reg]（x86）。,0xFCC98（BR X9 的地址）,必填。光标位置默认填充此值。
# Jump table,跳转表的起始地址。表包含固定数量的元素（每个元素为地址或偏移），用于索引计算目标。,0x1F9A28（off_1F9A28，包含 DCQ 如 loc_FCC9C）,必填。表大小由代码推断（如范围检查）。您的表有至少 3 个元素（0x9C CC 0F、DC CC 0F、A8 CC 0F）。
# Input register,用于索引表的寄存器（switch 的输入值）。在 ARM64 中，常为 Wn（32 位）或 Xn（64 位）。,"X9（从 AND X9, X9, #8 计算，实际索引为 0 或 8 的位掩码）",必填。用于反编译中标识 switch 表达式（如 switch (X9 & 8)）。
# Base,目标地址计算的基址。如果表项是绝对地址，可设为 0；如果是偏移，则为分支点附近地址。,0（您的表直接存储绝对地址，如 loc_FCC9C）,"可选，默认 0。示例：如果有 ADD target, base, offset，则 base 为 loc_FCCDC。"
# Shift,表元素加载后的左移位数（<< shift）。用于缩放（如乘以表元素大小，ARM64 常见 *4 或 *8）。,"0（您的 LDR X9, [X10,X9] 无显式 LSL）",可选，默认 0。示例：如果有 LSL #2，则 shift=2（*4）。
# First (lowest) input value,表索引 0 对应的输入值偏移。通常用于范围调整（如 case 从 1 开始，而索引从 0）。,0（您的 EOR 和 AND 后，可能为 0）,可选。用于 case 注释（如 case 1-8 而非 0-7）。
# Default jump address,默认分支地址（范围检查失败时跳转）。改善 listing 和反编译的整洁度。,loc_FCCA8（或代码中隐含的 fallback，如 B.HI）,可选。示例：您的代码中可能无显式 default，但可指定为表外分支。


import idaapi
import ida_nalt
import ida_bytes
import idc
import idautils

# 配置（自动检测或手动）
SWITCH_EA = 0xFCC98      # BR X9
TABLE_EA = 0x1F9A28      # 表基址
ENTRY_SIZE = 8           # ARM64 指针
NUM_CASES = 3            # case 数
LOW_CASE = 0
HIGH_CASE = 2
MARK_UNUSED = True       # 标记未用 case

def log(msg):
    print(f"[SwitchFix] {msg}")
    idc.Message(f"[SwitchFix] {msg}\n")

def ensure_table_defined():
    for i in range(NUM_CASES):
        ea = TABLE_EA + i * ENTRY_SIZE
        if ida_bytes.get_item_size(ea) != ENTRY_SIZE:
            ida_bytes.create_qword(ea, ENTRY_SIZE)  # 定义 dq
            log(f"Defined qword at 0x{ea:X}")

def get_cases():
    cases = []
    for i in range(NUM_CASES):
        ea = TABLE_EA + i * ENTRY_SIZE
        target = ida_bytes.get_qword(ea)
        cases.append((i, target))
        log(f"Case {i}: 0x{target:X}")
    return cases

def fix_switch():
    ensure_table_defined()
    cases = get_cases()

    # 构建 switch_info_t
    si = ida_nalt.switch_info_t()
    si.jumps = TABLE_EA          # 跳转表地址
    si.elbase = 0                # 基址偏移 (ARM64 通常 0)
    si.startea = SWITCH_EA       # switch 开始
    si.ncases = NUM_CASES        # case 数
    si.lowcase = LOW_CASE
    si.defjump = 0               # 默认 case (若无，0)
    si.flags = ida_nalt.SWI_J32 | ida_nalt.SWI_V32  # 32-bit 跳转/值 (调整为 ARM64)
    si.set_jsize(ENTRY_SIZE)     # 条目大小
    si.set_vsize(4)              # 值大小 (W 寄存器)

    # 设置 switch info (创建/更新)
    ida_nalt.set_switch_info(SWITCH_EA, si)
    log("Switch info set via set_switch_info")
    #    si = idaapi.switch_info_t()
    #             si.jumps = table_addr  # 跳转表地址
    #             si.ncases = 2  # case数量
    #             si.elbase = table_addr  # 表基址
    #             si.startea = cmp_ea  # switch起始
    #             si.defjump = 0  # 默认jump (需手动调整如果有)
    #             si.flags = idaapi.SWI_DEFAULT | idaapi.SWI_JMPINV  # 间接跳转
    #             si.lowcase = 0
    #             si.values = idaapi.uchar_vec_t([0, 1])  # 非连续values，如果适用
    #             si.set_jtable_element_size(8)  # 8字节项
    #             si.set_shift(3)  # 移位3
    #
    #             # 应用到BR指令
    #             idaapi.set_switch_info(br_ea, si)
    #             idaapi.create_switch_table(br_ea, si)
    #             idaapi.create_insn(br_ea)  # 刷新


    # 映射 case 并添加 XREF
    for case_val, target in cases:
        if target:
            idc.set_name(target, f"case_{case_val}", ida_nalt.SN_AUTO)
            idautils.add_cref(SWITCH_EA, target, ida_nalt.fl_JN)
            log(f"Mapped case_{case_val} at 0x{target:X}")

    # 标记未用 (检查 XREF)
    if MARK_UNUSED:
        for case_val, target in cases:
            if len(list(idautils.XrefsTo(target))) <= 1:  # <=1 表示未用
                idc.set_cmt(target, "; UNUSED CASE", 0)
                log(f"Marked case {case_val} as unused")

    # 刷新
    idaapi.auto_wait()
    idc.refresh_idaview_anyway()

    # 验证
    out_si = ida_nalt.switch_info_t()
    if ida_nalt.get_switch_info(out_si, SWITCH_EA) > 0:
        log("Switch verified successfully")
    else:
        log("Warning: Switch info not retrieved")











def main():
    log("Starting ARM64 Switch Fix...")
    fix_switch()
    log("Completed. Check Pseudocode (F5) for switch.")

if __name__ == "__main__":
    main()