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

# 参数名称,含义,填写建议（针对您的代码）,理由与说明
# Address of jump table,跳转表的起始地址（ea）。表包含连续元素，每个元素为目标地址或偏移。IDA 将此区域解析为数据，并生成 xref 到目标。,0x1F9A28 或标签 off_1F9A28,"代码中 ADRL X10, off_1F9A28 加载表基址。表从此处开始，包含 DCQ（8 字节）数据，如 0x00000FCC9C（指向 loc_FCC9C）。确保该地址已标记为数据。"
# Number of elements,表中的元素数量（n）。IDA 将解析前 n 个元素，并检查范围（out-of-bounds 视为 default）。,3（或实际扫描的元素数，如 4-8）,"表显示至少 3 个：0x1F9A28（loc_FCC9C）、0x1F9A30（loc_FCCDC）、0x1F9A38（loc_FCCA8）。输入索引为 0/8（步长 8 字节），对应索引 0 和 1；第三个可能为 default。运行脚本或手动检查表末尾以确认（e.g., 下一个非地址数据）。"
# Size of table element,每个表元素的字节大小（bytes per element）。常见为 4（DWORD）或 8（QWORD）。,8,"表使用 DCQ（double constant QWORD，8 字节）。LDR X9, [X10,X9] 加载 64 位地址，匹配 ARM64 的指针大小。"
# Element shift amount,"加载表元素后的左移位数（<< shift）。用于缩放偏移（e.g., 乘以元素大小）。如果无 LSL，则为 0。",0,"代码无显式 LSL 指令；AND X9, #8 已提供字节偏移（8 字节 = 1 个 QWORD），直接用于 LDR。如果表是字偏移，此处设 3（<<3 = *8）。"
# Element base value,"目标地址计算的基址（base）。如果表元素是绝对地址，为 0；如果是相对偏移，则为分支点附近地址（e.g., 跳转指令 ea）。",0,"表元素是绝对地址（e.g., 0x00000FCC9C 直接为 loc_FCC9C 的 ea），无需加基址。公式简化为 target = table[index]。"
# Start of the switch idiom,switch 结构的起始地址（idiom start ea）。通常是输入索引计算的第一个指令，帮助 IDA 追踪表达式。,0xFCC88 或 0xFCC40（函数起始）,"从 LDRSW X8, [X21,#0x18] 开始计算索引（EOR 和 AND 链）。置于 BR 前最近的计算指令（如 0xFCC88 的 LDRSW），以优化伪代码中的 switch 表达式追踪。"
# Input register of switch,switch 输入值的寄存器（reg）。这是索引源，常为计算后的 reg（如 X9）。,X9 或 r9（ARM64 64 位）,"代码中 BR X9，且 LDR X9, [X10,X9] 使用 X9 作为索引。IDA 支持 X9 或数字 9。这将伪代码中显示为 switch (expr >> ? & ?)。"
# First (lowest) input value,"表索引 0 对应的最低输入值（low）。用于调整 case 标签（e.g., case low + i）。默认 0。",0,输入从 AND #8 得 0 或 8，无偏移。case 对应输入 0（索引 0）和 8（索引 1）。如果 case 从 1 开始，此处设 1。
# Default jump address,默认分支地址（default ea）。范围外跳转目标，帮助 IDA 标记 fallback。,0xFCCA8 或标签 loc_FCCA8,表第三个元素 0x00000FCCA8 指向 loc_FCCA8，可能为 default（输入 >1 时 fallback）。代码无显式检查，但此可改善图表。

# 复选框选项,含义,推荐设置,理由与说明
# Separate value table is present,是否存在两级表：先查值表得索引，再查跳转表。公式：jump_table[value_table[input]]。,❌ 关闭,"您的代码是单级表（直接 LDR [X10, X9]），无值表（value table）。启用会误解析。"
# Signed jump table elements,表元素是否有符号（sign-extended），如使用 LDRSW/LDRSB 加载负偏移。,❌ 关闭,使用 LDR（无符号 64 位），元素为正绝对地址。启用会导致负 case 错误。
# Subtract table elements,从基址减元素（base - table[index]），而非加法。常见于某些 RISC 优化。,❌ 关闭,您的 LDR 后直接 BR，隐含加法（绝对地址）。无减法指令如 SUB。
# Table element is insn,表元素是指令偏移（insn delta），而非数据地址。常见于 PC-relative 跳转（如 ARM 的 B）。,❌ 关闭,元素是绝对数据地址（QWORD ea），非指令。启用会将表误为代码，破坏解析。


# 对话框字段,si 结构体成员,类型/说明,示例（您的代码）
# Address of jump table,si.jumps,ea_t（地址）：表起始 ea。,0x1F9A28
# Number of elements,si.ncases 或 si.cases,size_t（整数）：有效 case 数；cases 为数组大小。,3
# Size of table element,si.elsize,ushort（字节）：元素大小（1/2/4/8）。,8 (QWORD)
# Element shift amount,si.shift,char（位数）：左移量（0-7 典型）。,0
# Element base value,si.base 或 si.jtable_base,ea_t（地址）：计算基址（0 为绝对）。,0
# Start of the switch idiom,si.idiom_ea 或 si.start,ea_t（地址）：结构起始 ea（用于表达式追踪）。,0xFCC88
# Input register of switch,si.reg,"reg_t（寄存器 ID）：输入 reg（e.g., ARM 的 PR_X9 =9）。",9 (X9)
# First (lowest) input value,si.low 或 si.first_input,sword（有符号 int）：最低输入值偏移。,0
# Default jump address,si.def_jump,ea_t（地址）：默认目标 ea。,0xFCCA8


# Separate value table is present：si.flags & SWI_SEP_VALUE_TAB（位标志）。
# Signed jump table elements：si.flags & SWI_SIGNED_ELTS。
# Subtract table elements：si.flags & SWI_SUB_ELTS。
# Table element is insn：si.flags & SWI_INSN_ELTS。



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