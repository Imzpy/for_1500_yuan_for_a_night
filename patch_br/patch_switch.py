import idaapi
import idc
import idautils


def find_and_apply_switch():
    # 获取当前屏幕地址或函数起始
    ea = idc.here()
    func = idaapi.get_func(ea)
    if not func:
        print("No function at current address.")
        return

    # 扫描函数指令
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.print_insn_mnem(head) == 'CMP' and idc.get_operand_type(head, 1) == idc.o_imm:
            cmp_ea = head
            # 检查下一个: ADRP
            next_ea = idc.next_head(cmp_ea)
            if idc.print_insn_mnem(next_ea) != 'ADRP':
                continue
            adrp_ea = next_ea
            # CSET EQ
            next_ea = idc.next_head(adrp_ea)
            if idc.print_insn_mnem(next_ea) != 'CSET' or 'EQ' not in idc.print_insn_mnem(next_ea):
                continue
            cset_ea = next_ea
            # ADD
            next_ea = idc.next_head(cset_ea)
            if idc.print_insn_mnem(next_ea) != 'ADD':
                continue
            add_ea = next_ea
            # LDR with UXTW#3
            next_ea = idc.next_head(add_ea)
            if idc.print_insn_mnem(next_ea) != 'LDR' or 'UXTW#3' not in idc.GetDisasm(next_ea):
                continue
            ldr_ea = next_ea
            # 跳过MOV (可选)
            next_ea = idc.next_head(ldr_ea)
            if idc.print_insn_mnem(next_ea) == 'MOV':
                next_ea = idc.next_head(next_ea)
            # BR
            if idc.print_insn_mnem(next_ea) != 'BR':
                continue
            br_ea = next_ea

            print(f"Found potential switch at {hex(cmp_ea)}")

            # 计算参数
            switch_var_reg = idc.print_operand(cmp_ea, 0)  # e.g., 'X28'
            index_reg = idc.print_operand(cset_ea, 0)  # e.g., 'W8'
            table_base = idc.get_operand_value(adrp_ea, 1)  # ADRP imm
            table_off = idc.get_operand_value(add_ea, 2)  # ADD imm
            table_addr = table_base + table_off

            # 创建switch_info结构 (IDA 7.6兼容)
            si = idaapi.switch_info_t()
            si.jumps = table_addr  # 跳转表地址
            si.ncases = 2  # case数量
            si.elbase = table_addr  # 表基址
            si.startea = cmp_ea  # switch起始
            si.defjump = 0  # 默认jump (需手动调整如果有)
            si.flags = idaapi.SWI_DEFAULT | idaapi.SWI_JMPINV  # 间接跳转
            si.lowcase = 0
            si.values = idaapi.uchar_vec_t([0, 1])  # 非连续values，如果适用
            si.set_jtable_element_size(8)  # 8字节项
            si.set_shift(3)  # 移位3

            # 应用到BR指令
            idaapi.set_switch_info(br_ea, si)
            idaapi.create_switch_table(br_ea, si)
            idaapi.create_insn(br_ea)  # 刷新
            print(f"Applied switch at {hex(br_ea)}")
            return


find_and_apply_switch()
