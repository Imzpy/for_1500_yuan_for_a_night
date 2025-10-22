import idautils
import idaapi
import idc
import ida_hexrays as hr  # 用于反编译


def get_callers(ea, depth=3, current_depth=0, visited=None):
    if visited is None:
        visited = set()
    if current_depth >= depth:
        return set()
    callers = set()
    for ref in idautils.CodeRefsTo(ea, 1):  # 只取代码引用
        func = idaapi.get_func(ref)
        if func and func.start_ea not in visited:
            visited.add(func.start_ea)
            callers.add(func.start_ea)
            callers.update(get_callers(func.start_ea, depth, current_depth + 1, visited))
    return callers


def get_callees(ea, depth=3, current_depth=0, visited=None):
    if visited is None:
        visited = set()
    if current_depth >= depth:
        return set()
    callees = set()
    for head in idautils.FuncItems(ea):
        for ref in idautils.CodeRefsFrom(head, 0):  # 不跳过跳转
            func = idaapi.get_func(ref)
            if func and func.start_ea not in visited:
                visited.add(func.start_ea)
                callees.add(func.start_ea)
                callees.update(get_callees(func.start_ea, depth, current_depth + 1, visited))
    return callees


def get_pseudocode(ea):
    if not hr.init_hexrays_plugin():
        return "Hex-Rays Decompiler not available."
    try:
        cfunc = hr.decompile(ea)
        if cfunc:
            return str(cfunc)  # 获取伪代码字符串
        else:
            return "Failed to decompile function."
    except Exception as e:
        return f"Error decompiling: {str(e)}"


def export_call_chain_with_pseudo(target_ea, output_file, depth=3):
    related_eas = set()
    related_eas.add(target_ea)  # 包括自身
    related_eas.update(get_callers(target_ea, depth))
    related_eas.update(get_callees(target_ea, depth))

    # 转换为函数名和地址映射
    func_info = {}
    for ea in related_eas:
        name = idaapi.get_func_name(ea)
        if name:
            func_info[ea] = name

    # 导出到文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Call Chain for {target_ea} (Depth: {depth})\n")
        # f.write("\nCallers:\n")
        # callers = get_callers(target_ea, depth)
        # for ea in sorted(callers):
        #     f.write(f"- {func_info.get(ea, hex(ea))}\n")
        #
        # f.write("\nCallees:\n")
        # callees = get_callees(target_ea, depth)
        # for ea in sorted(callees):
        #     f.write(f"- {func_info.get(ea, hex(ea))}\n")

        f.write("\nPseudocode for Related Functions:\n")
        for ea in sorted(related_eas):
            name = func_info.get(ea, hex(ea))
            pseudo = get_pseudocode(ea)
            f.write(f"\n// Pseudocode for {name} at {hex(ea)}\n")
            f.write(pseudo + "\n" + "-" * 80 + "\n")

    print(f"Exported to {output_file}")


# 使用示例：替换为你的函数名、输出路径和深度
export_call_chain_with_pseudo(0x1013C8, "D:/desktop/ollvm_python/ext_func.cpp", depth=5)
