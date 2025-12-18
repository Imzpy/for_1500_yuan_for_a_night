import ida_funcs
import idautils


def undefine_and_redefine_function(start, end):
    # 步骤1: 找到并删除范围[start, end)内的所有函数
    for func_start in idautils.Functions(start, end):
        if ida_funcs.del_func(func_start):
            print(f"Deleted function at {hex(func_start)}")
        else:
            print(f"Failed to delete function at {hex(func_start)}")

    # 步骤2: 添加新函数从start到end (end为exclusive)
    if ida_funcs.add_func(start, end):
        print(f"Successfully added new function from {hex(start)} to {hex(end)}")
    else:
        print(f"Failed to add new function from {hex(start)} to {hex(end)}")

# 示例调用: 替换为实际地址
undefine_and_redefine_function(0x14f394, 0x1503e8)