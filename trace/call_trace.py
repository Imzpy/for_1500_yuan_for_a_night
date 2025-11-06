import idaapi
import idc


def get_function_symbol_at_offset(offset):
    if not idc.is_mapped(offset):
        return None
    func = idaapi.get_func(offset)
    if not func:
        return None
    func_name = idc.get_func_name(offset)
    if not func_name:
        return None
    demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled_name if demangled_name else func_name


def is_in_plt(address):
    seg = idaapi.getseg(address)
    if not seg:
        return False
    seg_name = idc.get_segm_name(seg.start_ea)
    return seg_name in [".plt", ".plt.got"]


class CallInfo:
    def __init__(self):
        self.type = None
        self.depth = None
        self.fromModuleName = None
        self.fromSymbolName = None
        self.toModuleName = None
        self.toSymbolName = None
        self.fromOffset = None
        self.toOffset = None
        self.fromAddr = None
        self.toAddr = None
        self.jumpOut = None
        self.fromIdaSymbolName = None
        self.toIdaSymbolName = None
        self.isPlt = False
        self.ret = None
        self.call = None


def load_trace(path):
    result = []
    data = open(path).read()
    lines = data.split("\n")
    for line in lines:
        if not line.startswith("call") and not line.startswith("ret"):
            continue
        info = CallInfo()
        sp = line.split(":")
        if sp[0] == "call":
            info.type = "call"
            info.jumpOut = sp[1]
            info.depth = int(sp[3])
            info.fromModuleName = sp[4]
            info.fromSymbolName = sp[5]
            info.fromAddr = int(sp[6], 16)
            info.fromOffset = int(sp[7], 16)
            info.toModuleName = sp[8]
            info.toSymbolName = sp[9]
            info.toAddr = int(sp[10], 16)
            info.toOffset = int(sp[11], 16)
        else:
            info.type = "ret"
            info.depth = int(sp[1])
            info.fromModuleName = sp[2]
            info.fromSymbolName = sp[3]
            info.fromAddr = int(sp[4], 16)
            info.fromOffset = int(sp[5], 16)
            info.toModuleName = sp[6]
            info.toSymbolName = sp[7]
            info.toAddr = int(sp[8], 16)
            info.toOffset = int(sp[9], 16)
        result.append(info)
    return result


def make_call_trace(path):
    data = load_trace(path)
    for item in data:
        if item.type == "call":
            item.fromIdaSymbolName = get_function_symbol_at_offset(item.fromOffset)
            item.toIdaSymbolName = get_function_symbol_at_offset(item.toOffset)
            item.isPlt = is_in_plt(item.toAddr)

    call_stack = []
    for item in data:
        if item.type == "call":
            call_stack.append(item)
        else:
            lastAddr = item.toAddr - 4
            find = False
            for i in range(len(call_stack) - 1, 0, -1):
                stack = call_stack[i]
                if stack.fromAddr == lastAddr:
                    stack.ret = item
                    item.call = stack
                    call_stack.remove(stack)
                    find = True
                    break
            if not find:
                # print("not find call for ret: ", hex(item.fromOffset))
                pass

    curDepth = 0
    for i in range(0, len(data)):
        item = data[i]
        if item.type == "call":
            if item.fromOffset == 0x14904:
                pass
            item.depth = curDepth
            if item.ret is not None:
                curDepth += 1
        else:
            if item.call is not None:
                curDepth -= 1
            if curDepth < 0:
                pass
    result = ""
    for item in data:
        indent = "\t" * item.depth
        if item.type == "call":
            funcName = item.toSymbolName
            if not funcName:
                funcName = item.toIdaSymbolName
            if not funcName:
                funcName = ""
            line = indent + funcName + "[" + hex(item.toOffset) + "][" + hex(item.fromOffset) + "]"
            result += line + "\n"
            print(line)
    open(path + "/../call_trace.txt", "w").write(result)


make_call_trace(r"D:\desktop\tmp\trace_call_19697_1496087063")
# make_call_trace(r"D:\desktop\ollvm\360\log\trace2\trace_call_18837_1724929177")
# make_call_trace(r"F:\desktop\360\log\trace_12254_1278053216")
