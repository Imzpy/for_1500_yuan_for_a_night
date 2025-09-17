import json
import logging
import os
import angr
import capstone.arm64
import claripy
from angr.block import CapstoneInsn, DisassemblerInsn
from capstone import *
from keystone import *
import pyvex
import archinfo

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
so_path = r'D:\desktop\ollvm\360\ida\rep.so'
project = angr.Project(so_path, auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0xC8000}})

state = project.factory.entry_state()

text_start = 0xF3C8C
# text_start = 1241000
text_end = 0x1C597C


class BrIfInfo:
    def __init__(self):
        self.br: DisassemblerInsn = None
        self.inst: list[DisassemblerInsn] = []
        self.jump_reg = None
        self.block_addr = None
        self.true_value = None
        self.false_value = None
        self.value = None


class BrIfInfoEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BrIfInfo):
            def serialize_instruction(inst):
                if inst is None:
                    return None
                return {
                    "address": inst.address,
                    "mnemonic": inst.mnemonic,
                    "op_str": inst.op_str,
                }

            inst = []
            for item in obj.inst:
                inst.append(serialize_instruction(item))
            return {
                "inst": inst,
                "br": serialize_instruction(obj.br),
                "jump_reg": obj.jump_reg,
                "block_addr": obj.block_addr,
                "true_value": obj.true_value,
                "false_value": obj.false_value,
                "value": obj.value,
            }


def load_br_if(path):
    def json2BrIfInfo(item):
        def json2inst(inst_json):
            if not inst_json:
                return None
            code = state.memory.load(inst_json["address"], 4)
            code_bytes = state.solver.eval(code, cast_to=bytes)
            for inst in cs.disasm(code_bytes, inst_json["address"]):
                return inst
            return None

        result = BrIfInfo()
        result.br = json2inst(item["br"])
        result.jump_reg = item["jump_reg"]
        result.block_addr = item["block_addr"]
        result.true_value = item.get("true_value")
        result.false_value = item.get("false_value")
        result.value = item.get("value")
        result.inst = []
        for item in item["inst"]:
            result.inst.append(json2inst(item))
        return result

    result = []
    data = json.loads(open(path, "r").read())
    for item in data:
        result.append(json2BrIfInfo(item))
    return result


def find_reg_dep_inst(irsb, target_reg):
    def get_add_mapping(statements):
        result = {}
        last_addr = None
        for idx in range(len(statements)):
            stmt = statements[idx]
            if isinstance(stmt, pyvex.IRStmt.IMark):
                last_addr = stmt.addr
            else:
                result[idx] = last_addr
        return result

    def get_tmp_offset_key(offset):
        return f"tmp_{offset}"

    def get_reg_offset_key(offset):
        return f"reg_{offset}"

    def make_interested_value(datas):
        result = {}
        if not isinstance(datas, list) and not isinstance(datas, tuple):
            datas = [datas]
        for data in datas:
            if isinstance(data, pyvex.expr.RdTmp):
                result[get_tmp_offset_key(data.tmp)] = {
                    "type": "tmp",
                    "value": data.tmp,
                }
            elif isinstance(data, pyvex.expr.Unop):
                result.update(make_interested_value(data.args))
            elif isinstance(data, pyvex.expr.Load):
                print("waring read mem")
                result.update(make_interested_value(data.addr))
            elif isinstance(data, pyvex.expr.Binop):
                result.update(make_interested_value(data.args))
            elif isinstance(data, pyvex.expr.CCall):
                result.update(make_interested_value(data.args))
            elif isinstance(data, pyvex.expr.ITE):
                result.update(make_interested_value(data.child_expressions))
                result.update(make_interested_value(data.cond))
            elif isinstance(data, pyvex.expr.Get):
                result[get_reg_offset_key(data.offset)] = {
                    "type": "reg",
                    "value": data.offset,
                }
            elif isinstance(data, pyvex.expr.Const):
                pass
            else:
                print("unknow put.data op", data)
        return result

    target_reg_offset = archinfo.ArchAArch64().get_register_offset(target_reg)
    statements = list(reversed(irsb.statements))
    dependencies_idx = []
    interested_value = {}
    interested_value[get_reg_offset_key(target_reg_offset)] = {
        "type": "reg",
        "value": target_reg_offset,
    }

    for idx in range(len(statements)):
        stmt = statements[idx]

        find_key = None
        find_value = None

        if isinstance(stmt, pyvex.IRStmt.IMark):
            continue
        elif isinstance(stmt, pyvex.IRStmt.Put):
            if get_reg_offset_key(stmt.offset) in interested_value.keys():
                find_key = get_reg_offset_key(stmt.offset)
                find_value = make_interested_value(stmt.data)
        elif isinstance(stmt, pyvex.IRStmt.WrTmp):
            if get_tmp_offset_key(stmt.tmp) in interested_value.keys():
                find_key = get_tmp_offset_key(stmt.tmp)
                find_value = make_interested_value(stmt.data)
        elif isinstance(stmt, pyvex.IRStmt.Store):
            if hasattr(stmt.data, "tmp") and get_tmp_offset_key(stmt.data.tmp) in interested_value.keys():
                find_key = get_tmp_offset_key(stmt.data.tmp)
                find_value = make_interested_value(stmt.data)
        else:
            print("unknow vex op ", stmt)

        if find_key:
            interested_value.update(find_value)
            del interested_value[find_key]
            dependencies_idx.append(idx)

    count = len(irsb.statements)
    addr_mapping = get_add_mapping(irsb.statements)
    dependencies_addr = set()
    for item in dependencies_idx:
        dependencies_addr.add(addr_mapping[count - item - 1])

    dependencies_addr = list(dependencies_addr)
    dependencies_addr.sort()
    return dependencies_addr


def find_br(block: angr.Block):
    br = BrIfInfo()
    br.block_addr = block.addr
    for inst in reversed(block.capstone.insns):
        if inst and hasattr(inst, "mnemonic"):
            if inst.mnemonic == "br":
                if br.br:
                    print("error br")
                br.br = inst
                br.jump_reg = inst.operands[0].value.reg

    if br.br and br.br.operands[0].type == CS_OP_REG:
        code_bytes = project.loader.memory.load(block.addr, block.size)
        irsb = pyvex.lift(code_bytes, block.addr, archinfo.ArchAArch64(), opt_level=0)
        dep_inst_addr = find_reg_dep_inst(irsb, cs.reg_name(br.jump_reg))
        for inst in block.capstone.insns:
            if inst.address in dep_inst_addr:
                br.inst.append(inst)
        br.inst.append(br.br)
        return br
    return None


def find_br_if():
    result = []
    current_addr = text_start
    block = project.factory.block(current_addr)
    while current_addr < text_end:
        # try:
        info = find_br(block)
        if info:
            result.append(info)
            if len(result) % 10 == 0:
                open("br_if.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
        if block.size == 0:
            current_addr += 4
        else:
            current_addr += block.size
        block = project.factory.block(current_addr)
        if current_addr % 10000 == 0:
            print("find_br_if", current_addr)
        # except Exception as e:
        #     print(e)
    open("br_if.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
    return result


def get_register_name(state, target_bvs):
    for reg_id, reg_name in state.arch.register_names.items():
        try:
            reg_value = getattr(state.regs, reg_name)
            if reg_value is target_bvs:
                return reg_name
        except AttributeError:
            continue
    return None


def find_args_reg(args):
    result = []
    for item in args:
        name = get_register_name(state, item)
        if name:
            result.append(item)
    return result


def get_value_or_reg_or_sym(state, value):
    if value.symbolic:
        reg = get_register_name(state, value)
        if reg:
            return reg
        return str(value)
    else:
        return state.solver.eval(value)


def eval_value(state, value):
    if not value.symbolic:
        return state.solver.eval(value)
    else:
        return None


def ast2value(state, value):
    if value.op == "If":
        condition = value.args[0]
        true_value = eval_value(state, value.args[1])
        false_value = eval_value(state, value.args[2])
        if not true_value or not false_value:
            return None
        print(f"reg is if")
        return {
            "cond_op": condition.op,
            "cond_l": get_value_or_reg_or_sym(state, claripy.simplify(condition.args[0])),
            "cond_r": get_value_or_reg_or_sym(state, claripy.simplify(condition.args[1])),
            "true_value": true_value,
            "false_value": false_value,
        }
    elif not value.symbolic:
        print(f"reg is value")
        return {
            "value": state.solver.eval(value)
        }
    else:
        print("unknown reg " + value.op, state.regs.pc)
        return None


def disasm(state, pc):
    code = state.memory.load(pc, 4)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    for item in cs.disasm(code_bytes, pc):
        return item
    return None


def evl_br_fast(br: BrIfInfo):
    block: angr.Block = project.factory.block(br.block_addr)
    state = project.factory.blank_state(addr=block.addr)
    state.options.add(angr.options.CALLLESS)
    sim = project.factory.simgr(state)
    pc = block.addr
    while pc < block.addr + block.size - 4:
        # print(disasm(state, pc).mnemonic)
        sim.step(num_inst=1)
        pc += 4
        for active_state in sim.active[:]:
            active_state.regs.pc = pc
    if len(sim.active) != 1:
        print("active_state len ", len(sim.active), hex(block.addr))
        return None
    reg = cs.reg_name(br.jump_reg)
    reg_value = sim.active[0].regs.get(reg)
    return ast2value(sim.active[0], reg_value)


def evl_br(br: BrIfInfo):
    addr = br.br.address
    reg = cs.reg_name(br.jump_reg)
    start = max(text_start, addr - 0x200)
    if start < text_start:
        start = text_start
    state = project.factory.blank_state(addr=start)
    state.options.add(angr.options.CALLLESS)  # Avoid external calls
    sim = project.factory.simgr(state)
    lastPc = start
    # Step until target address, limit path explosion
    while lastPc <= addr:
        sim.step(num_inst=1)
        if not len(sim.active) == 1:
            print("---end---", hex(lastPc + 4))
            state = project.factory.blank_state(addr=lastPc + 4)
            sim = project.factory.simgr(state)
            sim.step(num_inst=1)
            lastPc += 4
            continue

        for active_state in sim.active[:]:
            pc = active_state.solver.eval(active_state.regs.pc)
            if pc < lastPc or pc > addr:
                print("---end2---", hex(lastPc + 4))
                state = project.factory.blank_state(addr=lastPc + 4)
                sim = project.factory.simgr(state)
                sim.step(num_inst=1)
                lastPc += 4
                break
            if lastPc == pc:
                active_state.regs.pc += 4
                break
            lastPc = pc
            if pc == addr:
                try:
                    reg_value = active_state.regs.get(reg)
                    if active_state.solver.symbolic(reg_value):
                        print(f"reg {reg} is sym")
                        return None
                    concrete_value = active_state.solver.eval(reg_value, cast_to=int)
                    print(f"reg {reg} is 0x{concrete_value:x}")
                    return {
                        "value": concrete_value
                    }
                except Exception as e:
                    print(f"error: {e}")
                    return None

    print(f"not find 0x{addr:x}")
    return None


def make_pathc_info(br_if_list):
    result = []
    for item in br_if_list:
        r = evl_br_fast(item)
        if not r:
            r = evl_br(item)
        if r:
            item.true_value = r.get("true_value")
            item.false_value = r.get("false_value")
            item.value = r.get("value")
            result.append(item)
            if len(result) % 10 == 0:
                open("br_if_patch.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
    open("br_if_patch.json", "w").write(json.dumps(result, cls=BrIfInfoEncoder))
    return result


def bytes_to_chunks(data: bytes) -> list[bytes]:
    return [data[i:i + 4] for i in range(0, len(data), 4)]


def chunks_to_bytes(chunks: list[bytes]) -> bytes:
    return b''.join(chunks)


def move_none_to_end(arr: list) -> list:
    result = arr.copy()
    non_none_pos = 0
    for i in range(len(result)):
        if result[i] is not None:
            result[non_none_pos], result[i] = result[i], result[non_none_pos]
            non_none_pos += 1
    return result


class PatchSo:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.binary_bytes = f.read()
        self.binary_bytes = bytearray(self.binary_bytes)

    def patch(self, addr, data: bytes):
        addr = project.loader.main_object.addr_to_offset(addr)
        self.binary_bytes[addr:addr + len(data)] = data

    def save(self):
        with open(self.path + "_patch.so", 'wb') as f:
            f.write(self.binary_bytes)


def patch_br_if(br):
    def has_one_inst(insts: [DisassemblerInsn], name):
        result = []
        for item in insts:
            if item.mnemonic == name:
                result.append(item)
        return result

    if not br.inst or len(br.inst) == 0:
        return None
    if br.inst[0].mnemonic != "cmp":
        return None
    cset = has_one_inst(br.inst, "cset")
    if not cset:
        return None

    sp = cset[0].op_str.split(",")
    op = sp[1].strip()

    b_inst = None
    b_if_inst = None
    if op == "lt":
        b_if_inst = {
            "op": "b.lt",
            "addr": br.true_value
        }
    elif op == "ne":
        b_if_inst = {
            "op": "b.ne",
            "addr": br.true_value
        }
    elif op == "eq":
        b_if_inst = {
            "op": "b.eq",
            "addr": br.true_value
        }
    elif op == "hi":
        b_if_inst = {
            "op": "b.hi",
            "addr": br.true_value
        }
    elif op == "lo":
        b_if_inst = {
            "op": "b.lo",
            "addr": br.true_value
        }
    elif op == "gt":
        b_if_inst = {
            "op": "b.gt",
            "addr": br.true_value
        }
    else:
        print("unknown op ", op, hex(br.block_addr))
        return
    b_inst = {
        "op": "b",
        "addr": br.false_value
    }

    start_addr = br.inst[0].address
    size = br.br.address - start_addr + 4
    code = state.memory.load(start_addr, size)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    codes = bytes_to_chunks(code_bytes)
    nop_idx = []
    for ni in br.inst:
        nop_idx.append(int((ni.address - start_addr) / 4))

    nop = ks.asm("nop", 0, True)[0]
    for idx in nop_idx:
        codes[idx] = None

    codes = move_none_to_end(codes)
    for idx in range(0, len(codes)):
        if codes[idx] is None:
            codes[idx] = nop

    b_if_addr = start_addr + size - 8
    b_addr = start_addr + size - 4
    codes[len(codes) - 2] = ks.asm(b_if_inst["op"] + " " + str(b_if_inst["addr"]), b_if_addr, True)[0]
    codes[len(codes) - 1] = ks.asm("b " + str(b_inst["addr"]), b_addr, True)[0]
    codes = chunks_to_bytes(codes)
    return {
        "addr": start_addr,
        "codes": codes
    }


def patch_br(br):
    codes = ks.asm("b " + str(br.value), br.br.address, True)[0]
    return {
        "addr": br.br.address,
        "codes": codes
    }


def patch(br_list):
    patch = PatchSo(so_path)
    result = []
    for br in br_list:
        r = None
        if br.value:
            r = patch_br(br)
        elif br.true_value and br.false_value:
            r = patch_br_if(br)
        if r:
            patch.patch(r["addr"], r["codes"])
            r["codes"] = r["codes"].hex()
            result.append(r)
    open("patch.json", "w").write(json.dumps(result))
    patch.save()
    return result


br_list = find_br_if()
# br_list = load_br_if("br_if_patch.json")
# br_if_list = filter_br_if(br_list)
# br = judge_br_if(project.factory.block(0x109284))
patch(make_pathc_info(br_list))
# patch(br_list)
# print(json.dumps(br_if_list, cls=BrIfInfoEncoder))
