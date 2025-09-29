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

from patch_br.br_info import BrIfInfo, br_list_to_json, load_br_list
from patch_br.mico import find_reg_dep_inst
from patch_br.patch_so import PatchSo
from patch_br.tools import bytes_to_chunks, move_none_to_end, chunks_to_bytes

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
nop = ks.asm("nop", 0, True)[0]

so_path = r'D:\desktop\ollvm\360\ida\rep.so'
project = angr.Project(so_path, auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0xC8000}})

state = project.factory.entry_state()

text_start = 0xF3C8C
text_end = 0x1C597C


def find_br_dep_inst(block: angr.Block):
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


def find_so_br_inst():
    result = []
    current_addr = text_start
    block = project.factory.block(current_addr)
    while current_addr < text_end:
        # try:
        info = find_br_dep_inst(block)
        if info:
            result.append(info)
            if len(result) % 10 == 0:
                open("br_if.json", "w").write(br_list_to_json(result))
        if block.size == 0:
            current_addr += 4
        else:
            current_addr += block.size
        block = project.factory.block(current_addr)
        if current_addr % 10000 == 0:
            print("find_br_if", current_addr)
        # except Exception as e:
        #     print(e)
    open("br_if.json", "w").write(br_list_to_json(result))
    return result


def evl_if_br_value(state, value):
    def get_register_name(state, target_bvs):
        for reg_id, reg_name in state.arch.register_names.items():
            try:
                reg_value = getattr(state.regs, reg_name)
                if reg_value is target_bvs:
                    return reg_name
            except AttributeError:
                continue
        return None

    def get_value_or_reg_or_sym(state, value):
        if value.symbolic:
            reg = get_register_name(state, value)
            if reg:
                return reg
            return str(value)
        else:
            return state.solver.eval(value)

    def eval_no_sym_value(state, value):
        if not value.symbolic:
            return state.solver.eval(value)
        else:
            return None

    if value.op == "If":
        condition = value.args[0]
        true_value = eval_no_sym_value(state, value.args[1])
        false_value = eval_no_sym_value(state, value.args[2])
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


def evl_indirect_br_value(br: BrIfInfo):
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
    return evl_if_br_value(sim.active[0], reg_value)


def evl_direct_br_value(br: BrIfInfo):
    addr = br.br.address
    reg = cs.reg_name(br.jump_reg)
    # start = max(text_start, addr - 0x200)
    start = br.block_addr
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
            # print("---end---", hex(lastPc + 4))
            state = project.factory.blank_state(addr=lastPc + 4)
            sim = project.factory.simgr(state)
            sim.step(num_inst=1)
            lastPc += 4
            continue

        for active_state in sim.active[:]:
            pc = active_state.solver.eval(active_state.regs.pc)
            if pc < lastPc or pc > addr:
                # print("---end2---", hex(lastPc + 4))
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


def make_patch_info(br_if_list):
    success = []
    fail = []
    for item in br_if_list:
        r = evl_indirect_br_value(item)
        if not r:
            r = evl_direct_br_value(item)
        if r:
            item.true_value = r.get("true_value")
            item.false_value = r.get("false_value")
            item.value = r.get("value")
            success.append(item)
            if len(success) % 10 == 0:
                open("patch_success.json", "w").write(br_list_to_json(success))
        else:
            fail.append(item)

    open("patch_success.json", "w").write(br_list_to_json(success))
    open("patch_fail.json", "w").write(br_list_to_json(fail))
    return success, fail


def patch_cset_br(br):
    def find_all_inst(insts: [DisassemblerInsn], name):
        result = []
        for item in insts:
            if item.mnemonic == name:
                result.append(item)
        return result

    def only_has_one(insts: [DisassemblerInsn], name):
        return len(find_all_inst(insts, name)) == 1

    if not br.inst or len(br.inst) == 0:
        print("inst is empty", hex(br.block_addr))
        return None
    if not (only_has_one(br.inst, "cmp") or
            only_has_one(br.inst, "tst") or
            only_has_one(br.inst, "fcmp") or
            only_has_one(br.inst, "cmn")
    ):
        print("no cmp inst", hex(br.block_addr))
        return None
    if not only_has_one(br.inst, "cset"):
        print("no cset inst", hex(br.block_addr))
        return None

    cset = find_all_inst(br.inst, "cset")
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
    elif op == "le":
        b_if_inst = {
            "op": "b.le",
            "addr": br.true_value
        }
    elif op == "ge":
        b_if_inst = {
            "op": "b.ge",
            "addr": br.true_value
        }
    elif op == "mi":
        b_if_inst = {
            "op": "b.mi",
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
    patch = PatchSo(project, so_path)
    result = []
    for br in br_list:
        r = None
        if br.value:
            r = patch_br(br)
        elif br.true_value and br.false_value:
            r = patch_cset_br(br)
        if r:
            patch.patch(r["addr"], r["codes"])
            r["codes"] = r["codes"].hex()
            result.append(r)
    open("patch.json", "w").write(json.dumps(result))
    patch.save()
    return result


def test_single_br(addr):
    block = project.factory.block(addr)
    info = find_br_dep_inst(block)
    info = evl_indirect_br_value(info)
    print(info)


# br_list = load_br_if("br_if_patch.json")
# br_if_list = filter_br_if(br_list)
# br = judge_br_if(project.factory.block(0x109284))
# patch(make_pathc_info(br_list))
# patch(br_list)
# print(br_list_to_json(br_if_list))
# test_single_br(0xFEC34)

br_list = find_so_br_inst()
success, fail = make_patch_info(br_list)
patch(success)


# br_list = load_br_list(state, "./patch_success.json")
# patch(br_list)
