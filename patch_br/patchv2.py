import json
import logging
import os
import angr
import capstone.arm64
import claripy
from angr.block import CapstoneInsn, DisassemblerInsn
from capstone import *
from capstone.arm64_const import *
from keystone import *
import pyvex
import archinfo

from patch_br.br_info import BrIfInfo, br_list_to_json, load_br_list, serialize_instruction_list
from patch_br.mico import find_reg_dep_inst
from patch_br.patch_so import PatchSo
from patch_br.tools import bytes_to_chunks, move_none_to_end, chunks_to_bytes, disasm

cs = capstone.Cs(CS_ARCH_ARM64, CS_MODE_ARM)
ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
nop = ks.asm("nop", 0, True)[0]

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)

so_path = r'D:\desktop\保活\1215\2.so'

project = angr.Project(so_path, auto_load_libs=False,
                       load_options={'main_opts': {'base_addr': 0}})
text_section = project.loader.main_object.sections_map['.text']
text_start = text_section.vaddr
text_end = text_section.vaddr + text_section.filesize
print("text_start", text_start)
print("text_end", text_end)

state = project.factory.entry_state()

symbols = {}

for item in project.loader.extern_object.symbols:
    symbols[item.rebased_addr] = item.name


def angr_get_reg_idx_by_name(name):
    return state.arch.registers[name][0]


# 14F394
def guess_func_start(start):
    def guess(block):
        has_SUB_SP_SP = False
        has_STP_X29_X30 = False

        for inst in block.capstone.insns:
            if inst and hasattr(inst, "mnemonic"):
                if inst.mnemonic == "sub" and \
                        inst.operands[0].value.reg == ARM64_REG_SP and \
                        inst.operands[1].value.reg == ARM64_REG_SP:
                    has_SUB_SP_SP = True
                if inst.mnemonic == "stp" and \
                        ((inst.operands[0].value.reg == ARM64_REG_X29 and
                          inst.operands[1].value.reg == ARM64_REG_X30) or
                         (inst.operands[0].value.reg == ARM64_REG_X30 and
                          inst.operands[1].value.reg == ARM64_REG_X29)):
                    has_STP_X29_X30 = True
                if has_SUB_SP_SP and has_STP_X29_X30:
                    return True
        return False

    while start <= text_end:
        block = project.factory.block(start)

        if guess(block):
            return start

        if block.size == 0:
            start += 4
        else:
            start += block.size

    return None


def guess_func_end(start):
    def guess(block):
        has_ADD_SP_SP = False
        has_LDP_X29_X30 = False
        has_RET = False

        for inst in block.capstone.insns:
            if inst and hasattr(inst, "mnemonic"):
                if inst.mnemonic == "ret":
                    has_RET = True
                if inst.mnemonic == "add" and \
                        inst.operands[0].value.reg == ARM64_REG_SP and \
                        inst.operands[1].value.reg == ARM64_REG_SP:
                    has_ADD_SP_SP = True
                if inst.mnemonic == "ldp" and \
                        ((inst.operands[0].value.reg == ARM64_REG_X29 and
                          inst.operands[1].value.reg == ARM64_REG_X30) or
                         (inst.operands[0].value.reg == ARM64_REG_X30 and
                          inst.operands[1].value.reg == ARM64_REG_X29)):
                    has_LDP_X29_X30 = True
                if has_ADD_SP_SP and has_LDP_X29_X30 and has_RET:
                    return True
        return False

    while start <= text_end:
        block = project.factory.block(start)

        if guess(block):
            return start + block.size - 4

        if block.size == 0:
            start += 4
        else:
            start += block.size

    return None


def guess_func_range(start):
    func_start = guess_func_start(start)
    if func_start == None:
        return None
    func_end = guess_func_end(func_start + 4)
    if func_end == None:
        return None
    return [func_start, func_end]


def get_all_block(start, end):
    blocks = {}
    while start <= end:
        block = project.factory.block(start)
        blocks[start] = {
            "block": block,
        }
        if block.size == 0:
            start += 4
        else:
            start += block.size
    return blocks


def find_br_dep_inst(block: angr.Block):
    depend = []
    lastInst = block.capstone.insns[len(block.capstone.insns) - 1]
    code_bytes = project.loader.memory.load(block.addr, block.size)
    irsb = pyvex.lift(code_bytes, block.addr, archinfo.ArchAArch64(), opt_level=0)
    dep_inst_addr = find_reg_dep_inst(irsb, cs.reg_name(lastInst.operands[0].value.reg))
    for inst in block.capstone.insns:
        if inst.address in dep_inst_addr:
            depend.append(inst)
    depend.append(lastInst)
    return depend


def run_block(block: angr.Block, state, start_addr=None, stop_addr=None):
    sim = project.factory.simgr(state)
    if start_addr:
        pc = start_addr
    else:
        pc = block.addr
    sim.active[0].regs.pc = pc
    while pc < block.addr + block.size - 4:
        # print(disasm(state, pc).mnemonic)
        if stop_addr is not None and pc == stop_addr:
            break
        sim.step(num_inst=1)
        pc += 4
        for active_state in sim.active[:]:
            active_state.regs.pc = pc
    if len(sim.active) != 1:
        print("sim.active ", len(sim.active))
    return sim.active[0]


def solve_symbolic(block: angr.Block, state):
    successors = project.factory.successors(state, opt_level=1)  # 计算后继
    next_list = []
    for succ in successors.flat_successors + successors.unsat_successors:
        if succ.solver.satisfiable():
            addr = succ.addr
            if hasattr(addr, "symbolic"):
                try:
                    possible_addrs = succ.solver.any_n(addr, 10)
                    for p in possible_addrs:
                        constrained_state = succ.copy()
                        constrained_state.add_constraints(addr == p)
                        next_list.append((p, constrained_state))
                except claripy.errors.ClaripySolverError:
                    continue  # 无法解决，跳过
            else:
                next_list.append((succ.addr, succ))
    return next_list


def visit_block(block, state, on_fix_br, on_complex_br):
    new_state = run_block(block, state.copy())

    inst = block.capstone.insns[len(block.capstone.insns) - 1]
    if inst.mnemonic == "b":
        return [(inst.operands[0].value.imm, new_state)]

    elif inst.mnemonic == "bl":
        return [(block.addr + block.size, new_state)]

    elif inst.mnemonic == "blr":
        if inst.operands[0].type == CS_OP_REG:
            value = new_state.regs.get(cs.reg_name(inst.operands[0].value.reg))
            if value.symbolic:
                on_complex_br(state, new_state, block)
                return solve_symbolic(block, new_state)
            else:
                on_fix_br(inst, value.v)
                return [(block.addr + block.size, new_state)]
        print("wtf3")

    elif inst.mnemonic == "br":
        if inst.operands[0].type == CS_OP_REG:
            value = new_state.regs.get(cs.reg_name(inst.operands[0].value.reg))
            if value.symbolic:
                on_complex_br(state, new_state, block)
                return solve_symbolic(block, new_state)
            else:
                on_fix_br(inst, value.v)
                return [(value.v, new_state)]
        print("wtf1")

    elif inst.mnemonic == "ret":
        return []

    elif inst.mnemonic == "cbz":
        return [(block.addr + block.size, new_state),
                (inst.operands[1].value.imm, new_state)]

    elif inst.mnemonic == "tbnz":
        return [(block.addr + block.size, new_state),
                (inst.operands[2].value.imm, new_state)]

    elif (inst.mnemonic == "b.eq" or
          inst.mnemonic == "b.ne" or
          inst.mnemonic == "b.cs" or
          inst.mnemonic == "b.hs" or
          inst.mnemonic == "b.cc" or
          inst.mnemonic == "b.lo" or
          inst.mnemonic == "b.mi" or
          inst.mnemonic == "b.pl" or
          inst.mnemonic == "b.vs" or
          inst.mnemonic == "b.vc" or
          inst.mnemonic == "b.hi" or
          inst.mnemonic == "b.ls" or
          inst.mnemonic == "b.ge" or
          inst.mnemonic == "b.lt" or
          inst.mnemonic == "b.gt" or
          inst.mnemonic == "b.le" or
          inst.mnemonic == "b.al"):
        return [(block.addr + block.size, new_state),
                (inst.operands[0].value.imm, new_state)]

    print("wtf2", hex(inst.address), inst.mnemonic)


def fix_complex_csel_br(start_state, end_state, block: angr.Block, depend):
    def find_inst(name):
        for inst in depend:
            if inst.mnemonic == name:
                return inst
        return None

    br = block.capstone.insns[len(block.capstone.insns) - 1]
    csel = find_inst("csel")
    pre_state = run_block(block, start_state.copy(), stop_addr=csel.address)
    rd = csel.operands[0].value.reg
    rn = csel.operands[1].value.reg
    rm = csel.operands[2].value.reg
    cond = csel.op_str.split(", ")[3]

    start = csel.address + 4

    pre_state.registers.store(cs.reg_name(rd), pre_state.regs.get(cs.reg_name(rn)))
    rn_state = run_block(block, pre_state.copy(), start_addr=start)
    rn_value = rn_state.regs.get(cs.reg_name(br.operands[0].value.reg))
    if rn_value.symbolic:
        return None, None

    pre_state.registers.store(cs.reg_name(rd), pre_state.regs.get(cs.reg_name(rm)))
    rm_state = run_block(block, pre_state.copy(), start_addr=start)
    rm_value = rn_state.regs.get(cs.reg_name(br.operands[0].value.reg))
    if rm_value.symbolic:
        return None, None

    return [
        {
            "inst": "b." + cond,
            "real_addr": rn_value.v,
        }, {
            "inst": "b",
            "real_addr": rm_value.v,
        }
    ], [
        csel.address,
        br.address
    ]


def fix_complex_br(start_state, end_state, block: angr.Block):
    depend = find_br_dep_inst(block)

    def count_inst(name):
        count = 0
        for inst in depend:
            if inst.mnemonic == name:
                count += 1
        return count

    print(serialize_instruction_list(depend))

    if not (count_inst("cmp") >= 0 or
            count_inst("tst") >= 0 or
            count_inst("fcmp") >= 0 or
            count_inst("cmn") >= 0):
        print("no one cmp")
        return None

    new_13 = None
    nop_addr = None
    if count_inst("csel") == 1:
        new_13, nop_addr = fix_complex_csel_br(start_state, end_state, block, depend)
    elif count_inst("csel") > 1:
        print("more than one csel")
        return None

    if len(new_13) > len(nop_addr):
        print("new_13 > nop_addr")
        return None

    br = block.capstone.insns[len(block.capstone.insns) - 1]
    start_addr = block.capstone.insns[0].address
    size = br.address - start_addr + 4
    code = state.memory.load(start_addr, size)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    codes = bytes_to_chunks(code_bytes)

    def addr2idx(addr):
        return int((addr - br.address) / 4)

    for item in nop_addr:
        codes[addr2idx(item)] = None
    codes = move_none_to_end(codes)

    def get_nop_addr():
        index = 0
        for idx in range(0, len(codes)):
            if codes[idx] == None:
                index = idx
                break

        return index, br.address + index * 4

    for item in new_13:
        idx, addr = get_nop_addr()
        codes[idx] = ks.asm(item["inst"] + " " + hex(item["real_addr"]), addr, True)[0]

    return {
        "addr": br.address,
        "code": chunks_to_bytes(codes).hex()
    }


def process_func(addr):
    func_start, func_end = guess_func_range(addr)
    print(hex(func_start), hex(func_end))
    blocks = get_all_block(func_start, func_end)
    print("blocks size ", len(blocks))

    state = project.factory.blank_state(addr=func_start)
    state.options.add(angr.options.CALLLESS)
    state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
    stack = [(func_start, state)]
    visited = set()
    patch_info = []

    def on_fix_br(inst, real_target):
        print("fix ", inst, hex(real_target))
        fix_inst = ""
        if inst.mnemonic == "blr":
            fix_inst = "bl "
        elif inst.mnemonic == "br":
            fix_inst = "b "
        else:
            print("wtf4")
        if symbols.get(real_target):
            info = {
                "addr": inst.address,
                "inst": fix_inst,
                "sym": symbols.get(real_target)
            }
        else:
            info = {
                "addr": inst.address,
                "code": ks.asm(fix_inst + hex(real_target), inst.address, True)[0].hex()
            }
        patch_info.append(info)

    def on_complex_br(start_state, end_state, block):
        result = fix_complex_br(start_state, end_state, block)
        patch_info.append(result)

    while stack:
        current_addr, current_state = stack.pop()
        if current_addr in visited:
            continue
        visited.add(current_addr)

        if current_addr not in blocks:
            print("new block", hex(current_addr))
            blocks[current_addr] = {
                "block": project.factory.block(current_addr)
            }
        block = blocks[current_addr]["block"]

        log_next_addr = ""
        next_states = visit_block(block, current_state, on_fix_br, on_complex_br)
        for next_addr, next_state in next_states:
            # if func_start <= next_addr < func_end and next_addr not in visited:  # 限制在函数内
            stack.append((next_addr, next_state))
            log_next_addr += hex(next_addr) + ", "

        print("visit", hex(current_addr), "next", log_next_addr)

    visited_sorted = ', '.join(map(hex, sorted(visited)))
    print("visited", visited_sorted)

    blocks_keys_sorted = ', '.join(map(hex, sorted(blocks.keys())))
    print("all", blocks_keys_sorted)

    print("patch_info", json.dumps(patch_info))


process_func(0x14F394)

# print(serialize_instruction_list()

# find_br_dep_inst(project.factory.block(0x150138))
