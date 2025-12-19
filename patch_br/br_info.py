import json

from angr.block import DisassemblerInsn
from capstone import *

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


class BrIfInfo:
    def __init__(self):
        self.br: DisassemblerInsn = None
        self.inst: list[DisassemblerInsn] = []
        self.jump_reg = None
        self.block_addr = None
        self.true_value = None
        self.false_value = None
        self.value = None

    def __str__(self):
        return json.dumps(self, cls=BrIfInfoEncoder)


def serialize_instruction(inst):
    if inst is None:
        return None
    return {
        "address": inst.address,
        "mnemonic": inst.mnemonic,
        "op_str": inst.op_str,
    }


def serialize_instruction_list(inst):
    result = []
    for item in inst:
        if item is None:
            return None
        result.append({
            "address": item.address,
            "mnemonic": item.mnemonic,
            "op_str": item.op_str,
        })
    return result


class BrIfInfoEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, BrIfInfo):
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


def br_list_to_json(brs: list):
    return json.dumps(brs, cls=BrIfInfoEncoder)


def load_br_list(state, path):
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
