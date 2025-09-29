from capstone import *

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def disasm(state, pc):
    code = state.memory.load(pc, 4)
    code_bytes = state.solver.eval(code, cast_to=bytes)
    for item in cs.disasm(code_bytes, pc):
        return item
    return None

def chunks_to_bytes(chunks: list[bytes]) -> bytes:
    return b''.join(chunks)

def bytes_to_chunks(data: bytes) -> list[bytes]:
    return [data[i:i + 4] for i in range(0, len(data), 4)]


def move_none_to_end(arr: list) -> list:
    result = arr.copy()
    non_none_pos = 0
    for i in range(len(result)):
        if result[i] is not None:
            result[non_none_pos], result[i] = result[i], result[non_none_pos]
            non_none_pos += 1
    return result
