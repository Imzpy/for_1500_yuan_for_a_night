import archinfo
import pyvex


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
                # print("waring read mem")
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