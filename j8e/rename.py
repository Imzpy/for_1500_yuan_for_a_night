# ?description=Rename a Java field to its source variable's name, in a field assignment statement.
# ?shortcut=
# coding=utf-8
from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit


class rename(IScript):
    def run(self, ctx):
        self.ctx = ctx
        self.mainProject = ctx.getMainProject()
        clzIdx = 0
        for unit in self.mainProject.findUnits(IDexUnit):
            for clz in unit.getClasses():
                if any(ord(c) > 127 for c in clz.getName()):
                    clz.setName("Class_" + str(clzIdx))
                    clzIdx += 1

                fIdx = 0
                for f in clz.getFields():
                    if any(ord(c) > 127 for c in f.getName()):
                        f.setName(self.java_field_sign_to_type_name(f.getSignature(True)) + "_" + str(fIdx))
                        fIdx += 1

                mIdx = 0
                for m in clz.getMethods():
                    if any(ord(c) > 127 for c in m.getName()):
                        m.setName("method_" + str(mIdx))
                        mIdx += 1

    def java_field_sign_to_type_name(self, field_sign):
        base_types = {
            'B': 'byte', 'C': 'char', 'D': 'double', 'F': 'float',
            'I': 'int', 'J': 'long', 'S': 'short', 'Z': 'boolean'
        }
        array_dim = 0
        while field_sign.startswith('['):
            array_dim += 1
            field_sign = field_sign[1:]
        if field_sign in base_types:
            type_name = base_types[field_sign]
        elif field_sign.startswith('L') and field_sign.endswith(';'):
            type_name = field_sign[1:-1].split('/')[-1]
        else:
            type_name = 'unknown'
        if array_dim > 0:
            type_name += 'Array' * array_dim
        var_name = type_name[0].lower() + type_name[1:] if type_name != 'unknown' else 'unknownType'
        return var_name