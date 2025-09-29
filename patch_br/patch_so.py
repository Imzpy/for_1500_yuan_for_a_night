class PatchSo:
    def __init__(self, project, path):
        self.path = path
        self.project = project
        with open(path, 'rb') as f:
            self.binary_bytes = f.read()
        self.binary_bytes = bytearray(self.binary_bytes)

    def patch(self, addr, data: bytes):
        addr = self.project.loader.main_object.addr_to_offset(addr)
        self.binary_bytes[addr:addr + len(data)] = data

    def save(self):
        with open(self.path + "_patch.so", 'wb') as f:
            f.write(self.binary_bytes)
