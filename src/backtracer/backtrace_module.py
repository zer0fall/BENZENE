from typing import Dict
from typing import List

class BacktraceModule:
    def __init__(self, filename: str, start: int, end: int):
        self.filename: str = filename
        self._start_addr = start
        self._end_addr = end

    @property
    def base(self):
        return self._start_addr

    def check(self, addr):
        if addr >= self._start_addr and addr <= self._end_addr: # m[1]: module base address, m[2]: module end address
            return True
        return False



class BacktraceModules:
    def __init__(self):
        self.modules: Dict[str, BacktraceModule] = {}
        self.skip_modules: List[BacktraceModule] = []

    def addModule(self, name, start, end):
        self.modules[name] = BacktraceModule(name, start, end)

    def getModuleByName(self, name):
        return self.modules[name]

    def getModuleBase(self, addr):
        for m in self.modules.values():
            if m.check(addr):
                return m.base

        return None

    def getModule(self, addr):
        for m in self.modules.values():
            if m.check(addr):
                return m
        return None

    def add_skip_module(self, name, start, end):
        self.skip_modules.append(BacktraceModule(name, start, end))


bt_modules = BacktraceModules()

def get_module_base(addr):
    return bt_modules.getModuleBase(addr)

def get_module(addr):
    return bt_modules.getModule(addr)

def get_module_by_name(name):
    return bt_modules.getModuleByName(name)

def add_module(filename, start, end):
    bt_modules.addModule(filename, start, end)

def is_skip_module(addr):
    for module in bt_modules.skip_modules:
        if module._start_addr <= addr and addr <= module._end_addr:
            return True
    return False
