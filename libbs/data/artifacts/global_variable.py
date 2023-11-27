import toml

from .artifact import Artifact


class GlobalVariable(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "type",
        "size"
    )

    def __init__(self, addr, name, type_=None, size=0, last_change=None):
        super(GlobalVariable, self).__init__(last_change=last_change)
        self.addr = addr
        self.name = name
        self.type = type_
        self.size = size

    def __str__(self):
        return f"<GlobalVar: {self.type} {self.name}; @{self.addr} len={self.size}>"

    def __repr__(self):
        return self.__str__()

    @classmethod
    def parse(cls, s):
        gv = GlobalVariable(None, None)
        gv.__setstate__(toml.loads(s))
        return gv

    @classmethod
    def load_many(cls, gvars_toml):
        for gvar_toml in gvars_toml.values():
            global_var = GlobalVariable(None, None)
            try:
                global_var.__setstate__(gvar_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield global_var

    @classmethod
    def dump_many(cls, global_vars):
        global_vars_ = {}

        for v in sorted(global_vars.values(), key=lambda x: x.addr):
            global_vars_[hex(v.addr)] = v.__getstate__()
        return global_vars_

    def copy(self):
        gvar = GlobalVariable(self.addr, self.name, type_=self.type, size=self.size, last_change=self.last_change)
        return gvar
