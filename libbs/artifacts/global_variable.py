from typing import Optional

import toml

from .artifact import Artifact


class GlobalVariable(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "type",
        "size"
    )

    def __init__(
        self,
        addr: int = None,
        name: str = None,
        type_: Optional[str] = None,
        size: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.addr = addr
        self.name = name
        self.type = type_
        self.size = size

    def __str__(self):
        return f"<GlobalVar: {self.type} {self.name}; @{self.addr} len={self.size}>"

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
