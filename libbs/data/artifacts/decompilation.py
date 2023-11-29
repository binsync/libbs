import toml

from .artifact import Artifact


class Decompilation(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "decompilation",
        "decompiler",
    )

    def __init__(self, addr, decompilation, decompiler=None, last_change=None):
        super().__init__(last_change=last_change)
        self.addr = addr
        self.decompilation = decompilation
        self.decompiler = decompiler

    def __str__(self):
        return f"//ADDR: {hex(self.addr)}\n// SOURCE: {self.decompiler}\n{self.decompilation}"

    def __repr__(self):
        return f"<Decompilation: {self.decompiler}@{hex(self.addr)} len={len(self.decompilation)}>"

    @classmethod
    def parse(cls, s):
        dec = Decompilation(None, None)
        dec.__setstate__(toml.loads(s))
        return dec
