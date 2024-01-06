import codecs

import toml

from .artifact import Artifact


class Patch(Artifact):
    """
    Describes a patch on the binary code.
    """
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "bytes",
    )

    def __init__(self, addr, bytes_, name=None, last_change=None):
        super(Patch, self).__init__(last_change=last_change)
        self.addr = addr
        self.name = name
        self.bytes = bytes_

    def __str__(self):
        return f"<Patch: {self.name}@{hex(self.addr)} len={len(self.bytes)}>"

    def __repr__(self):
        return self.__str__()

    def __getstate__(self):
        return {
            "name": self.name,
            "addr": hex(self.addr),
            "bytes": codecs.encode(self.bytes, "hex"),
            "last_change": self.last_change
        }

    @classmethod
    def parse(cls, s):
        patch = Patch(None, None, None)
        patch.__setstate__(toml.loads(s))
        return patch

    @classmethod
    def load_many(cls, patches_toml):
        for patch_toml in patches_toml.values():
            patch = Patch(None, None, None)
            try:
                patch.__setstate__(patch_toml)
            except TypeError:
                # skip all incorrect ones
                continue
            yield patch

    @classmethod
    def dump_many(cls, patches):
        patches_ = {}
        for v in patches.values():
            patches_[hex(v.addr)] = v.__getstate__()
        return patches_

    def copy(self):
        return Patch(
            self.addr,
            self.bytes,
            name=self.name,
            last_change=self.last_change
        )
