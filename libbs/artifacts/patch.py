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

    def __init__(
        self,
        addr: int = None,
        bytes_: bytes = None,
        name: str = None,
        **kwargs
    ):
        super(Patch, self).__init__(**kwargs)
        self.addr = addr
        self.name = name
        self.bytes = bytes_

    def __str__(self):
        return f"<Patch: {self.name}@{hex(self.addr)} len={len(self.bytes)}>"

    def __getstate__(self):
        data_dict = super().__getstate__()
        data_dict["bytes"] = codecs.encode(self.bytes, "hex").decode()
        return data_dict

    def __setstate__(self, state):
        bytes_dat = state.pop("bytes", None)
        if bytes_dat:
            self.bytes = codecs.decode(bytes_dat, "hex")
        super().__setstate__(state)

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
