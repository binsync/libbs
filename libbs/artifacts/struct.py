from typing import Dict, List, Optional

import toml

from .artifact import Artifact
from . import TomlHexEncoder

import logging
l = logging.getLogger(name=__name__)


class StructMember(Artifact):
    """
    Describes a struct member that corresponds to a struct.
    Offset is the byte offset of the member from the start of the struct.
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "offset",
        "type",
        "size",
    )

    def __init__(
        self,
        name: str = None,
        offset: int = None,
        type_: Optional[str] = None,
        size: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.name: str = name
        self.offset: int = offset
        self.type: str = type_
        self.size: int = size

    def __str__(self):
        return f"<StructMember: {self.type} {self.name}; @{hex(self.offset)}>"


class Struct(Artifact):
    """
    Describes a struct.
    All members are stored by their byte offset from the start of the struct.
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "size",
        "members",
    )

    def __init__(
        self,
        name: str = None,
        size: int = None,
        members: Dict[int, StructMember] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.name = name
        self.size = size or 0
        self.members: Dict[int, StructMember] = members or {}

    def __str__(self):
        scope_str = f" scope={self.scope}" if self.scope else ""
        return f"<Struct: {self.name} membs={len(self.members)}{scope_str} ({hex(self.size)})>"

    def __getstate__(self):
        data_dict = super().__getstate__()
        data_dict["members"] = {
            hex(offset): member.__getstate__() for offset, member in self.members.items()
        }

        return data_dict

    # TODO: fix how state dumping and loading works, see explanation below
    #
    # We, apparently, implemented __setestate__ and __getstate__ incorrectly for actual Pickle dumping and loading.
    # When we try to access the `self.members` below, it seems that `self` does not yet have any of the attributes.
    # This implies that `self` is not to be actually used, which also means we should be instead adding members
    # to the bigger `members` dictionary.
    #
    # Remvoing just this case of `self` usage is easy... but we use `self` in almost every nested object Artifact.
    # To make this get/set state actually useful they need to all be rewritten to not use `self`, which includes
    # the top-level Artifact class (uses a list defined by objects to figure out what attributes should not be
    # seralized when serializing objects).
    #
    # So, to make it work do the following:
    # 1. Search through all artifact classes on setstate and make sure we do not actually use `self`
    # 2. If use `self`, replace with the dictionary access and setting
    # 3. For the use in Artifact, replace the dynamic lists with static lists, which is only really used by
    #   by `Function` for excluding decompilation object.
    def __setstate__(self, state):
        # XXX: this is a backport of the old state format. Remove this after a few releases.
        if "metadata" in state:
            metadata: Dict = state.pop("metadata")
            metadata.update(state)
            state = metadata

        members_dat = state.pop("members", None)
        if members_dat:
            for off, member in members_dat.items():
                sm = StructMember()
                sm.__setstate__(member)
                self.members[int(off, 0)] = sm
        else:
            self.members = {}
        super().__setstate__(state)

    def add_struct_member(self, mname, moff, mtype, size):
        self.members[moff] = StructMember(mname, moff, mtype, size)

    def append_struct_member(self, mname, mtype, size):
        # first, find the next available offset
        next_offset = 0
        for off in self.members.keys():
            if off >= next_offset:
                next_offset = off + self.members[off].size
        self.members[next_offset] = StructMember(mname, next_offset, mtype, size)

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, Struct):
            return diff_dict

        for k in ["name", "size"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # struct members
        diff_dict["members"] = {}
        for off, member in self.members.items():
            try:
                other_mem = other.members[off]
            except KeyError:
                other_mem = None

            diff_dict["members"][off] = member.diff(other_mem)

        for off, other_mem in other.members.items():
            if off in diff_dict["members"]:
                continue

            diff_dict["members"][off] = self.invert_diff(other_mem.diff(None))

        return diff_dict

    def nonconflict_merge(self, struct2: "Struct", **kwargs) -> "Struct":
        struct1: "Struct" = self.copy()
        if not struct2 or struct1 == struct2:
            return struct1

        struct_diff = struct1.diff(struct2)
        merge_struct = struct1

        members_diff = struct_diff["members"]
        for off, mem in struct2.members.items():
            # no difference
            if off not in members_diff:
                continue

            mem_diff = members_diff[off]

            # struct member is newly created
            if "before" in mem_diff and mem_diff["before"] is None:
                # check for overlap
                new_mem_size = mem.size
                new_mem_offset = mem.offset

                for off_check in range(new_mem_offset, new_mem_offset + new_mem_size):
                    if off_check in merge_struct.members:
                        break
                else:
                    merge_struct.members[off] = mem.copy()

                continue

            # member differs
            merge_mem = merge_struct.members.get(off, None)
            if not merge_mem:
                merge_mem = mem

            merge_mem = StructMember.nonconflict_merge(merge_mem, mem)
            merge_struct.members[off] = merge_mem

        # compute the new size
        merge_struct.size = sum(mem.size for mem in merge_struct.members.values())
        return merge_struct
