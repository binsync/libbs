import json
from typing import Dict, Optional, List, Type
import datetime

import toml

from .formatting import ArtifactFormat, TomlHexEncoder


class Artifact:
    """
    The Artifact class acts as the base for all other artifacts that can be produced by a decompiler (or decompiler
    adjacent tool). In general, the comparisons of these derived classes should only be done on the attributes in
    __slots__, with the exception of the last_change property.
    """
    LST_CHNG_ATTR = "last_change"
    ADDR_ATTR = "addr"
    __slots__ = (
        LST_CHNG_ATTR,
    )

    def __init__(self, last_change: Optional[datetime.datetime] = None):
        self.last_change = last_change

    def __getstate__(self) -> Dict:
        return dict(
            (k, getattr(self, k)) for k in self.__slots__
        )

    def __setstate__(self, state):
        for k in self.__slots__:
            if k in state:
                setattr(self, k, state[k])

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        for k in self.__slots__:
            if k == self.LST_CHNG_ATTR:
                continue

            if getattr(self, k) != getattr(other, k):
                return False

        return True

    def __hash__(self):
        long_str = ""
        for attr in self.__slots__:
            long_str += getattr(self, attr)

        return hash(long_str)

    def __repr__(self):
        return self.__str__()

    def copy(self) -> "Artifact":
        new_obj = self.__class__()
        for attr in self.__slots__:
            attr_v = getattr(self, attr)
            if isinstance(attr_v, list):
                new_list = []
                for lobj in attr_v:
                    if hasattr(lobj, "copy"):
                        new_list.append(lobj.copy())
                setattr(new_obj, attr, new_list)
            elif isinstance(attr_v, dict):
                new_dict = {}
                for dk, dv in attr_v.items():
                    new_dk = dk.copy() if hasattr(dk, "copy") else dk
                    new_dv = dv.copy() if hasattr(dv, "copy") else dv
                    new_dict[new_dk] = new_dv
                setattr(new_obj, attr, new_dict)
            else:
                setattr(new_obj, attr, attr_v)

        return new_obj

    #
    # Serialization
    #

    def _to_c_string(self):
        raise NotImplementedError

    @classmethod
    def _from_c_string(cls, cstring) -> Dict:
        raise NotImplementedError

    def dumps(self, fmt=ArtifactFormat.TOML) -> str:
        dict_data = self.__getstate__()
        if fmt == ArtifactFormat.TOML:
            return toml.dumps(dict_data, encoder=TomlHexEncoder())
        elif fmt == ArtifactFormat.JSON:
            return json.dumps(dict_data)
        elif fmt == ArtifactFormat.C_LANG:
            return self._to_c_string()
        else:
            raise ValueError(f"Dumping to format {fmt} is not yet supported.")

    def dump(self, fp, fmt=ArtifactFormat.TOML):
        data = self.dumps(fmt=fmt)
        fp.write(data)

    @classmethod
    def loads(cls, string, fmt=ArtifactFormat.TOML) -> "Artifact":
        if fmt == ArtifactFormat.TOML:
            dict_data = toml.loads(string)
        elif fmt == ArtifactFormat.JSON:
            dict_data = json.loads(string)
        elif fmt == ArtifactFormat.C_LANG:
            dict_data = cls._from_c_string(string)
        else:
            raise ValueError(f"Loading from format {fmt} is not yet supported.")

        art = cls()
        art.__setstate__(dict_data)
        return art

    @classmethod
    def load(cls, fp, fmt=ArtifactFormat.TOML):
        data = fp.read()
        return cls.loads(data, fmt=fmt)

    @classmethod
    def dumps_many(cls, artifacts: List["Artifact"], key_attr=ADDR_ATTR, fmt=ArtifactFormat.TOML) -> str:
        artifacts_dict = {}
        for art in artifacts:
            k = getattr(art, key_attr)
            if isinstance(k, int):
                k = hex(k)

            artifacts_dict[k] = art.__getstate__()

        if fmt == ArtifactFormat.TOML:
            return toml.dumps(artifacts_dict, encoder=TomlHexEncoder())
        elif fmt == ArtifactFormat.JSON:
            return json.dumps(artifacts_dict)
        else:
            raise ValueError(f"Dumping many to format {fmt} is not yet supported.")

    @classmethod
    def loads_many(cls, string, fmt=ArtifactFormat.TOML) -> List["Artifact"]:
        if fmt == ArtifactFormat.TOML:
            dict_data = toml.loads(string)
        elif fmt == ArtifactFormat.JSON:
            dict_data = json.loads(string)
        else:
            raise ValueError(f"Loading many from format {fmt} is not yet supported.")

        arts = []
        for _, v in dict_data.items():
            art = cls()
            art.__setstate__(v)
            arts.append(art)

        return arts

    #
    # Public API
    #

    @property
    def commit_msg(self) -> str:
        return f"Updated {self}"

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, self.__class__):
            for k in self.__slots__:
                if k == self.LST_CHNG_ATTR:
                    continue

                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }
            return diff_dict

        for k in self.__slots__:
            self_attr, other_attr = getattr(self, k), getattr(other, k)
            if self_attr != other_attr:
                if k == self.LST_CHNG_ATTR:
                    continue

                diff_dict[k] = {
                    "before": self_attr,
                    "after": other_attr
                }
        return diff_dict

    @classmethod
    def invert_diff(cls, diff_dict: Dict):
        inverted_diff = {}
        for k, v in diff_dict.items():
            if k == "before":
                inverted_diff["after"] = v
            elif k == "after":
                inverted_diff["before"] = v
            elif isinstance(v, Dict):
                inverted_diff[k] = cls.invert_diff(v)
            else:
                inverted_diff[k] = v

        return inverted_diff

    def reset_last_change(self):
        """
        Resets the change time of the Artifact.
        In subclasses, this should also reset all artifacts with nested artifacts
        """
        self.last_change = None

    def overwrite_merge(self, obj2: "Artifact", **kwargs):
        """
        This function should really be overwritten by its subclass
        """
        merge_obj = self.copy()
        if not obj2 or merge_obj == obj2:
            return merge_obj

        for attr in self.__slots__:
            a2 = getattr(obj2, attr)
            if a2 is not None:
                setattr(merge_obj, attr, a2)

        return merge_obj

    def nonconflict_merge(self, obj2: "Artifact", **kwargs):
        obj1 = self.copy()
        if not obj2 or obj1 == obj2:
            return obj1

        obj_diff = obj1.diff(obj2)
        merge_obj = obj1.copy()

        for attr in self.__slots__:
            if attr in obj_diff and obj_diff[attr]["before"] is None:
                setattr(merge_obj, attr, getattr(obj2, attr))

        return merge_obj
