import logging
import typing

from libbs.artifacts import StackVariable, Artifact, FunctionArgument, StructMember
from libbs.api.type_parser import CTypeParser

if typing.TYPE_CHECKING:
    from libbs.api import DecompilerInterface

_l = logging.getLogger(name=__name__)


class ArtifactLifter:
    def __init__(self, deci: "DecompilerInterface", types=None):
        self.deci = deci
        self.type_parser = CTypeParser(extra_types=types)

    #
    # Public API
    #

    def lift(self, artifact: Artifact):
        return self._lift_or_lower_artifact(artifact, "lift")

    def lower(self, artifact: Artifact):
        return self._lift_or_lower_artifact(artifact, "lower")

    #
    # Override Mandatory Funcs
    #

    def lift_type(self, type_str: str) -> str:
        pass

    def lift_addr(self, addr: int) -> int:
        base_addr = self.deci.binary_base_addr
        if addr < base_addr:
            self.deci.warning(f"Lifting an address that appears already lifted: {addr}...")

        return addr - base_addr

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        pass

    def lower_type(self, type_str: str) -> str:
        pass

    def lower_addr(self, addr: int) -> int:
        base_addr = self.deci.binary_base_addr
        if addr >= base_addr != 0:
            self.deci.warning(f"Lowering an address that appears already lowered: {addr}...")

        return addr + base_addr

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        pass

    #
    # Private
    #

    def _lift_or_lower_artifact(self, artifact, mode):
        target_attrs = ("type", "offset", "addr", "func_addr", "line_map")
        if mode not in ("lower", "lift"):
            return None

        if not isinstance(artifact, Artifact):
            return artifact
        lifted_art = artifact.copy()

        # correct simple properties in the artifact
        for attr in target_attrs:
            if hasattr(lifted_art, attr):
                curr_val = getattr(lifted_art, attr)
                if curr_val is None:
                    continue

                # special handling for stack variables
                if attr == "offset":
                    if not isinstance(artifact, StackVariable):
                        continue
                    lifting_func = getattr(self, f"{mode}_stack_offset")
                    setattr(lifted_art, attr, lifting_func(curr_val, lifted_art.addr))
                # special handling for decompilation
                elif attr == "line_map":
                    lifted_line_map = {}
                    lift_or_lower_func = self.lift_addr if mode == "lift" else self.lower_addr
                    for k, v in curr_val.items():
                        lifted_line_map[k] = {lift_or_lower_func(_v) for _v in v}

                    setattr(lifted_art, attr, lifted_line_map)
                else:
                    attr_func_name = attr if attr != "func_addr" else "addr"
                    lifting_func = getattr(self, f"{mode}_{attr_func_name}")
                    setattr(lifted_art, attr, lifting_func(curr_val))

        # recursively correct nested artifacts
        for attr in lifted_art.__slots__:
            attr_val = getattr(lifted_art, attr)
            if not attr_val:
                continue

            # nested function headers
            if attr == "header":
                setattr(lifted_art, attr, self._lift_or_lower_artifact(attr_val, mode))
            # nested args, stack_vars, or struct_members
            elif isinstance(attr_val, dict):
                nested_arts = {}
                for k, v in attr_val.items():
                    nested_art = self._lift_or_lower_artifact(v, mode)
                    nested_arts[nested_art.offset if isinstance(nested_art, (StackVariable, FunctionArgument, StructMember)) else k] = nested_art
                setattr(lifted_art, attr, nested_arts)

        return lifted_art
