import logging

from libbs.data import StackVariable, Artifact
from libbs.api.type_parser import CTypeParser

_l = logging.getLogger(name=__name__)


class ArtifactLifter:
    def __init__(self, controller, types=None):
        self.controller = controller
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
        pass

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        pass

    def lower_type(self, type_str: str) -> str:
        pass

    def lower_addr(self, addr: int) -> int:
        pass

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        pass

    #
    # Private
    #

    def _lift_or_lower_artifact(self, artifact, mode):
        target_attrs = ("type", "offset", "addr")
        if mode not in ("lower", "lift"):
            return None

        if not isinstance(artifact, Artifact):
            return artifact
        lifted_art = artifact.copy()

        # correct simple properties in the artifact
        for attr in target_attrs:
            if hasattr(lifted_art, attr):
                curr_val = getattr(lifted_art, attr)
                if not curr_val:
                    continue

                # special handling for stack variables
                if attr == "offset":
                    if not isinstance(artifact, StackVariable):
                        continue
                    lifting_func = getattr(self, f"{mode}_stack_offset")
                    setattr(lifted_art, attr, lifting_func(curr_val, lifted_art.addr))
                else:
                    lifting_func = getattr(self, f"{mode}_{attr}")
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
                nested_arts = {
                    k: self._lift_or_lower_artifact(v, mode) for k, v in attr_val.items()
                }
                setattr(lifted_art, attr, nested_arts)

        return lifted_art
