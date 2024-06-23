import logging

from libbs.api import ArtifactLifter

l = logging.getLogger(name=__name__)


class GhidraArtifactLifter(ArtifactLifter):
    lift_map = {
        "undefined64": "long long",
        "undefined32": "int",
        "undefined16": "short",
        "undefined8": "char",
        "undefined": "char",
    }

    def lift_type(self, type_str: str) -> str:
        for ghidra_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(ghidra_t, bs_t)

        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset
