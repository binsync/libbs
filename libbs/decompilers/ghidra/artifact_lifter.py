import logging

from libbs.api import ArtifactLifter

_l = logging.getLogger(name=__name__)


class GhidraArtifactLifter(ArtifactLifter):
    lift_map = {
        "undefined64": "long long",
        "undefined32": "int",
        "undefined16": "short",
        "undefined8": "char",
        "undefined": "char",
    }

    def lift_type(self, type_str: str) -> str:
        og_type_str = type_str
        # convert to simple C when possible
        for ghidra_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(ghidra_t, bs_t)

        # parse out type decls if needed
        type_str = self.type_parser.extract_type_name(type_str)
        if type_str is None:
            self.deci.error(f"Failed to extract type name from {og_type_str}, defaulting to void *")
            type_str = "void *"

        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset
