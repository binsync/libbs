import logging

from libbs.api import ArtifactLifter

l = logging.getLogger(name=__name__)


class IDAArtifactLifter(ArtifactLifter):
    lift_map = {
        "__int64": "long long",
        "__int32": "int",
        "__int16": "short",
        "__int8": "char",
    }

    def __init__(self, deci):
        super(IDAArtifactLifter, self).__init__(deci)

    def lift_type(self, type_str: str) -> str:
        for ida_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(ida_t, bs_t)

        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return abs(offset) #compat.ida_to_angr_stack_offset(func_addr, offset)
