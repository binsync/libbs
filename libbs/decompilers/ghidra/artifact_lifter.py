import logging

from libbs.api import ArtifactLifter

l = logging.getLogger(name=__name__)


class GhidraArtifactLifter(ArtifactLifter):
    lift_map = {}

    def __init__(self, deci):
        super(GhidraArtifactLifter, self).__init__(deci)

    def lift_type(self, type_str: str) -> str:
        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset
