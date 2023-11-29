from libbs.api import ArtifactLifter


class AngrArtifactLifter(ArtifactLifter):
    """
    TODO: finish me
    """
    def __init__(self, interface):
        super(AngrArtifactLifter, self).__init__(interface)

    def lift_addr(self, addr: int) -> int:
        return self.controller.rebase_addr(addr)

    def lift_type(self, type_str: str) -> str:
        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_addr(self, addr: int) -> int:
        return self.controller.rebase_addr(addr, up=True)

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset
