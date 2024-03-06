import typing

if typing.TYPE_CHECKING:
    from .ghidra_api import GhidraAPIWrapper


class Transaction:
    def __init__(self, ghidra: "GhidraAPIWrapper", msg="BinSync transaction"):
        self._ghidra = ghidra
        self._trans_msg = msg

        self.trans_id = None

    def __enter__(self):
        self.trans_id = self._ghidra.currentProgram.startTransaction(self._trans_msg)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ghidra.currentProgram.endTransaction(self.trans_id, True)