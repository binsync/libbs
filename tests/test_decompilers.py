import unittest
from pathlib import Path
import os

from libbs.api import DecompilerInterface
from libbs.artifacts import FunctionHeader, StackVariable, Struct, GlobalVariable, Enum, Comment
from libbs.decompilers import IDA_DECOMPILER, ANGR_DECOMPILER, BINJA_DECOMPILER, GHIDRA_DECOMPILER

GHIDRA_HEADLESS_PATH = Path(os.environ.get('GHIDRA_HEADLESS_PATH', ""))
IDA_HEADLESS_PATH = Path(os.environ.get('IDA_HEADLESS_PATH', ""))
TEST_BINARY_DIR = Path(__file__).parent / "binaries"
DEC_TO_HEADLESS = {
    IDA_DECOMPILER: IDA_HEADLESS_PATH,
    GHIDRA_DECOMPILER: GHIDRA_HEADLESS_PATH,
    ANGR_DECOMPILER: None,
    BINJA_DECOMPILER: None,
}

func_change_count = 0
class TestHeadlessInterfaces(unittest.TestCase):
    def setUp(self):
        self._generic_renamed_name = "binsync_main"
        self._fauxware_path = TEST_BINARY_DIR / "fauxware"

    def test_ghidra(self):
        # useful command for testing, kills all Headless-Ghidra:
        # kill $(ps aux | grep 'Ghidra-Headless' | awk '{print $2}')
        deci = DecompilerInterface.discover(
            force_decompiler=GHIDRA_DECOMPILER,
            headless=True,
            headless_dec_path=DEC_TO_HEADLESS[GHIDRA_DECOMPILER],
            binary_path=self._fauxware_path,
            start_headless_watchers = True
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self._generic_renamed_name
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self._generic_renamed_name

        func_args = main.header.args
        func_args[0].name = "new_name_1"
        func_args[0].type = "int"
        func_args[0].size = 4   # set manually to avoid resetting the size in the caller
        func_args[1].name = "new_name_2"
        func_args[1].type = "double"
        func_args[1].size = 8
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].header.args == func_args

        # Test artifact watchers
        deci.artifact_write_callbacks[FunctionHeader] = [func_hit]

        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = "changed"
        deci.functions[func_addr] = main

        main.name = "main"
        deci.functions[func_addr] = main

        # TODO: fix argument change watching
        # func_args = main.header.args
        # func_args[0].name = "changed_name"
        # func_args[1].name = "changed_name2"
        # deci.functions[func_addr] = main

        assert func_change_count == 2

        deci.shutdown()

    def test_angr(self):
        deci = DecompilerInterface.discover(
            force_decompiler=ANGR_DECOMPILER,
            headless=True,
            binary_path=self._fauxware_path
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self._generic_renamed_name
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self._generic_renamed_name
        assert self._generic_renamed_name in deci.main_instance.project.kb.functions


def func_hit(*args, **kwargs):
    global func_change_count
    func_change_count += 1

if __name__ == "__main__":
    unittest.main()
