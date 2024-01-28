import unittest
from pathlib import Path
import os

from libbs.api import DecompilerInterface
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


class TestHeadlessInterfaces(unittest.TestCase):
    def setUp(self):
        self._generic_renamed_name = "binsync_main"

    def _generic_decompiler_test(self, decompiler):
        fauxware_path = TEST_BINARY_DIR / "fauxware"
        deci = DecompilerInterface.discover(
            force_decompiler=decompiler,
            headless=True,
            headless_dec_path=DEC_TO_HEADLESS[decompiler],
            binary_path=fauxware_path
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self._generic_renamed_name
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self._generic_renamed_name

        return deci

    def test_ghidra(self):
        deci = self._generic_decompiler_test(decompiler=GHIDRA_DECOMPILER)
        deci.shutdown()

    def test_angr(self):
        deci = self._generic_decompiler_test(decompiler=ANGR_DECOMPILER)
        assert self._generic_renamed_name in deci.main_instance.project.kb.functions
