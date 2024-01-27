import unittest
from pathlib import Path
import os

from libbs.api import DecompilerInterface

GHIDRA_HEADLESS_PATH = Path(os.environ.get('GHIDRA_HEADLESS_PATH'))
TEST_BINARY_DIR = Path(__file__).parent / "binaries"


class TestHeadlessInterfaces(unittest.TestCase):
    def test_ghidra(self):
        fauxware_path = TEST_BINARY_DIR / "fauxware"
        deci = DecompilerInterface.discover(
            force_decompiler="ghidra",
            headless=True,
            headless_dec_path=GHIDRA_HEADLESS_PATH,
            binary_path=fauxware_path
        )
        main = deci.functions[0x400664]
        main.name = "binsync_main"
        deci.functions[0x400664] = main
        assert deci.functions[0x400664].name == "binsync_main"
        deci.shutdown()

    def test_angr(self):
        fauxware_path = TEST_BINARY_DIR / "fauxware"
        deci = DecompilerInterface.discover(
            force_decompiler="angr",
            headless=True,
            binary_path=fauxware_path
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        new_name = "binsync_main"
        main = deci.functions[func_addr]
        main.name = new_name
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == new_name
        # good redudancy: verify internal angr sees the change
        assert deci.main_instance.project.kb.functions[new_name]
