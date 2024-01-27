import unittest
from pathlib import Path
import os

from libbs.api import DecompilerInterface

GHIDRA_HEADLESS_PATH = Path(os.environ.get('GHIDRA_HEADLESS_PATH'))
TEST_BINARY_DIR = Path(__file__).parent / "binaries"


class TestHeadlessInterfaces(unittest.TestCase):
    def test_ghidra_interface(self):
        fauxware_path = TEST_BINARY_DIR / "fauxware"
        deci = DecompilerInterface.discover(
            force_decompiler="ghidra",
            headless=True,
            headless_dec_path=GHIDRA_HEADLESS_PATH,
            binary_path=fauxware_path
        )
        main = deci.functions[0x400664]
        main.name = "main"
        deci.functions[0x400664] = main
        assert deci.functions[0x400664].name == "main"
        deci.shutdown()
