import unittest

from libbs.api import DecompilerInterface


class TestHeadlessInterfaces(unittest.TestCase):
    def test_ghidra_interface(self):
        #deci = DecompilerInterface.discover_interface(force_decompiler="ghidra", headless=True)
        # 1. starts the headless ghidra server
        # todo: do more stuff here, like set a function name
        print("under development")
