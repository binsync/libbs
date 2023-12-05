import unittest

from libbs.api import DecompilerInterface


class TestHeadlessInterfaces(unittest.TestCase):
    def test_ghidra_interface(self):
        # TODO: Make deci headless
        deci = DecompilerInterface.discover_interface(force_decompiler="ghidra")
        main = deci.functions[0x400664]
        main.name = "main"
        deci.functions[0x400664] = main
        assert(deci.functions[0x400664].name == "main")
        main.stack_vars[-24].name = "input"
        deci.functions[0x400664] = main
        assert(deci.functions[0x400664].stack_vars[-24].name == "input")
        main.args[3].name = "key"
        deci.functions[0x400664] = main
        assert(main.args[3].name == "key")
        print("under development")
