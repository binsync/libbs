import unittest

from libbs.api import DecompilerInterface


class TestHeadlessInterfaces(unittest.TestCase):
    def test_ghidra_interface(self):
        # TODO: install ghidra and fauxware on ci box for testing
        ci_headless_binary_path = "/ghidra_10.4_PUBLIC/support/analyzeHeadless" # TODO: update with real path
        deci = DecompilerInterface.discover_interface(force_decompiler="ghidra",
                                                      headless=True,
                                                      headless_binary=ci_headless_binary_path,
                                                      binary="/fauxware"
                                                      )
        main = deci.functions[0x400664]
        main.name = "main"
        deci.functions[0x400664] = main
        #assert deci.functions[0x400664].name == "main"
        main.stack_vars[-24].name = "input"
        deci.functions[0x400664] = main
        #TODO: Fix stack variables
        #assert deci.functions[0x400664].stack_vars[-24].name == "input"
        main.args[3].name = "key"
        deci.functions[0x400664] = main
        #assert main.args[3].name == "key"
        deci.shutdown()
        print("under development")
