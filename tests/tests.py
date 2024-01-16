import unittest
import pathlib
import os

from libbs.api import DecompilerInterface

GHIDRA_INSTALL_DIR = os.environ.get('GHIDRA_INSTALL_DIR')
HOME_DIR = os.environ.get('HOME')

class TestHeadlessInterfaces(unittest.TestCase):
    def test_ghidra_interface(self):
        ci_headless_binary_path = GHIDRA_INSTALL_DIR + "/support/analyzeHeadless"
        fauxware_path = HOME_DIR + "/fauxware"
        deci = DecompilerInterface.discover(force_decompiler="ghidra",
                                                      headless=True,
                                                      decompiler_headless_binary_path=ci_headless_binary_path,
                                                      project_binary_path=fauxware_path
                                            )
        #main = deci.functions[0x400664]
        #main.name = "main"
        #deci.functions[0x400664] = main
        #assert deci.functions[0x400664].name == "main"
        #main.stack_vars[-24].name = "input"
        #deci.functions[0x400664] = main
        #TODO: Fix stack variables
        #assert deci.functions[0x400664].stack_vars[-24].name == "input"
        #main.args[3].name = "key"
        #deci.functions[0x400664] = main
        #assert main.args[3].name == "key"
        deci.shutdown()
        print("under development")
