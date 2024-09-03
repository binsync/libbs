import logging
import time
import unittest
from pathlib import Path
from collections import defaultdict
import os

from libbs.api import DecompilerInterface
from libbs.artifacts import FunctionHeader, StackVariable, Struct, GlobalVariable, Enum, Comment
from libbs.decompilers import GHIDRA_DECOMPILER
from libbs.decompilers.ghidra.testing import HeadlessGhidraDecompiler
from libbs.decompilers.ghidra.compat.transaction import Transaction
from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface

GHIDRA_HEADLESS_PATH = Path(os.environ.get('GHIDRA_INSTALL_DIR', "")) / "support" / "analyzeHeadless"
TEST_BINARY_DIR = Path(__file__).parent / "binaries"

_l = logging.getLogger(__name__)


class TestRemoteGhidra(unittest.TestCase):
    FAUXWARE_PATH = TEST_BINARY_DIR / "fauxware"

    def setUp(self):
        self.deci = None

    def tearDown(self):
        if self.deci is not None:
            self.deci.shutdown()

    def test_ghidra_artifact_watchers(self):
        with HeadlessGhidraDecompiler(self.FAUXWARE_PATH, headless_dec_path=GHIDRA_HEADLESS_PATH):
            deci: GhidraDecompilerInterface = DecompilerInterface.discover(
                force_decompiler=GHIDRA_DECOMPILER,
                binary_path=self.FAUXWARE_PATH,
                start_headless_watchers=True
            )
            self.deci = deci

            #
            # Test Artifact Watchers
            #

            hits = defaultdict(list)
            def func_hit(*args, **kwargs): hits[args[0].__class__].append(args[0])

            deci.artifact_change_callbacks = {
                typ: [func_hit] for typ in (FunctionHeader, StackVariable, Enum, Struct, GlobalVariable, Comment)
            }

            # Exact number of hits is not consistent, so we instead check for the minimum increment expected
            old_header_hits = len(hits[FunctionHeader])

            # function names
            func_addr = deci.art_lifter.lift_addr(0x400664)
            main = deci.functions[func_addr]
            main.name = "changed"
            deci.functions[func_addr] = main

            main.name = "main"
            deci.functions[func_addr] = main

            assert len(hits[FunctionHeader]) >= old_header_hits + 2
            old_header_hits = len(hits[FunctionHeader])

            # function return type
            main.header.type = 'long'
            deci.functions[func_addr] = main
            time.sleep(5)

            main.header.type = 'double'
            deci.functions[func_addr] = main
            time.sleep(5)

            # confirm the final type is correct
            new_main = deci.functions[func_addr]
            assert new_main.header.type == main.header.type

            assert len(hits[FunctionHeader]) >= old_header_hits + 2

            # global var names
            old_global_hits = len(hits[GlobalVariable])
            g1_addr = deci.art_lifter.lift_addr(0x4008e0)
            g2_addr = deci.art_lifter.lift_addr(0x601048)
            g1 = deci.global_vars[g1_addr]
            g2 = deci.global_vars[g2_addr]
            g1.name = "gvar1"
            g2.name = "gvar2"
            deci.global_vars[g1_addr] = g1
            deci.global_vars[g2_addr] = g2
            # TODO: re-enable this once we have a better way to track global variable changes
            #assert len(hits[GlobalVariable]) == old_global_hits + 2

            main.stack_vars[-24].name = "named_char_array"
            main.stack_vars[-12].name = "named_int"
            deci.functions[func_addr] = main
            # TODO: fixme: stack variable changes are not being tracked
            # first_changed_sv = hits[StackVariable][0]
            # assert first_changed_sv.name == main.stack_vars[-24].name
            # assert len(hits[StackVariable]) == 2

            # struct = deci.structs['eh_frame_hdr']
            # struct.name = "my_struct_name"
            # deci.structs['eh_frame_hdr'] = struct

            # TODO: add argument naming
            # func_args = main.header.args
            # func_args[0].name = "changed_name"
            # func_args[1].name = "changed_name2"
            # deci.functions[func_addr] = main

            # assert hits[Struct] == 2 # One change results in 2 hits because the struct is first removed and then added again.

            #
            # Test Image Base Watcher
            #

            original_base_addr = deci.binary_base_addr
            new_base_addr = 0x1000000
            # NOTE: if this code is continuously flaky, we can remove it
            with Transaction(deci.flat_api, msg="BS::test_ghidra_artifact_watchers"):
                deci.flat_api.currentProgram.setImageBase(deci.flat_api.toAddr(new_base_addr), True)

            time.sleep(0.5)
            assert deci.binary_base_addr != original_base_addr
            assert deci.binary_base_addr == new_base_addr

            deci.shutdown()


if __name__ == "__main__":
    unittest.main()
