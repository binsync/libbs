import json
import logging
import tempfile
import time
import unittest
from pathlib import Path
from collections import defaultdict
import os

from libbs.api import DecompilerInterface
from libbs.artifacts import FunctionHeader, StackVariable, Struct, GlobalVariable, Enum, Comment, ArtifactFormat
from libbs.decompilers import IDA_DECOMPILER, ANGR_DECOMPILER, BINJA_DECOMPILER, GHIDRA_DECOMPILER
from libbs.decompilers.ghidra.testing import HeadlessGhidraDecompiler

GHIDRA_HEADLESS_PATH = Path(os.environ.get('GHIDRA_INSTALL_DIR', "")) / "support" / "analyzeHeadless"
IDA_HEADLESS_PATH = Path(os.environ.get('IDA_HEADLESS_PATH', ""))
TEST_BINARY_DIR = Path(__file__).parent / "binaries"
TEST_SCRIPTS_DIR = Path(__file__).parent / "scripts"
DEC_TO_HEADLESS = {
    IDA_DECOMPILER: IDA_HEADLESS_PATH,
    GHIDRA_DECOMPILER: None,
    ANGR_DECOMPILER: None,
    BINJA_DECOMPILER: None,
}

_l = logging.getLogger(__name__)


class TestHeadlessInterfaces(unittest.TestCase):
    FAUXWARE_PATH = TEST_BINARY_DIR / "fauxware"
    RENAMED_NAME = "binsync_main"

    def setUp(self):
        self.deci = None

    def tearDown(self):
        if self.deci is not None:
            self.deci.shutdown()

    def test_readme_example(self):
        # TODO: add angr, IDA
        for dec_name in [GHIDRA_DECOMPILER, BINJA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                headless_dec_path=DEC_TO_HEADLESS[dec_name],
                binary_path=TEST_BINARY_DIR / "posix_syscall",
            )
            self.deci = deci
            for addr in deci.functions:
                function = deci.functions[addr]
                if function.header.type == "void":
                    function.header.type = "int"
                    deci.functions[function.addr] = function

            deci.shutdown()

    def test_getting_artifacts(self):
        # TODO: add angr, IDA
        for dec_name in [GHIDRA_DECOMPILER, BINJA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                headless_dec_path=DEC_TO_HEADLESS[dec_name],
                binary_path=TEST_BINARY_DIR / "posix_syscall",
            )
            self.deci = deci

            # list all the different artifacts
            json_strings = []
            for func in deci.functions.values():
                json_strings.append(func.dumps(fmt=ArtifactFormat.JSON))
                # verify decompilation works
                dec_func = deci.functions[func.addr]
                assert dec_func is not None
            for struct in deci.structs.values():
                json_strings.append(struct.dumps(fmt=ArtifactFormat.JSON))
            for enum in deci.enums.values():
                json_strings.append(enum.dumps(fmt=ArtifactFormat.JSON))
            for gvar in deci.global_vars.values():
                json_strings.append(gvar.dumps(fmt=ArtifactFormat.JSON))
            for comment in deci.comments.values():
                json_strings.append(comment.dumps(fmt=ArtifactFormat.JSON))

            # validate each one is not corrupted
            for json_str in json_strings:
                json.loads(json_str)

            deci.shutdown()

    def test_ghidra_fauxware(self):
        deci = DecompilerInterface.discover(
            force_decompiler=GHIDRA_DECOMPILER,
            headless=True,
            headless_dec_path=DEC_TO_HEADLESS[GHIDRA_DECOMPILER],
            binary_path=self.FAUXWARE_PATH,
        )
        self.deci = deci

        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self.RENAMED_NAME
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self.RENAMED_NAME

        func_args = main.header.args
        func_args[0].name = "new_name_1"
        func_args[0].type = "int"
        func_args[0].size = 4   # set manually to avoid resetting the size in the caller
        func_args[1].name = "new_name_2"
        func_args[1].type = "double"
        func_args[1].size = 8
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].header.args == func_args

        struct = deci.structs['eh_frame_hdr']
        struct.name = "my_struct_name"
        struct.members[0].type = 'char'
        struct.members[1].type = 'char'
        deci.structs['eh_frame_hdr'] = struct
        updated = deci.structs[struct.name]
        assert updated.name == struct.name
        assert updated.members[0].type == 'char'
        assert updated.members[1].type == 'char'

        enum = Enum("my_enum", {"member1": 0, "member2": 1})
        deci.enums[enum.name] = enum
        assert deci.enums[enum.name] == enum

        nested_enum = Enum("SomeEnums/nested_enum", {"field": 0, "another_field": 2, "third_field": 3})
        deci.enums[nested_enum.name] = nested_enum
        assert deci.enums[nested_enum.name] == nested_enum

        # gvar_addr = deci.art_lifter.lift_addr(0x4008e0)
        # g1 = deci.global_vars[gvar_addr]
        # g1.name = "gvar1"
        # deci.global_vars[gvar_addr] = g1
        # assert deci.global_vars[gvar_addr] == g1

        stack_var = main.stack_vars[-24]
        stack_var.name = "named_char_array"
        stack_var.type = 'double'
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].stack_vars[-24] == stack_var

        #
        # Test Random APIs
        #

        func_size = deci.get_func_size(func_addr)
        assert func_size != -1

        deci.shutdown()

    def test_ghidra_project_loading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proj_name = "posix_syscall_ghidra"
            binary_path = TEST_BINARY_DIR / "posix_syscall"

            start_load = time.time()
            deci = DecompilerInterface.discover(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=binary_path,
                project_location=tmpdir,
                project_name=proj_name,
            )
            slow_load_time = time.time() - start_load
            first_funcs = list(deci.functions.values())
            deci.shutdown()

            start_load = time.time()
            # load it by just reading the project
            deci = DecompilerInterface.discover(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=binary_path,
                project_location=tmpdir,
                project_name=proj_name,
                analyze=False,
            )
            fast_load_time = time.time() - start_load
            self.deci = deci
            second_funcs = list(deci.functions.values())

            assert first_funcs == second_funcs
            assert slow_load_time > fast_load_time

    def test_angr(self):
        deci = DecompilerInterface.discover(
            force_decompiler=ANGR_DECOMPILER,
            headless=True,
            binary_path=self.FAUXWARE_PATH
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self.RENAMED_NAME
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self.RENAMED_NAME
        assert self.RENAMED_NAME in deci.main_instance.project.kb.functions

    def test_binja(self):
        deci = DecompilerInterface.discover(
            force_decompiler=BINJA_DECOMPILER,
            headless=True,
            binary_path=self.FAUXWARE_PATH
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self.RENAMED_NAME
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self.RENAMED_NAME


if __name__ == "__main__":
    unittest.main()
