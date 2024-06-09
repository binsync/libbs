import json
import unittest
from pathlib import Path
from collections import defaultdict
import os

from libbs.api import DecompilerInterface
from libbs.artifacts import FunctionHeader, StackVariable, Struct, GlobalVariable, Enum, Comment, ArtifactFormat
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
        self._fauxware_path = TEST_BINARY_DIR / "fauxware"

    def test_setting_and_listing_arts(self):
        """
        TODO: Add angr an IDA
        """
        for dec_name in [BINJA_DECOMPILER, GHIDRA_DECOMPILER]:
            # the direct example from the README:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                headless_dec_path=DEC_TO_HEADLESS[dec_name],
                binary_path=TEST_BINARY_DIR / "posix_syscall",
            )
            for addr in deci.functions:
                function = deci.functions[addr]
                if function.header.type == "void":
                    function.header.type = "int"
                    deci.functions[function.addr] = function

            # list all the different artifacts
            json_strings = []
            for func in deci.functions.values():
                json_strings.append(func.dumps(fmt=ArtifactFormat.JSON))
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

    def test_ghidra(self):
        # useful command for testing, kills all Headless-Ghidra:
        # kill $(ps aux | grep 'Ghidra-Headless' | awk '{print $2}')
        deci = DecompilerInterface.discover(
            force_decompiler=GHIDRA_DECOMPILER,
            headless=True,
            headless_dec_path=DEC_TO_HEADLESS[GHIDRA_DECOMPILER],
            binary_path=self._fauxware_path,
            start_headless_watchers=True
        )

        #
        # Test Artifact Reading & Writing
        #

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

        struct = deci.structs['eh_frame_hdr']
        struct.name = "my_struct_name"
        struct.members[0].type = 'undefined'
        struct.members[1].type = 'undefined'
        deci.structs['eh_frame_hdr'] = struct
        updated = deci.structs[struct.name]
        assert updated.name == struct.name
        assert updated.members[0].type == 'undefined'
        assert updated.members[1].type == 'undefined'

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

        #
        # Test Artifact Watchers
        #

        hits = defaultdict(list)
        def func_hit(*args, **kwargs): hits[args[0].__class__].append(args[0])

        deci.artifact_write_callbacks = {
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

        first_changed_func = hits[FunctionHeader][0]
        assert len(hits[FunctionHeader]) >= old_header_hits + 2
        old_header_hits = len(hits[FunctionHeader])

        # global var names
        # TODO: The gvar test cant function until gvar setting is fixed
        old_global_hits = len(hits[GlobalVariable])
        g1_addr = deci.art_lifter.lift_addr(0x4008e0)
        g2_addr = deci.art_lifter.lift_addr(0x601048)
        g1 = deci.global_vars[g1_addr]
        g2 = deci.global_vars[g2_addr]
        g1.name = "gvar1"
        g2.name = "gvar2"
        deci.global_vars[g1_addr] = g1
        deci.global_vars[g2_addr] = g2
        # assert len(hits[GlobalVariable]) == old_global_hits + 2

        # function return type
        main.header.type = 'long'
        deci.functions[func_addr] = main

        main.header.type = 'double'
        deci.functions[func_addr] = main

        assert len(hits[FunctionHeader]) >= old_header_hits + 2

        # TODO: Fix CI for below
        main.stack_vars[-24].name = "named_char_array"
        main.stack_vars[-12].name = "named_int"
        deci.functions[func_addr] = main
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

        #assert hits[Struct] == 2 # One change results in 2 hits because the struct is first removed and then added again.

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

    def test_binja(self):
        deci = DecompilerInterface.discover(
            force_decompiler=BINJA_DECOMPILER,
            headless=True,
            binary_path=self._fauxware_path
        )
        func_addr = deci.art_lifter.lift_addr(0x400664)
        main = deci.functions[func_addr]
        main.name = self._generic_renamed_name
        deci.functions[func_addr] = main
        assert deci.functions[func_addr].name == self._generic_renamed_name

if __name__ == "__main__":
    unittest.main()
