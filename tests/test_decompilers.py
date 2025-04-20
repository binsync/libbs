import json
import logging
import tempfile
import time
import unittest
from pathlib import Path
from collections import defaultdict
import os

from libbs.api import DecompilerInterface
from libbs.artifacts import FunctionHeader, StackVariable, Struct, GlobalVariable, Enum, Comment, ArtifactFormat, \
    Decompilation, Function, StructMember, Typedef
from libbs.decompilers import IDA_DECOMPILER, ANGR_DECOMPILER, BINJA_DECOMPILER, GHIDRA_DECOMPILER
from libbs.decompilers.ghidra.testing import HeadlessGhidraDecompiler

GHIDRA_HEADLESS_PATH = Path(os.environ.get('GHIDRA_INSTALL_DIR', "")) / "support" / "analyzeHeadless"
IDA_HEADLESS_PATH = Path(os.environ.get('IDA_HEADLESS_PATH', ""))

if os.getenv("TEST_BINARIES_DIR"):
    TEST_BINARIES_DIR = Path(os.getenv("TEST_BINARIES_DIR"))
else:
    # default assumes its a git repo that is above this one
    TEST_BINARIES_DIR = Path(__file__).parent.parent.parent / "bs-artifacts" / "binaries"

assert TEST_BINARIES_DIR.exists(), f"Test binaries dir {TEST_BINARIES_DIR} does not exist"


_l = logging.getLogger(__name__)


class TestHeadlessInterfaces(unittest.TestCase):
    FAUXWARE_PATH = TEST_BINARIES_DIR / "fauxware"
    RENAMED_NAME = "binsync_main"

    def setUp(self):
        self.deci = None

    def tearDown(self):
        if self.deci is not None:
            self.deci.shutdown()

    def test_readme_example(self):
        # TODO: add angr
        for dec_name in [IDA_DECOMPILER, GHIDRA_DECOMPILER, BINJA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                binary_path=TEST_BINARIES_DIR / "posix_syscall",
            )
            self.deci = deci
            changed_addrs = set()
            # set it
            for addr in deci.functions:
                function = deci.functions[addr]
                if function.header.type == "void":
                    function.header.type = "int"
                    deci.functions[function.addr] = function
                    changed_addrs.add(function.addr)

            # now check that it really was set for AT LEAST one
            # note: this is not a guarantee that it was set for all, type setting can fail
            success = 0
            no_voids = not bool(changed_addrs)
            for addr in deci.functions:
                if addr not in changed_addrs:
                    continue

                function = deci.functions[addr]
                if function.type == "int":
                    success += 1

            assert no_voids | success > 0, "Failed to set function type for any functions"
            deci.shutdown()

    def test_getting_artifacts(self):
        # TODO: add angr
        for dec_name in [IDA_DECOMPILER, GHIDRA_DECOMPILER, BINJA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                binary_path=TEST_BINARIES_DIR / "posix_syscall",
            )
            self.deci = deci

            # list all the different artifacts
            json_strings = []
            for func in deci.functions.values():
                json_strings.append(func.dumps(fmt=ArtifactFormat.JSON))
                # verify decompilation works
                dec_func: Function = deci.functions[func.addr]
                assert dec_func is not None
                dec_json: dict = json.loads(dec_func.dumps(fmt=ArtifactFormat.JSON))
                assert dec_json.get("header", {}).get("type", None) is not None

            for struct in deci.structs.values():
                json_strings.append(struct.dumps(fmt=ArtifactFormat.JSON))
            for enum in deci.enums.values():
                json_strings.append(enum.dumps(fmt=ArtifactFormat.JSON))
            for gvar in deci.global_vars.values():
                json_strings.append(gvar.dumps(fmt=ArtifactFormat.JSON))
            for comment in deci.comments.values():
                json_strings.append(comment.dumps(fmt=ArtifactFormat.JSON))
            for typedef in deci.typedefs.values():
                json_strings.append(typedef.dumps(fmt=ArtifactFormat.JSON))

            # validate each one is not corrupted
            for json_str in json_strings:
                json.loads(json_str)

            deci.shutdown()

    def test_ghidra_types(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_name = "fdupes_ghidra"

            deci = DecompilerInterface.discover(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=TEST_BINARIES_DIR / 'fdupes',
                project_location=Path(temp_dir),
                project_name=proj_name,
            )
            self.deci = deci

            # get decompiled function 'getcrcsignatureuntil'
            func = deci.functions[0x1d66]

            # verify that the second argument is just a normal type name, and not a 'typedef ...'
            type_name, _ = deci.art_lifter.parse_scoped_type(func.header.args[1].type)
            assert type_name == "off_t"
            assert "typedef" not in func.header.args[1].type

    def test_ghidra_artifact_dependency_resolving(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            proj_name = "fdupes_ghidra"

            deci = DecompilerInterface.discover(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=TEST_BINARIES_DIR / 'fdupes',
                project_location=Path(temp_dir),
                project_name=proj_name,
            )
            self.deci = deci
            light_funcs = {addr: func for addr, func in deci.functions.items()}
            md5_process_func = deci.art_lifter.lift_addr(0x1036f4)

            # dont decompile the function to test it is decompiled on demand, however
            # a normal use case would be to decompile it first
            auth_func = light_funcs[md5_process_func]
            initial_deps = deci.get_dependencies(auth_func)
            for art in initial_deps:
                assert art is not None
                assert art.dumps(fmt=ArtifactFormat.JSON) is not None

            assert len(initial_deps) == 4
            # check the deps
            struct_cnt = 0
            typedef_cnt = 0
            for dep in initial_deps:
                if isinstance(dep, Struct):
                    struct_cnt += 1
                    assert dep.name == "md5_state_s", "Unexpected struct"
                    assert len(dep.members) == 3, "Unexpected number of members"
                elif isinstance(dep, Typedef):
                    typedef_cnt += 1
                    assert dep.name in {"md5_word_t", "md5_state_t", "md5_byte_t"}, "Unexpected typedef"
            assert struct_cnt == 1
            assert typedef_cnt == 3

            # test a case of dependency resolving where we have a func arg with a multi-defined type
            # the type in this case is '__off64_t' which is defined in types.h and DWARF
            # the correct one to be used is the one from DWARF
            func = deci.functions[0x1d66]
            deps = deci.get_dependencies(func)
            off64t_types = [d for d in deps if isinstance(d, Typedef) and d.name.endswith("__off64_t")]
            assert len(off64t_types) == 1
            off64t_type = off64t_types[0]
            assert off64t_type.scope == "DWARF"


            # TODO: right now in headless Ghidra you cant ever set structs to variable types.
            #   This is a limitation of the headless decompiler, not the API.
            # now create two structs that reference each other
            #
            # struct A {
            #     struct B *b;
            # };
            #
            # struct B {
            #   struct A *a;
            #   int size;
            # };
            #

            #struct_a = Struct(
            #    name="A",
            #    members={
            #        0: StructMember(name="b", type_="B*", offset=0, size=8)
            #    },
            #    size=8
            #)
            #struct_b = Struct(
            #    name="B",
            #    members={
            #        0: StructMember(name="a", type_="A*", offset=0, size=8),
            #        1: StructMember(name="size", type_="int", offset=8, size=4)
            #    },
            #    size=12
            #)

            ## first add the structs to the decompiler, empty, so both names can exist
            #deci.structs[struct_a.name] = Struct(name=struct_a.name, size=struct_a.size)
            #deci.structs[struct_b.name] = Struct(name=struct_b.name, size=struct_b.size)

            ## now add the members to the structs
            #deci.structs[struct_a.name] = struct_a
            #deci.structs[struct_b.name] = struct_b

            ## now change a stack variable to be of type A
            #auth_func = deci.functions[auth_func_addr]
            #auth_func.stack_vars[-24].type = "A*"
            #deci.functions[auth_func_addr] = auth_func
            ## refresh the decompilation
            #auth_func = deci.functions[auth_func_addr]

            ## now get the dependencies again
            #new_deps = deci.get_dependencies(auth_func)
            #assert len(new_deps) == 3
            deci.shutdown()

        # Test another case of dependency resolving where we have a function that looks like this:
        # 1. A custom-typed function argument (typedef)
        # 2. The typedef points to a struct
        # 3. The pointed to struct is empty
        with tempfile.TemporaryDirectory() as temp_dir:
            deci = DecompilerInterface.discover(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=TEST_BINARIES_DIR / "posix_syscall",
                project_location=Path(temp_dir),
                project_name="posix_syscall_ghidra",
            )
            self.deci = deci

            start_func = deci.functions[deci.art_lifter.lift_addr(0x100740)]
            deps = deci.get_dependencies(start_func)
            assert len(deps) == 3
            typdefs = [d for d in deps if isinstance(d, Typedef)]
            assert len(typdefs) == 1
            typdef = typdefs[0]
            assert typdef.name == "EVP_PKEY_CTX"
            type_name, type_scope = self.deci.art_lifter.parse_scoped_type(typdef.type)
            assert type_name == "evp_pkey_ctx_st"
            structs = [d for d in deps if isinstance(d, Struct)]
            assert len(structs) == 1
            struct = structs[0]
            assert struct.name == "evp_pkey_ctx_st"

            deci.shutdown()

    def test_fauxware(self):
        # TODO: add support for everyone else, but more specifically, IDA!
        #   there is a problem right now with how function args are set in IDA
        for dec_name in [GHIDRA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                binary_path=self.FAUXWARE_PATH,
            )
            self.deci = deci

            func_addr = deci.art_lifter.lift_addr(0x400664)
            main = deci.functions[func_addr]
            main.name = self.RENAMED_NAME
            deci.functions[func_addr] = main
            assert deci.functions[func_addr].name == self.RENAMED_NAME

            #
            # Structs
            #

            func_args = main.header.args
            func_args[0].name = "new_name_1"
            func_args[0].type = "int"
            func_args[0].size = 4   # set manually to avoid resetting the size in the caller
            func_args[1].name = "new_name_2"
            func_args[1].type = "double"
            func_args[1].size = 8
            deci.functions[func_addr] = main
            assert deci.functions[func_addr].header.args == func_args

            eh_hdr_struct = deci.structs['eh_frame_hdr']
            eh_hdr_struct.name = "my_struct_name"
            eh_hdr_struct.members[0].type = 'char'
            eh_hdr_struct.members[1].type = 'char'
            deci.structs['eh_frame_hdr'] = eh_hdr_struct
            updated = deci.structs[eh_hdr_struct.name]
            assert updated.name == eh_hdr_struct.name
            assert updated.members[0].type == 'char'
            assert updated.members[1].type == 'char'

            #
            # Enums
            #

            elf_dyn_tag_enum: Enum = deci.enums['ELF::Elf64_DynTag']
            elf_dyn_tag_enum.members['DT_YEET'] = elf_dyn_tag_enum.members['DT_FILTER'] + 1
            deci.enums[elf_dyn_tag_enum.name] = elf_dyn_tag_enum
            assert deci.enums[elf_dyn_tag_enum.scoped_name] == elf_dyn_tag_enum

            enum = Enum("my_enum", {"member1": 0, "member2": 1})
            deci.enums[enum.name] = enum
            assert deci.enums[enum.name] == enum

            nested_enum = Enum("nested_enum", {"field": 0, "another_field": 2, "third_field": 3}, scope="SomeEnums")
            deci.enums[nested_enum.scoped_name] = nested_enum
            assert deci.enums[nested_enum.scoped_name] == nested_enum

            #
            # Typedefs
            #

            # simple typedef
            typedef = Typedef("my_typedef", "int")
            deci.typedefs[typedef.name] = typedef
            assert deci.typedefs[typedef.name] == typedef

            # typedef to a struct
            typedef = Typedef("my_eh_frame_hdr", eh_hdr_struct.scoped_name)
            deci.typedefs[typedef.name] = typedef
            assert deci.typedefs[typedef.name] == typedef

            # typedef to an enum
            typedef = Typedef("my_elf_dyn_tag", elf_dyn_tag_enum.scoped_name)
            deci.typedefs[typedef.name] = typedef
            updated_typedef = deci.typedefs[typedef.name]
            assert updated_typedef.name == typedef.name

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
            # Test Artifact Deletion
            #

            eh_hdr_struct = deci.structs['my_struct_name']
            del deci.structs['my_struct_name']
            struct_items = deci.structs.items()
            struct_keys = [k for k, v in struct_items]
            struct_values = [v for k, v in struct_items]
            assert eh_hdr_struct.name not in struct_keys and eh_hdr_struct not in struct_values

            deci.shutdown()

    def test_ghidra_project_loading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proj_name = "posix_syscall_ghidra"
            binary_path = TEST_BINARIES_DIR / "posix_syscall"

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
        func_authenticate = deci.functions[func_addr]
        func_authenticate.name = self.RENAMED_NAME

        # test renaming a function
        deci.functions[func_addr] = func_authenticate
        assert deci.functions[func_addr].name == self.RENAMED_NAME

        # test strucr creation
        new_struct = Struct()
        new_struct.name = "my_new_struct"
        new_struct.add_struct_member('char_member', 0, 'char', 1)
        new_struct.add_struct_member('int_member', 1, 'int', 4)
        deci.structs[new_struct.name] = new_struct

        updated = deci.structs[new_struct.name]
        assert updated.name == new_struct.name
        assert updated.members[0].type == 'char'
        assert updated.members[1].type == 'int'

        # test some typedef stuff
        new_typedef = Typedef(name="my_int", type_="int")
        deci.typedefs[new_typedef.name] = new_typedef
        assert deci.typedefs[new_typedef.name] == new_typedef

        new_typedef = Typedef(name="my_int_t", type_="my_int")
        deci.typedefs[new_typedef.name] = new_typedef
        assert deci.typedefs[new_typedef.name] == new_typedef

        # test function arg change
        func_main = deci.functions[deci.art_lifter.lift_addr(0x40071d)]
        func_main.header.args[0].name = "my_arg"
        # this arg is normally char** argv, so we can retype to another pointer
        new_struct_type = new_struct.name + "*"
        func_main.header.args[1].type = new_struct_type

        deci.functions[func_main.addr] = func_main
        assert deci.functions[func_main.addr].header.args[0].name == "my_arg"
        current_struct_type = deci.functions[func_main.addr].header.args[1].type
        current_struct_type = current_struct_type.replace("struct ", "").replace(" ", "")
        assert current_struct_type == new_struct_type

        # test struct deletion
        del deci.structs[new_struct.name]
        struct_items = deci.structs.items()
        struct_keys = [k for k, v in struct_items]
        struct_values = [v for k, v in struct_items]
        assert new_struct.name not in struct_keys and new_struct not in struct_values

    def test_decompile_api(self):
        for dec_name in [IDA_DECOMPILER, BINJA_DECOMPILER, ANGR_DECOMPILER, GHIDRA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                binary_path=TEST_BINARIES_DIR / "fauxware",
            )
            self.deci = deci
            main_func_addr = deci.art_lifter.lift_addr(0x40071d)
            decompilation = deci.decompile(main_func_addr, map_lines=True)

            assert decompilation is not None, f"Decompilation failed for {dec_name}"
            assert decompilation.decompiler == deci.name
            assert decompilation.addr == main_func_addr
            assert decompilation.text is not None
            print_username_line = 'puts("Username: ");'
            assert print_username_line in decompilation.text

            line_no = [line.strip() for line in decompilation.text.splitlines()].index(print_username_line)
            assert bool(decompilation.line_map) is True

            correct_addr = deci.art_lifter.lift_addr(0x400739)
            # TODO: fix the mapping for everyone except IDA... everything is off-by-one in some way
            if dec_name == BINJA_DECOMPILER:
                line_no -= 1
            if dec_name in [GHIDRA_DECOMPILER, ANGR_DECOMPILER]:
                line_no += 1

            assert line_no in decompilation.line_map
            assert correct_addr in decompilation.line_map[line_no]

            self.deci.shutdown()

    def test_fast_function_api(self):
        for dec_name in [GHIDRA_DECOMPILER, BINJA_DECOMPILER, ANGR_DECOMPILER, IDA_DECOMPILER]:
            deci = DecompilerInterface.discover(
                force_decompiler=dec_name,
                headless=True,
                binary_path=TEST_BINARIES_DIR / "fauxware",
            )
            self.deci = deci
            main_func_addr = deci.art_lifter.lift_addr(0x40071d)
            main_func = deci.fast_get_function(main_func_addr)
            assert main_func is not None
            assert main_func.name is not None

            self.deci.shutdown()

    def test_ghidra_type_scoping(self):
        """
        Scopes help distinguish between types with the same name but different namespaces.
        In most decompilers, there is no such thing as a type scope, i.e., a type is always scoped to the global
        and the name must be unique.

        In Ghidra, however, types can be scoped to a specific category, which is a way to group types together.
        Types looks like this: `/CategoryLayer1/CategorLayery2/my_type`.
        We need to save types from Ghidra in such a way that:
        1. The scope is preserved when the type is saved, so that other Ghidra instances can load it and use it.
        2. The type can be used without the scope, i.e., the type can be used as if it was a global type.
        """
        # first use ghidra to load types from a debug sym binary
        ghidra_deci = DecompilerInterface.discover(
            force_decompiler=GHIDRA_DECOMPILER,
            headless=True,
            binary_path=TEST_BINARIES_DIR / "fauxware",
        )
        self.deci = ghidra_deci

        #
        # Typedefs
        #

        custom_type = Typedef(name="my_int", type_="int", scope="MyCategory")
        ghidra_deci.typedefs[custom_type.scoped_name] = custom_type
        assert custom_type.scope == "MyCategory"
        # use special scoped name to access the scoped type
        assert ghidra_deci.typedefs[custom_type.scoped_name] == custom_type

        # define another custom type that has no scope
        custom_type_no_scope = Typedef(name="my_int", type_="int")
        ghidra_deci.typedefs[custom_type_no_scope.name] = custom_type_no_scope
        assert custom_type_no_scope.scope is None
        # use the normal name to access the type, since it has no scope (scoped works too)
        assert ghidra_deci.typedefs[custom_type_no_scope.name] == custom_type_no_scope
        assert ghidra_deci.typedefs[custom_type_no_scope.scoped_name] == custom_type_no_scope

        # make sure both are in the lister
        all_typedefs = list(ghidra_deci.typedefs.items())
        assert (custom_type.scoped_name, custom_type) in all_typedefs
        assert (custom_type_no_scope.scoped_name, custom_type_no_scope) in all_typedefs

        #
        # Structs
        #

        custom_type = Struct(name="my_struct", size=0, scope="MyCategory")
        ghidra_deci.structs[custom_type.scoped_name] = custom_type
        assert custom_type.scope == "MyCategory"
        assert ghidra_deci.structs[custom_type.scoped_name] == custom_type

        custom_type_no_scope = Struct(name="my_struct", size=0)
        ghidra_deci.structs[custom_type_no_scope.name] = custom_type_no_scope
        assert custom_type_no_scope.scope is None
        assert ghidra_deci.structs[custom_type_no_scope.name] == custom_type_no_scope

        all_structs = list(ghidra_deci.structs.items())
        assert (custom_type.scoped_name, custom_type) in all_structs
        assert (custom_type_no_scope.scoped_name, custom_type_no_scope) in all_structs

        #
        # Enums
        #

        custom_type = Enum(name="my_enum", members={}, scope="MyCategory")
        ghidra_deci.enums[custom_type.scoped_name] = custom_type
        assert custom_type.scope == "MyCategory"
        assert ghidra_deci.enums[custom_type.scoped_name] == custom_type
        custom_type_no_scope = Enum(name="my_enum", members={})
        ghidra_deci.enums[custom_type_no_scope.name] = custom_type_no_scope
        assert custom_type_no_scope.scope is None
        assert ghidra_deci.enums[custom_type_no_scope.name] == custom_type_no_scope
        all_enums = list(ghidra_deci.enums.values())
        assert custom_type in all_enums
        assert custom_type_no_scope in all_enums

        #
        # Get dependencies check for overlapping name use
        #

        custom_type = Typedef(name="my_int", type_="int", scope="MyCategory")
        custom_type_no_scope = Typedef(name="my_int", type_="int")
        main_func = ghidra_deci.functions[0x71d]
        main_func.type = custom_type.scoped_name
        main_func.stack_vars[-0x2c].type = custom_type_no_scope.scoped_name

        # refresh the function to be sure it set
        ghidra_deci.functions[main_func.addr] = main_func
        main_func = ghidra_deci.functions[main_func.addr]

        deps = ghidra_deci.get_dependencies(main_func)
        assert len(deps) == 2

        ghidra_deci.shutdown()

    def test_ghidra_to_ida_transfer(self):
        # first use ghidra to load types from a debug sym binary
        ghidra_deci = DecompilerInterface.discover(
            force_decompiler=GHIDRA_DECOMPILER,
            headless=True,
            binary_path=TEST_BINARIES_DIR / "debug_symbol",
        )
        debug_func = ghidra_deci.functions[0x1249]
        debug_types = ghidra_deci.get_dependencies(debug_func)
        for debug_type in debug_types:
            if isinstance(debug_type, Typedef) and debug_type.name.endswith("_IO_lock_t"):
                break
        else:
            raise RuntimeError("Failed to find the expected typedef")
        ghidra_deci.shutdown()

        ida_deci = DecompilerInterface.discover(
            force_decompiler=IDA_DECOMPILER,
            headless=True,
            binary_path=TEST_BINARIES_DIR / "debug_symbol_mod_stripped",
        )
        # since this type is already native to IDA, even without symbols, we need to change the name
        debug_type.name += "_new"
        assert debug_type.name not in ida_deci.typedefs

        # now add the type to IDA
        ida_deci.typedefs[debug_type.name] = debug_type

        # verify it was added
        assert debug_type.name in ida_deci.typedefs
        ida_deci.shutdown()


if __name__ == "__main__":
    unittest.main()
