import sys
import json

import unittest

from libbs.artifacts import (
    FunctionHeader, StackVariable, FunctionArgument, Function
)


class TestArtifacts(unittest.TestCase):
    def test_func_diffing(self):
        # setup top
        func_addr = 0x400000
        fh1 = FunctionHeader("main", func_addr, type_="int *", args={
            0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "long", 8)
        })
        fh2 = FunctionHeader("binsync_main", func_addr, type_="long *", args={
            0: FunctionArgument(0, "a1", "int", 4), 1: FunctionArgument(1, "a2", "int", 4)
        })

        stack_vars1 = {
            0x0: StackVariable(0, "v0", "int", 4, func_addr),
            0x4: StackVariable(4, "v4", "int", 4, func_addr)
        }
        stack_vars2 = {
            0x0: StackVariable(0, "v0", "int", 4, func_addr),
            0x4: StackVariable(4, "v4", "long", 8, func_addr),
            0x8: StackVariable(8, "v8", "long", 8, func_addr)
        }

        func1 = Function(func_addr, 0x100, header=fh1, stack_vars=stack_vars1)
        func2 = Function(func_addr, 0x150, header=fh2, stack_vars=stack_vars2)

        diff_dict = func1.diff(func2)
        header_diff = diff_dict["header"]
        vars_diff = diff_dict["stack_vars"]

        # size should not match
        assert func1.size != func2.size
        assert diff_dict["size"]["before"] == func1.size
        assert diff_dict["size"]["after"] == func2.size

        # names should not match
        assert header_diff["name"]["before"] == func1.name
        assert header_diff["name"]["after"] == func2.name

        # arg1 should match
        assert not header_diff["args"][0]

        # arg2 should not match
        assert header_diff["args"][1]["type"]["before"] != header_diff["args"][1]["type"]["after"]

        # v4 and v8 should differ
        offsets = [0, 4, 8]
        for off in offsets:
            var_diff = vars_diff[off]
            if off == 0:
                assert not var_diff
            if off == 0x4:
                assert var_diff["size"]["before"] != var_diff["size"]["after"]
            elif off == 0x8:
                assert var_diff["addr"]["before"] is None
                assert var_diff["addr"]["after"] == func1.addr

        print(json.dumps(diff_dict, sort_keys=False, indent=4))

    def test_func_nonconflict_merge(self):
        # setup top
        func_addr = 0x400000
        fh1 = FunctionHeader("user1_func", func_addr, type_="int *", args={})
        fh2 = FunctionHeader("main", func_addr, type_="long *", args={})

        stack_vars1 = {
            0x0: StackVariable(0, "v0", "int", 4, func_addr),
            0x4: StackVariable(4, "my_var", "int", 4, func_addr)
        }
        stack_vars2 = {
            0x0: StackVariable(0, "v0", "int", 4, func_addr),
            0x4: StackVariable(4, "v4", "long", 8, func_addr),
            0x8: StackVariable(8, "v8", "long", 8, func_addr)
        }

        func1 = Function(func_addr, 0x100, header=fh1, stack_vars=stack_vars1)
        func2 = Function(func_addr, 0x100, header=fh2, stack_vars=stack_vars2)
        merge_func = func1.nonconflict_merge(func2)

        assert merge_func.name == "user1_func"
        assert merge_func.header.type == "int *"
        assert merge_func.stack_vars[0].name == "v0"
        assert merge_func.stack_vars[4].name == "my_var"
        assert merge_func.stack_vars[4].type == "int"
        assert merge_func.stack_vars[8].name == "v8"

    def test_func_overwrite_merge(self):
        func_addr = 0x400000
        func_size = 0x100
        fh1 = FunctionHeader("main", func_addr, type_="int *", args={
            0: FunctionArgument(0, "a1", "int", 4)
        })
        fh2 = FunctionHeader("binsync_main", func_addr, type_="long *", args={
            1: FunctionArgument(1, "bs_2", "int", 4)
        })

        stack_vars1 = {
            0x0: StackVariable(0, "v0", "int", 4, func_addr),
            0x4: StackVariable(4, "v4", "long", 8, func_addr),
            0x8: StackVariable(8, "v8", "long", 8, func_addr)
        }
        stack_vars2 = {
            0x0: StackVariable(0, "v0", "long", 4, func_addr),
            0x4: StackVariable(4, "my_var", "int", 4, func_addr)
        }

        func1 = Function(func_addr, func_size, header=fh1, stack_vars=stack_vars1)
        func2 = Function(func_addr, func_size, header=fh2, stack_vars=stack_vars2)

        merge_func = func1.overwrite_merge(func2)

        assert merge_func.size == func1.size == func2.size
        assert merge_func.name == func2.name
        assert merge_func.header.args[0].name == func1.header.args[0].name
        assert merge_func.stack_vars[0].name == stack_vars1[0].name
        assert merge_func.stack_vars[0].type == stack_vars2[0].type
        assert merge_func.stack_vars[0x4] == stack_vars2[0x4]
        assert merge_func.stack_vars[0x8] == stack_vars1[0x8]


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
