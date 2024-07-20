# pylint: disable=wrong-import-position,wrong-import-order
import logging
from collections import defaultdict
from typing import Optional

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace

from libbs.artifacts import (
    StackVariable, FunctionHeader, Enum, Struct, GlobalVariable, Comment, FunctionArgument
)
from libbs.decompilers.angr.interface import AngrInterface

l = logging.getLogger(__name__)


class GenericBSAngrManagementPlugin(BasePlugin):
    def __init__(self, workspace: Workspace, interface: Optional[AngrInterface] = None, context_menu_items=None):
        super().__init__(workspace)
        # (name, action_string, callback_func, category)
        self.context_menu_items = context_menu_items or []
        if interface is None:
            from libbs.decompilers.angr.interface import AngrInterface
            self.interface = AngrInterface(workspace)
        else:
            self.interface = interface

    def teardown(self):
        pass

    #
    # Context Menus
    #

    @staticmethod
    def build_nested_structure_from_ctx_items(context_items):
        def insert(categories, action, func, node):
            if categories:
                category = categories[0]
                next_node = None
                for child in node:
                    if child[0] == category:
                        next_node = child[1]
                        break
                if not next_node:
                    next_node = []
                    node.append((category, next_node))
                insert(categories[1:], action, func, next_node)
            else:
                node.append((action, func))

        root = []
        for path, action, func in context_items:
            categories = path.strip('/').split('/')
            insert(categories, action, func, root)

        return root[0]

    def build_context_menu_node(self, node):
        """
        The context menu triggered on right-click on a node in the decompilation view.
        If used agnostic to the node type, this will always be on the context menu
        """
        try:
            func_addr = node.codegen.cfunc.addr
        except AttributeError:
            func_addr = None

        # only add the context menu items if we are in a function
        if func_addr is not None:
            # collect all the context menu items into a single list
            ctx_items = [
                (category if category else "", action_string, callback_func)
                for name, action_string, callback_func, category in self.context_menu_items
            ]
            if ctx_items:
                nested_structure = GenericBSAngrManagementPlugin.build_nested_structure_from_ctx_items(ctx_items)
                if not nested_structure[0][0]:
                    root_items = nested_structure[0][1]
                    categorized_items = nested_structure[1]
                    for item in root_items:
                        yield item
                else:
                    categorized_items = nested_structure

                yield categorized_items

    #
    #  Decompiler Hooks
    #

    # pylint: disable=unused-argument
    def handle_stack_var_renamed(self, func, offset, old_name, new_name):
        print("handle_stack_var_renamed")
        if func is None:
            return False

        decompilation = self.interface.decompile_function(func).codegen
        stack_var = self.interface.find_stack_var_in_codegen(decompilation, offset)
        print("handle_stack_var_renamed signal sent out to everyone")
        self.interface.stack_variable_changed(StackVariable(offset, new_name, None, stack_var.size, func.addr))
        return True

    # pylint: disable=unused-argument
    def handle_stack_var_retyped(self, func, offset, old_type, new_type):
        decompilation = self.interface.decompile_function(func).codegen
        stack_var = self.interface.find_stack_var_in_codegen(decompilation, offset)
        var_type = AngrInterface.stack_var_type_str(decompilation, stack_var)
        self.interface.stack_variable_changed(StackVariable(offset, stack_var.name, var_type, stack_var.size, func.addr))
        return True

    # pylint: disable=unused-argument
    def handle_func_arg_renamed(self, func, offset, old_name, new_name):
        decompilation = self.interface.decompile_function(func).codegen
        func_args = AngrInterface.func_args_as_libbs_args(decompilation)
        self.interface.function_header_changed(
            FunctionHeader(
                name=None,
                addr=func.addr,
                type_=None,
                args={
                    offset: FunctionArgument(offset=offset, name=new_name, type_=None, size=func_args[offset].size)
                },
            )
        )

        return True

    # pylint: disable=unused-argument
    def handle_func_arg_retyped(self, func, offset, old_type, new_type):
        decompilation = self.interface.decompile_function(func).codegen
        func_args = AngrInterface.func_args_as_libbs_args(decompilation)
        self.interface.function_header_changed(
            FunctionHeader(
                name=None,
                addr=func.addr,
                type_=None,
                args={
                    offset: FunctionArgument(offset=offset, name=None, type_=new_type, size=func_args[offset].size)
                },
            )
        )

        return True

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_renamed(self, address, old_name, new_name):
        self.interface.global_variable_changed(
            GlobalVariable(addr=address, name=new_name, type_=None)
        )
        return True

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_retyped(self, address, old_type, new_type):
        self.interface.global_variable_changed(
            GlobalVariable(addr=address, name=None, type_=new_type)
        )
        return True

    # pylint: disable=unused-argument
    def handle_function_renamed(self, func, old_name, new_name):
        if func is None:
            return False

        self.interface.function_header_changed(FunctionHeader(name=new_name, addr=func.addr))
        return True

    # pylint: disable=unused-argument,no-self-use
    def handle_function_retyped(self, func, old_type, new_type):
        if func is None:
            return False

        self.interface.function_header_changed(FunctionHeader(name=None, addr=func.addr, type_=new_type))
        return True

    # pylint: disable=unused-argument
    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool):
        # comments are only possible in functions in AM
        func_addr = self.interface.get_closest_function(address)
        if func_addr is None:
            return False

        self.interface.comment_changed(
            Comment(addr=address, comment=new_cmt, func_addr=func_addr, decompiled=True), deleted=not new_cmt
        )
        return True


def line_map_from_decompilation(dec):
    import ailment
    from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeWalker, CFunctionCall, CIfElse, CIfBreak

    if dec is None or dec.codegen is None:
        return None

    codegen = dec.codegen
    base_addr = dec.project.loader.main_object.image_base_delta
    if hasattr(dec, "unoptimized_ail_graph"):
        nodes = dec.unoptimized_ail_graph.nodes
    else:
        l.critical(f"You are likely using an older version of angr that has no unoptimized_ail_graph."
                   f" Using clinic_graph instead, results will be less accurate...")
        nodes = dec.clinic.cc_graph.nodes

    # get the mapping of the original AIL graph
    mapping = defaultdict(set)
    ail_node_addr_map = {
        node.addr: node for node in nodes
    }
    for addr, ail_block in ail_node_addr_map.items():
        # get instructions of this block
        try:
            vex_block = dec.project.factory.block(addr)
        except Exception:
            continue

        ail_block_stmts = [stmt for stmt in ail_block.statements if not isinstance(stmt, ailment.statement.Label)]
        if not ail_block_stmts:
            continue

        next_ail_stmt_idx = 0
        for ins_addr in vex_block.instruction_addrs:
            next_ail_stmt_addr = ail_block_stmts[next_ail_stmt_idx].ins_addr
            mapping[next_ail_stmt_addr].add(ins_addr)
            if ins_addr == next_ail_stmt_addr:
                next_ail_stmt_idx += 1
            if next_ail_stmt_idx >= len(ail_block_stmts):
                break

    # node to addr map
    ailaddr_to_addr = defaultdict(set)
    for k, v in mapping.items():
        for v_ in v:
            ailaddr_to_addr[k - base_addr].add(v_ - base_addr)

    codegen.show_externs = False
    codegen.regenerate_text()

    decompilation = codegen.text
    if not decompilation:
        return

    try:
        first_code_pos = codegen.map_pos_to_addr.items()[0][0]
    except Exception:
        return

    # map the position start to an address
    pos_addr_map = defaultdict(set)
    for start, pos_map in codegen.map_pos_to_addr.items():
        obj = pos_map.obj
        if not hasattr(obj, "tags"):
            continue

        # leads to mapping at the beginning of loops, so skip.
        # see kill.o binary for send_signals
        if isinstance(obj, CIfElse):
            continue

        ins_addr = obj.tags.get("ins_addr", None)
        if ins_addr:
            pos_addr_map[start].add(ins_addr - base_addr)

    # find every line
    line_end_pos = [i for i, x in enumerate(decompilation) if x == "\n"]
    line_to_addr = defaultdict(set)
    last_pos = len(decompilation) - 1
    line_to_addr[str(1)].add(codegen.cfunc.addr - base_addr)
    for i, pos in enumerate(line_end_pos[:-1]):
        if pos == last_pos:
            break

        curr_end = line_end_pos[i+1] - 1
        # check if this is the variable decs and header
        if curr_end < first_code_pos:
            line_to_addr[str(i+2)].add(codegen.cfunc.addr - base_addr)
            continue

        # not header, real code
        for p_idx in range(pos+1, curr_end+1):
            if p_idx in pos_addr_map:
                # line_to_addr[str(i+1)].update(pos_addr_map[p_idx])
                for ail_ins_addr in pos_addr_map[p_idx]:
                    if ail_ins_addr in ailaddr_to_addr:
                        line_to_addr[str(i+2)].update(ailaddr_to_addr[ail_ins_addr])
                    else:
                        line_to_addr[str(i+2)].add(ail_ins_addr)

    return line_to_addr
