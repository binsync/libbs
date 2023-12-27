# pylint: disable=wrong-import-position,wrong-import-order
import logging
import typing

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace

if typing.TYPE_CHECKING:
    from .interface import AngrInterface

l = logging.getLogger(__name__)


class GenericBSAngrManagementPlugin(BasePlugin):
    def __init__(self, workspace: Workspace, interface: "AngrInterface", context_menu_items=None):
        super().__init__(workspace)
        # (name, action_string, callback_func, category)
        self.context_menu_items = context_menu_items or []
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
        if func is None:
            return False

        decompilation = self.interface.decompile_function(func)
        stack_var = self.interface.find_stack_var_in_codegen(decompilation, offset)
        var_type = AngrInterface.stack_var_type_str(decompilation, stack_var)
        return False

    # pylint: disable=unused-argument
    def handle_stack_var_retyped(self, func, offset, old_type, new_type):
        decompilation = self.interface.decompile_function(func)
        stack_var = self.interface.find_stack_var_in_codegen(decompilation, offset)
        return False

    # pylint: disable=unused-argument
    def handle_func_arg_renamed(self, func, offset, old_name, new_name):
        decompilation = self.interface.decompile_function(func)
        func_args = AngrInterface.func_args_as_libbs_args(decompilation)
        func_type = decompilation.cfunc.functy.returnty.c_repr()
        return False

    # pylint: disable=unused-argument
    def handle_func_arg_retyped(self, func, offset, old_type, new_type):
        decompilation = self.interface.decompile_function(func)
        func_args = AngrInterface.func_args_as_libbs_args(decompilation)
        func_type = decompilation.cfunc.functy.returnty.c_repr()
        return False

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_renamed(self, address, old_name, new_name):
        return False

    # pylint: disable=unused-argument,no-self-use
    def handle_global_var_retyped(self, address, old_type, new_type):
        return False

    # pylint: disable=unused-argument
    def handle_function_renamed(self, func, old_name, new_name):
        return False

    # pylint: disable=unused-argument,no-self-use
    def handle_function_retyped(self, func, old_type, new_type):
        return False

    # pylint: disable=unused-argument
    def handle_comment_changed(self, address, old_cmt, new_cmt, created: bool, decomp: bool):
        func_addr = self.interface.get_closest_function(address)
        return False
