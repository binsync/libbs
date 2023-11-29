# pylint: disable=wrong-import-position,wrong-import-order
import logging

from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.workspace import Workspace

from .interface import AngrInterface

l = logging.getLogger(__name__)


class LibBSPlugin(BasePlugin):
    """
    Controller plugin for BinSync
    """
    def __init__(self, workspace: Workspace):
        """
        The entry point for the BinSync plugin. This class is respobsible for both initializing the GUI and
        deiniting it as well. The BinSync plugin also starts the BinsyncController, which is a threaded class
        that pushes and pulls changes every so many seconds.

        @param workspace:   an AM _workspace (usually found in _instance)
        """
        super().__init__(workspace)

        # init the Sync View on load
        self.interface = AngrInterface(workspace=self.workspace)
        self.selected_funcs = []

    #
    # BinSync Deinit
    #

    def teardown(self):
        pass

    #
    #   BinSync Decompiler Hooks
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
