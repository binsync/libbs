import re

from binaryninjaui import (
    UIContext,
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
)
import binaryninja
from binaryninja import PluginCommand
from binaryninja.types import StructureType, EnumerationType
from binaryninja import SymbolType
from binaryninja.binaryview import BinaryDataNotification

from collections import defaultdict
import logging

from .interface import BinjaInterface
from binsync.data import (
    Artifact,
    Function, FunctionHeader, FunctionArgument, Comment, GlobalVariable, Enum, StructMember
)

l = logging.getLogger(__name__)


#
# Hooks (callbacks)
#

class DataMonitor(BinaryDataNotification):
    def __init__(self, view, interface):
        super().__init__()
        self._view = view
        self._interface = interface
        self._func_addr_requested = None
        self._func_before_change = None

    def function_updated(self, view, func_):
        if self._interface.sync_lock.locked() or self._func_before_change is None:
            # TODO: add support for creating functions here
            return

        # service requested function only
        if self._func_addr_requested == func_.start:
            l.debug(f"Update on {hex(self._func_addr_requested)} being processed...")
            self._func_addr_requested = None

            # convert to libbs Function type for diffing
            bn_func = view.get_function_at(func_.start)
            bs_func = BinjaInterface.bn_func_to_bs(bn_func)

            #
            # header
            # NOTE: function name done inside symbol update hook
            #

            # check if the headers differ
            if self._func_before_change.header.diff(bs_func.header):
                self._interface.schedule_job(
                    self._interface.push_artifact,
                    bs_func.header
                )
                
            #
            # stack vars
            #

            for off, var in self._func_before_change.stack_vars.items():
                if off in bs_func.stack_vars and var != bs_func.stack_vars[off]:
                    new_var = bs_func.stack_vars[off]
                    if re.match(r"var_\d+[_\d+]{0,1}", new_var.name) \
                            or new_var.name in {'__saved_rbp', '__return_addr',}:
                        continue

                    self._interface.schedule_job(
                        self._interface.push_artifact,
                        new_var
                    )

            self._func_before_change = None

    def function_update_requested(self, view, func):
        if not self._interface.sync_lock.locked() and self._func_addr_requested is None:
            l.debug(f"Update on {func} requested...")
            self._func_addr_requested = func.start
            self._func_before_change = BinjaInterface.bn_func_to_bs(func)
    
    def symbol_updated(self, view, sym):
        if self._interface.sync_lock.locked():
            return

        l.debug(f"Symbol update Requested on {sym}...")
        if sym.type == SymbolType.FunctionSymbol:
            l.debug(f"   -> Function Symbol")
            func = view.get_function_at(sym.address)
            bs_func = BinjaInterface.bn_func_to_bs(func)
            self._interface.schedule_job(
                self._interface.push_artifact,
                FunctionHeader(sym.name, sym.address, type_=bs_func.header.type, args=bs_func.header.args)
            )
        elif sym.type == SymbolType.DataSymbol:
            l.debug(f"   -> Data Symbol")
            var: binaryninja.DataVariable = view.get_data_var_at(sym.address)
            
            self._interface.schedule_job(
                self._interface.push_artifact,
                GlobalVariable(var.address, var.name, type_=str(var.type), size=var.type.width)
            )
        else:
            l.debug(f"   -> Other Symbol: {sym.type}")
            pass

    def type_defined(self, view, name, type_):
        l.debug(f"Type Defined: {name} {type_}")
        name = str(name)
        if self._interface.sync_lock.locked():
            return 
        
        if isinstance(type_, StructureType):
            bs_struct = BinjaInterface.bn_struct_to_bs(name, type_)
            self._interface.schedule_job(
                self._interface.push_artifact,
                bs_struct
            )

        elif isinstance(type_, EnumerationType):
            bs_enum = BinjaInterface.bn_enum_to_bs(name, type_)
            self._interface.schedule_job(self._interface.push_artifact, bs_enum)


def start_data_monitor(view, controller):
    notification = DataMonitor(view, controller)
    view.register_notification(notification)
