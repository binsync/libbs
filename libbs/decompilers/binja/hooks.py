from collections import defaultdict
from typing import Dict

import binaryninja
from binaryninja.types import StructureType, EnumerationType
from binaryninja import SymbolType
from binaryninja.binaryview import BinaryDataNotification

import logging

from .interface import BinjaInterface
from libbs.artifacts import (
    FunctionHeader, FunctionArgument, GlobalVariable, StackVariable, Comment
)

l = logging.getLogger(__name__)


#
# Hooks (callbacks)
#

class DataMonitor(BinaryDataNotification):
    def __init__(self, view, interface):
        super().__init__()
        self._bv = view
        self._interface: BinjaInterface = interface
        self._changing_func_addr = None
        self._changing_func_pre_change = None
        self._seen_comments = defaultdict(dict)

    def function_updated(self, view, func_):
        # updates that occur without a service request are requests for comment changes
        if self._changing_func_pre_change is None:
            #
            # comments
            #

            func_addr = func_.start
            current_comments = dict(func_.comments)
            if self._seen_comments[func_addr] != current_comments:
                # comments changed
                old_comments = self._seen_comments
                new_comments = current_comments

                for addr, old_comment in old_comments.items():
                    new_comment = new_comments.get(addr, None)
                    if new_comment == old_comment:
                        continue

                    self._interface.comment_changed(
                        self._interface.art_lifter.lift(
                            Comment(
                                addr, str(new_comment) if new_comment else "", decompiled=True, func_addr=func_addr
                            )
                        )
                    )

                for addr, new_comment in new_comments.items():
                    if addr in old_comments:
                        continue

                    if new_comment:
                        self._interface.comment_changed(
                            self._interface.art_lifter.lift(
                                Comment(addr, str(new_comment), decompiled=True, func_addr=func_addr)
                            )
                        )

                self._seen_comments[func_addr] = current_comments

        # service requested function only
        if self._changing_func_pre_change is not None and self._changing_func_addr == func_.start:
            l.debug(f"Update on {hex(self._changing_func_addr)} being processed...")
            self._changing_func_addr = None

            # convert to libbs Function type for diffing
            bn_func = view.get_function_at(func_.start)
            bs_func = BinjaInterface.bn_func_to_bs(bn_func)
            current_comments = dict(bn_func.comments)

            #
            # header
            #

            # check if the headers differ
            # NOTE: function name done inside symbol update hook
            if self._changing_func_pre_change.header.diff(bs_func.header):
                old_header: FunctionHeader = self._changing_func_pre_change.header
                new_header: FunctionHeader = bs_func.header

                old_args = old_header.args or {}
                for off, old_arg in old_args.items():
                    new_arg = new_header.args.get(off, None)
                    if new_arg is None:
                        # TODO: support deleting args
                        continue

                    if old_arg == new_arg:
                        continue

                    diff_arg = FunctionArgument(off, None, None, None)
                    if old_arg.name != new_arg.name:
                        diff_arg.name = str(new_arg.name)

                    if old_arg.type != new_arg.type:
                        diff_arg.type = str(new_arg.type)

                    if old_arg.size != new_arg.size:
                        diff_arg.size = int(new_arg.size)

                    self._interface.function_header_changed(
                        self._interface.art_lifter.lift(
                            FunctionHeader(None, old_header.addr, args={off: diff_arg})
                        )
                    )

                # new func args added to header
                for off, new_arg in bs_func.args.items():
                    if off in old_args:
                        continue

                    self._interface.function_header_changed(
                        self._interface.art_lifter.lift(
                            FunctionHeader(None, old_header.addr, args={
                                    off: FunctionArgument(off, str(new_arg.name), str(new_arg.type), int(new_arg.size))
                                }
                            )
                        )
                    )

            #
            # stack vars
            #

            header_args_names = set([arg.name for arg in bs_func.header.args.values()])
            if self._changing_func_pre_change.stack_vars != bs_func.stack_vars:
                old_svs: Dict[int, StackVariable] = self._changing_func_pre_change.stack_vars
                new_svs: Dict[int, StackVariable] = bs_func.stack_vars

                for off, old_sv in old_svs.items():
                    new_sv = new_svs.get(off, None)
                    if new_sv is None or new_sv.name in header_args_names:
                        continue

                    if old_sv == new_sv:
                        continue

                    diff_sv = StackVariable(off, None, None, old_sv.size, bs_func.addr)
                    if old_sv.name != new_sv.name:
                        diff_sv.name = str(new_sv.name)

                    if old_sv.type != new_sv.type:
                        diff_sv.type = str(new_sv.type)

                    self._interface.stack_variable_changed(
                        self._interface.art_lifter.lift(diff_sv)
                    )

                for off, new_sv in new_svs.items():
                    if off in old_svs or new_sv.name in header_args_names:
                        continue

                    self._interface.stack_variable_changed(
                        self._interface.art_lifter.lift(
                            StackVariable(off, str(new_sv.name), str(new_sv.type), new_sv.size, bs_func.addr)
                        )
                    )

            self._changing_func_pre_change = None

    def function_update_requested(self, view, func):
        if self._changing_func_addr is None:
            l.debug(f"Update on {func} requested...")
            self._changing_func_addr = func.start
            self._changing_func_pre_change = BinjaInterface.bn_func_to_bs(func)
    
    def symbol_updated(self, view, sym):
        l.debug(f"Symbol update Requested on {sym}...")
        if sym.type == SymbolType.FunctionSymbol:
            l.debug(f"   -> Function Symbol")
            func = view.get_function_at(sym.address)
            bs_func = BinjaInterface.bn_func_to_bs(func)
            self._interface.function_header_changed(
                self._interface.art_lifter.lift(FunctionHeader(bs_func.name, bs_func.addr))
            )
        elif sym.type == SymbolType.DataSymbol:
            l.debug(f"   -> Data Symbol")
            var: binaryninja.DataVariable = view.get_data_var_at(sym.address)
            self._interface.global_variable_changed(
                self._interface.art_lifter.lift(
                    GlobalVariable(int(sym.address), str(var.name), type_=str(var.type), size=int(var.type.width))
                )
            )
        else:
            print(f"   -> Other Symbol: {sym.type}")
            pass

    def type_defined(self, view, name, type_):
        l.debug(f"Type Defined: {name} {type_}")
        name = str(name)
        if isinstance(type_, StructureType):
            bs_struct = BinjaInterface.bn_struct_to_bs(name, type_)
            self._interface.struct_changed(
                self._interface.art_lifter.lift(bs_struct)
            )
        elif isinstance(type_, EnumerationType):
            bs_enum = BinjaInterface.bn_enum_to_bs(name, type_)
            self._interface.enum_changed(
                self._interface.art_lifter.lift(bs_enum)
            )
