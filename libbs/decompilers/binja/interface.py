import threading
import functools
from typing import Dict, Tuple, Optional, Iterable, Any, List
import hashlib
import logging

from binaryninja import SymbolType
from binaryninjaui import (
    UIContext,
    DockContextHandler,
    UIActionHandler,
    Menu,
)
import binaryninja
from binaryninja import PluginCommand
from binaryninja import lineardisassembly
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType, InstructionTextTokenType
from binaryninja.enums import VariableSourceType
from binaryninja.types import StructureType, EnumerationType

from libbs.api.decompiler_interface import DecompilerInterface
import libbs
from libbs.data import (
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch, StructMember, FunctionArgument,
    Enum, Struct, Artifact
)

from .artifact_lifter import BinjaArtifactLifter

l = logging.getLogger(__name__)

#
# Helpers
#


def background_and_wait(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        output = [None]

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        thread = threading.Thread(target=thunk)
        thread.start()
        thread.join()

        return output[0]
    return wrapper


#
# Controller
#

class BinjaInterface(DecompilerInterface):
    def __init__(self, bv=None, **kwargs):
        self.bv: binaryninja.BinaryView = bv
        print("Initializing BinjaInterface...")
        super(BinjaInterface, self).__init__(name="binja", artifact_lifter=BinjaArtifactLifter(self), **kwargs)

    def binary_hash(self) -> str:
        hash_ = ""
        try:
            hash_ = hashlib.md5(self.bv.file.raw[:]).hexdigest()
        except Exception:
            pass

        return hash_

    def binary_path(self) -> Optional[str]:
        try:
            return self.bv.file.filename
        except Exception:
            return None

    def get_func_size(self, func_addr) -> int:
        func = self.bv.get_function_at(func_addr)
        if not func:
            return 0

        return func.highest_address - func.start

    def xrefs_to(self, artifact: Artifact) -> List[Artifact]:
        if not isinstance(artifact, Function):
            l.warning("xrefs_to is only implemented for functions.")
            return []

        function: Function = self.artifact_lifer.lower(artifact)
        if not function:
            return []

        bn_xrefs = self.bv.get_code_refs(function.addr)
        xrefs = []
        for bn_xref in bn_xrefs:
            if bn_xref.function is None:
                continue

            xrefs.append(Function(bn_xref.function.start, 0))

        return xrefs

    def get_func_containing(self, addr: int) -> Optional[Function]:
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return None

        if len(funcs) > 1:
            l.warning(f"More than one function contains the the address {addr}")

        bn_func = funcs[0]
        return self._get_function(bn_func.start)

    def _decompile(self, function: Function) -> Optional[str]:
        bv = self.bv
        if bv is None:
            print("[DAILA] Warning: was unable to collect the current BinaryView. Please report this issue.")
            return

        bn_func = self.addr_to_bn_func(bv, function.addr)
        if bn_func is None:
            return None

        settings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)
        settings.set_option(DisassemblyOption.GroupLinearDisassemblyFunctions)
        settings.set_option(DisassemblyOption.WaitForIL)

        decomp = ""
        obj = lineardisassembly.LinearViewObject.single_function_language_representation(bn_func, settings)
        cursor = obj.cursor
        while True:
            for line in cursor.lines:
                if line.type in [
                    LinearDisassemblyLineType.FunctionHeaderStartLineType,
                    LinearDisassemblyLineType.FunctionHeaderEndLineType,
                    LinearDisassemblyLineType.AnalysisWarningLineType,
                ]:
                    continue
                for i in line.contents.tokens:
                    if i.type == InstructionTextTokenType.TagToken:
                        continue

                    decomp += str(i)
                decomp += "\n"

            if not cursor.next():
                break

        return decomp

    def local_variable_names(self, func: Function) -> List[str]:
        bn_func = self.addr_to_bn_func(self.bv, func.addr)
        if bn_func is None:
            return []

        return [str(var.name) for var in bn_func.vars]

    @background_and_wait
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str]) -> bool:
        bn_func = self.addr_to_bn_func(self.bv, func.addr)
        if bn_func is None:
            return False

        lvars = {
            lvar.name: lvar for lvar in bn_func.vars if lvar.name
        }
        update = False
        for name, lvar in lvars.items():
            new_name = name_map.get(name, None)
            if new_name is None:
                continue

            lvar.name = new_name
            update |= True

        if update:
            bn_func.reanalyze()

        return update

    def get_decompilation_object(self, function: Function) -> Optional[object]:
        """
        Binary Ninja has no internal object that needs to be refreshed.
        """
        return None

    #
    # GUI API
    #

    def _init_gui_plugin(self, *args, **kwargs):
        return self

    def active_context(self):
        all_contexts = UIContext.allContexts()
        if not all_contexts:
            return None

        ctx = all_contexts[0]
        handler = ctx.contentActionHandler()
        if handler is None:
            return None

        actionContext = handler.actionContext()
        func = actionContext.function
        if func is None:
            return None

        return libbs.data.Function(
            func.start, 0, header=FunctionHeader(func.name, func.start)
        )

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        resp = binaryninja.get_text_line_input(question, title)
        return resp.decode() if resp else ""

    def register_ctx_menu_item(self, name, action_string, callback_func, category=None) -> bool:
        # TODO: this needs to have a wrapper function that passes the bv to the current controller
        # correct name, category, and action_string for Binja
        action_string = action_string.replace("/", "\\")
        category = category.replace("/", "\\") if category else ""

        PluginCommand.register_for_address(
            f"{category}\\{action_string}",
            action_string,
            callback_func,
            is_valid=self.is_bn_func
        )
        return True

    def goto_address(self, func_addr) -> None:
        self.bv.offset = func_addr

    #
    # Artifact API
    #

    # functions
    def _set_function(self, func: Function, **kwargs) -> bool:
        bn_func = self.bv.get_function_at(func.addr)
        if bn_func is None:
            return False

        return super()._set_function(func, bn_func=bn_func, **kwargs)

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        bn_func = self.bv.get_function_at(addr)
        if bn_func is None:
            return None

        return self.bn_func_to_bs(bn_func)

    def _functions(self) -> Dict[int, Function]:
        funcs = {}
        for bn_func in self.bv.functions:
            if bn_func.symbol.type != SymbolType.FunctionSymbol:
                continue

            funcs[bn_func.start] = Function(bn_func.start, bn_func.total_bytes)
            funcs[bn_func.start].name = bn_func.name

        return funcs

    # function header
    def _set_function_header(self, fheader: FunctionHeader, bn_func=None, **kwargs) -> bool:
        updates = False
        if not fheader:
            return updates

        # func name
        if fheader.name and fheader.name != bn_func.name:
            bn_func.name = fheader.name
            updates |= True

        # ret type
        if fheader.type and \
                fheader.type != bn_func.return_type.get_string_before_name():

            try:
                new_type, _ = self.bv.parse_type_string(fheader.type)
            except Exception:
                new_type = None

            if new_type is not None:
                bn_func.return_type = new_type
                updates |= True

        # parameters
        if not fheader.args:
            return updates

        # XXX: hacky prototype parsing
        prototype_tokens = [fheader.type] if fheader.type else [bn_func.return_type.get_string_before_name()]
        prototype_tokens.append("(")
        for idx, func_arg in fheader.args.items():
            prototype_tokens.append(func_arg.type)
            prototype_tokens.append(func_arg.name)
            prototype_tokens.append(",")

        if prototype_tokens[-1] == ",":
            prototype_tokens[-1] = ")"

        prototype_str = " ".join(prototype_tokens)

        try:
            bn_prototype, _ = self.bv.parse_type_string(prototype_str)
        except Exception:
            bn_prototype = None

        if bn_prototype is not None:
            bn_func.type = bn_prototype
            updates |= True

        return updates

    # stack vars
    def _set_stack_variable(self, svar: StackVariable, bn_func=None, **kwargs) -> bool:
        updates = False
        existing_stack_vars: Dict[int, Any] = {
            v.storage: v for v in bn_func.stack_layout
            if v.source_type == VariableSourceType.StackVariableSourceType
        }

        bn_offset = svar.offset
        if bn_offset in existing_stack_vars:
            if existing_stack_vars[bn_offset].name != svar.name:
                existing_stack_vars[bn_offset].name = svar.name

            try:
                type_, _ = self.bv.parse_type_string(svar.type)
            except Exception:
                type_ = None

            if type_ is not None:
                if existing_stack_vars[bn_offset].type != type_:
                    existing_stack_vars[bn_offset].type = type_
                try:
                    bn_func.create_user_stack_var(bn_offset, type_, svar.name)
                    bn_func.create_auto_stack_var(bn_offset, type_, svar.name)
                except Exception as e:
                    l.warning(f"BinSync could not sync stack variable at offset {bn_offset}: {e}")

                updates |= True

        return updates

    # global variables
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs) -> bool:
        bn_gvar = self.bv.get_data_var_at(gvar.addr)
        global_type = self.bv.parse_type_string(gvar.type)
        changed = False

        if bn_gvar is None:
            bn_gvar = self.bv.define_user_data_var(gvar.addr, global_type, gvar.name)
            changed = True

        if bn_gvar:
            self.bv.define_user_data_var(gvar.addr, global_type, gvar.name)
            changed = True

        return changed

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        bn_gvar = self.bv.get_data_var_at(addr)
        if bn_gvar is None:
            return None

        return GlobalVariable(
            addr,
            self.bv.get_symbol_at(addr) or f"data_{addr:x}",
            type_=str(bn_gvar.type) if bn_gvar.type is not None else None,
            size=bn_gvar.type.width
        )

    def _global_vars(self) -> Dict[int, GlobalVariable]:
        return {
            addr: GlobalVariable(addr, var.name or f"data_{addr:x}")
            for addr, var in self.bv.data_vars.items()
        }

    # structs
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        if header:
            self.bv.define_user_type(struct.name, binaryninja.Type.structure())

        if members:
            # this scope assumes that the type is now defined... if it's not we will error
            with binaryninja.Type.builder(self.bv, struct.name) as s:
                s.width = struct.size
                members = list()
                for offset in sorted(struct.members.keys()):
                    bs_memb = struct.members[offset]
                    try:
                        bn_type = self.bv.parse_type_string(bs_memb.type)[0] if bs_memb.type else None
                    except Exception:
                        bn_type = None
                    finally:
                        if bn_type is None:
                            bn_type = binaryninja.Type.int(bs_memb.size)

                    members.append((bn_type, bs_memb.name))

                s.members = members

        return True

    def _get_struct(self, name) -> Optional[Struct]:
        bn_struct = self.bv.types.get(name, None)
        if bn_struct is None or not isinstance(bn_struct, StructureType):
            return None

        return self.bn_struct_to_bs(name, bn_struct)

    def _structs(self) -> Dict[str, Struct]:
        return {
            name: Struct(''.join(name.name), t.width, {}) for name, t in self.bv.types.items()
            if isinstance(t, StructureType)
        }

    # enums
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        bn_members = list(enum.members.items())
        new_type = binaryninja.TypeBuilder.enumeration(self.bv.arch, bn_members)
        self.bv.define_user_type(enum.name, new_type)
        return True

    def _get_enum(self, name) -> Optional[Enum]:
        bn_enum = self.bv.types.get(name, None)
        if bn_enum is None:
            return None

        if isinstance(bn_enum, EnumerationType):
            return self.bn_enum_to_bs(name, bn_enum)

        return None

    def _enums(self) -> Dict[str, Enum]:
        return {
            name: self.bn_enum_to_bs(''.join(name.name), t) for name, t in self.bv.types.items()
            if isinstance(t, EnumerationType)
        }

    # patches
    def _set_patch(self, patch: Patch, **kwargs) -> bool:
        l.warning(f"Patch setting is unimplemented in Binja")
        return False

    def _get_patch(self, addr) -> Optional[Patch]:
        l.warning(f"Patch getting is unimplemented in Binja")
        return None

    def _patches(self) -> Dict[int, Patch]:
        l.warning(f"Patch listing is unimplemented in Binja")
        return {}

    # comments
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        # search for the right function
        libbs_func = self.get_func_containing(comment.addr)
        if libbs_func is None:
            # in the case of the function not existing, just comment in addr space
            self.bv.set_comment_at(comment.addr, comment.comment)
            return True

        # func exists for commenting
        bn_func = self.addr_to_bn_func(self.bv, comment.addr)
        bn_func.set_comment_at(comment.addr, comment.comment)

    def _get_comment(self, addr) -> Optional[Comment]:
        non_func_cmt = self.bv.get_comment_at(addr)
        if non_func_cmt:
            return Comment(addr, non_func_cmt)

        # search for the right function
        funcs = self.bv.get_functions_containing(addr)
        if not funcs:
            return None

        bn_func = funcs[0]

        for _addr, cmt in bn_func.comments.items():
            if addr == _addr:
                return Comment(
                    addr,
                    cmt,
                    func_addr=bn_func.start,
                    decompiled=True
                )

        return None

    def _comments(self) -> Dict[int, Comment]:
        # search every single function for comments
        comments = {}
        for bn_func in self.bv.functions:
            if bn_func.symbol.type != SymbolType.FunctionSymbol:
                continue

            comments.update(bn_func.comments)

        # TODO: show non-function based comments
        return comments

    #
    # Helper converter functions
    #

    @staticmethod
    def bn_struct_to_bs(name, bn_struct):
        members = {
            member.offset: StructMember(str(member.name), member.offset, str(member.type), member.type.width)
            for member in bn_struct.members if member.offset is not None
        }

        return Struct(
            str(name),
            bn_struct.width if bn_struct.width is not None else 0,
            members
        )

    @staticmethod
    def bn_func_to_bs(bn_func):
        #
        # header: name, ret type, args
        #

        args = {
            i: FunctionArgument(i, parameter.name, parameter.type.get_string_before_name(), parameter.type.width)
            for i, parameter in enumerate(bn_func.parameter_vars)
        }

        sync_header = FunctionHeader(
            bn_func.name,
            bn_func.start,
            type_=bn_func.return_type.get_string_before_name(),
            args=args
        )

        #
        # stack vars
        #

        binja_stack_vars = {
            v.storage: v for v in bn_func.stack_layout if v.source_type == VariableSourceType.StackVariableSourceType
        }
        sorted_stack = sorted(bn_func.stack_layout, key=lambda x: x.storage)
        var_sizes = {}

        for off, var in binja_stack_vars.items():
            i = sorted_stack.index(var)
            if i + 1 >= len(sorted_stack):
                var_sizes[var] = 0
            else:
                var_sizes[var] = var.storage - sorted_stack[i].storage

        bs_stack_vars = {
            off: libbs.data.StackVariable(
                off,
                var.name,
                var.type.get_string_before_name(),
                var_sizes[var],
                bn_func.start
            )
            for off, var in binja_stack_vars.items()
        }

        try:
            size = bn_func.highest_address - bn_func.start
        except Exception as e:
            size = 0
            l.critical(f"Failed to grab the size of function because {e}. It's possible the function "
                       f"is not yet known to Binary Ninja.")

        return Function(bn_func.start, size, header=sync_header, stack_vars=bs_stack_vars)

    @staticmethod
    def bn_enum_to_bs(name: str, bn_enum: binaryninja.EnumerationType):
        members = {}

        for enum_member in bn_enum.members:
            if isinstance(enum_member, binaryninja.EnumerationMember) and isinstance(enum_member.value, int):
                members[enum_member.name] = enum_member.value

        return Enum(name, members)

    @staticmethod
    def addr_to_bn_func(bv, address):
        funcs = bv.get_functions_containing(address)
        try:
            func = funcs[0]
        except IndexError:
            return None

        return func

    def is_bn_func(self, bv, address):
        # HACK: update the BV whenever this is used in a context menu
        self.bv = bv
        func = self.addr_to_bn_func(bv, address)
        return func is not None
