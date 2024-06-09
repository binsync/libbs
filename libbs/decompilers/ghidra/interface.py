import os
import time
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import logging
import subprocess
import tempfile
from functools import wraps

from libbs.api import DecompilerInterface
from libbs.api.decompiler_interface import requires_decompilation
from libbs.artifacts import (
    Function, FunctionHeader, StackVariable, Comment, FunctionArgument, GlobalVariable, Struct, StructMember, Enum
)
from libbs.plugin_installer import PluginInstaller

import psutil
import pyhidra

from .artifact_lifter import GhidraArtifactLifter

_l = logging.getLogger(__name__)


def ghidra_transaction(f):
    @wraps(f)
    def _ghidra_transaction(self: "GhidraDecompilerInterface", *args, **kwargs):
        from .compat.transaction import Transaction
        with Transaction(flat_api=self.flat_api, msg=f"BS::{f.__name__}(args={args})"):
            ret_val = f(self, *args, **kwargs)

        return ret_val

    return _ghidra_transaction


class GhidraDecompilerInterface(DecompilerInterface):
    CACHE_TIMEOUT = 5

    def __init__(self, flat_api=None, loop_on_plugin=True, start_headless_watchers=False, analyze=True, **kwargs):
        self.loop_on_plugin = loop_on_plugin
        self.flat_api = flat_api

        self._start_headless_watchers = start_headless_watchers

        self._last_addr = None
        self._last_func = None
        self._binary_base_addr = None
        self._last_base_addr_access = time.time()

        self._headless_analyze = analyze
        self._pyhidra_ctx = None

        self._data_monitor = None
        super().__init__(name="ghidra", artifact_lifter=GhidraArtifactLifter(self), supports_undo=True, **kwargs)

    def __del__(self):
        self.shutdown()

    def _init_gui_components(self, *args, **kwargs):
        super()._init_gui_components(*args, **kwargs)

    def start_artifact_watchers(self):
        # TODO: fixme!
        from .hooks import create_data_monitor
        from .compat.state import get_current_program

        if not self._artifact_watchers_started:
            if self.flat_api is None:
                raise RuntimeError("Cannot start artifact watchers without Ghidra Bridge connection.")

            self._data_monitor = create_data_monitor(self)
            get_current_program().addListener(self._data_monitor)
            # TODO: generalize superclass method?
            super().start_artifact_watchers()

    def stop_artifact_watchers(self):
        if self._artifact_watchers_started:
            self._data_monitor = None
            # TODO: generalize superclass method?
            super().stop_artifact_watchers()

    def _shutdown_pyhidra_ctx(self):
        if self._pyhidra_ctx is not None:
            self._pyhidra_ctx.__exit__(None, None, None)
            self._pyhidra_ctx = None

    def _init_headless_components(self, *args, **kwargs):
        if not self._binary_path.exists():
            raise FileNotFoundError(f"Binary path does not exist: {self._binary_path}")

        self._pyhidra_ctx = pyhidra.open_program(self._binary_path, analyze=self._headless_analyze)
        self.flat_api = self._pyhidra_ctx.__enter__()
        if self.flat_api is None:
            self._shutdown_pyhidra_ctx()
            raise RuntimeError("Failed to open program with Pyhidra")

        if self._start_headless_watchers:
            self.start_artifact_watchers()

    def shutdown(self):
        super().shutdown()
        if self.headless and self._pyhidra_ctx is not None:
            self._shutdown_pyhidra_ctx()

    #
    # GUI
    #

    @property
    def gui_plugin(self):
        """
        A special property to never exit this function if the remote server is running.
        This is used to standardize plugin access across all decompilers.

        WARNING: If you initialized with init_plugin=True, simply autocompleting (tab) in IPython will
        cause this to loop forever.
        """
        if self.loop_on_plugin and self._init_plugin:
            self._run_until_server_closed()
        return None

    @gui_plugin.setter
    def gui_plugin(self, value):
        pass

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None) -> bool:
        from .hooks import create_context_action

        def callback_func_wrap(*args, **kwargs):
            try:
                callback_func(*args, **kwargs)
            except Exception as e:
                self.warning(f"Exception in ctx menu callback {name}: {e}")
                raise
        ctx_menu_action = create_context_action(self.ghidra, name, action_string, callback_func_wrap, category or "LibBS")
        self.flat_api.getState().getTool().addAction(ctx_menu_action)
        return True

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        from .compat.imports import CancelledException
        try:
            answer = self.flat_api.askString(title, question)
        except CancelledException:
            answer = None

        return answer if answer is not None else ""

    def gui_active_context(self):
        from .compat.state import get_current_address
        active_addr = get_current_address(flat_api=self.flat_api)
        if active_addr is None:
            return Function(0, 0)

        if active_addr != self._last_addr:
            self._last_addr = active_addr
            self._last_func = self._gfunc_to_bsfunc(self._get_nearest_function(active_addr))
            self._last_func.addr = self.art_lifter.lift_addr(self._last_func.addr)

        return self._last_func

    def gui_goto(self, func_addr) -> None:
        func_addr = self.art_lifter.lower_addr(func_addr)
        self.flat_api.goTo(self.flat_api.toAddr(func_addr))

    #
    # Mandatory API
    #

    @property
    def binary_base_addr(self) -> int:
        # TODO: this is a hack for a dumb cache, and can cause bugs, but good enough for now:
        if (time.time() - self._last_base_addr_access > self.CACHE_TIMEOUT) or self._binary_base_addr is None:
            self._binary_base_addr = int(self.currentProgram.getImageBase().getOffset())
            self._last_base_addr_access = time.time()

        return self._binary_base_addr

    @property
    def binary_hash(self) -> str:
        return self.currentProgram.executableMD5

    @property
    def binary_path(self) -> Optional[str]:
        return self.currentProgram.executablePath

    def get_func_size(self, func_addr) -> int:
        func_addr = self.art_lifter.lower_addr(func_addr)
        gfunc = self._get_nearest_function(func_addr)
        if gfunc is None:
            _l.critical("Failed to get function size for %s, likely a lifting error, report!", func_addr)
            return -1

        return int(gfunc.getBody().getNumAddresses())

    def _decompile(self, function: Function) -> Optional[str]:
        dec_obj = self.get_decompilation_object(function, do_lower=False)
        if dec_obj is None:
            return None

        dec_func = dec_obj.getDecompiledFunction()
        if dec_func is None:
            return None

        return str(dec_func.getC())

    def get_decompilation_object(self, function: Function, do_lower=True) -> Optional[object]:
        lowered_addr = self.art_lifter.lower_addr(function.addr) if do_lower else function.addr
        return self._ghidra_decompile(self._get_nearest_function(lowered_addr))

    #
    # Extra API
    #

    def undo(self):
        self.currentProgram.undo()

    def local_variable_names(self, func: Function) -> List[str]:
        symbols_by_name = self._get_local_variable_symbols(func)
        return list(symbols_by_name.keys())

    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        symbols_by_name = self._get_local_variable_symbols(func)
        symbols_to_update = {}
        for name, new_name in name_map.items():
            if name not in symbols_by_name or symbols_by_name[name].name == new_name or new_name in symbols_by_name:
                continue

            sym: "HighSymbol" = symbols_by_name[name]
            symbols_to_update[sym] = (new_name, None)

        return self._update_local_variable_symbols(symbols_to_update) if symbols_to_update else False

    #
    # Private Artifact API
    #

    def _set_function(self, func: Function, **kwargs) -> bool:
        decompilation = self._ghidra_decompile(self._get_nearest_function(func.addr))
        changes = super()._set_function(func, decompilation=decompilation, **kwargs)
        return changes

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        func = self._get_nearest_function(addr)
        if func is None:
            return None

        dec = self._ghidra_decompile(func)
        stack_variables = self._stack_variables(addr, decompilation=dec)
        args = self._function_args(addr, decompilation=dec)
        type_ = self._function_type(addr, decompilation=dec)
        func_addr = int(func.getEntryPoint().getOffset())
        return Function(
            addr=func_addr,
            size=int(func.getBody().getNumAddresses()),
            header=FunctionHeader(name=func.getName(), addr=func_addr, args=args, type_=type_),
            stack_vars=stack_variables, dec_obj=dec
        )

    def _functions(self) -> Dict[int, Function]:
        funcs = {}
        for func in self.currentProgram.getFunctionManager().getFunctions(True):
            addr = int(func.getEntryPoint().getOffset())
            funcs[addr] = Function(
                addr=addr, size=int(func.getBody().getNumAddresses()),
                header=FunctionHeader(name=str(func.getName()), addr=addr)
            )

        if not funcs:
            _l.warning(f"Failed to get any functions from Ghidra. Did something break?")

        return funcs

    def _function_args(self, func_addr: int, decompilation=None) -> Dict[int, FunctionArgument]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(func_addr))
        args = {}
        arg_offset = 0
        for sym in decompilation.getHighFunction().getLocalSymbolMap().getSymbols():
            if not sym.isParameter():
                continue

            args[arg_offset] = FunctionArgument(
                offset=arg_offset, name=str(sym.getName()), type_=str(sym.getDataType()), size=int(sym.getSize())
            )
            arg_offset += 1

        return args

    def _function_type(self, addr: int, decompilation=None) -> Optional[str]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(addr))
        return str(decompilation.getHighFunction().getFunctionPrototype().getReturnType().getName())

    @ghidra_transaction
    def _set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        from .compat.imports import SourceType
        changes = False
        if not svar:
            return changes

        decompilation = kwargs.get('decompilation', None) or self._ghidra_decompile(self._get_function(svar.addr))
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(svar.addr)
        gstack_var = self._get_gstack_var(ghidra_func, svar.offset)
        if not gstack_var:
            return changes

        # name
        if svar.name and svar.name != gstack_var.getName():
            gstack_var.setName(svar.name, SourceType.USER_DEFINED)
            changes = True

        # type
        if svar.type:
            parsed_type = self.typestr_to_gtype(svar.type)
            if parsed_type is not None and parsed_type != str(gstack_var.getDataType()):
                gstack_var.setDataType(parsed_type, False, True, SourceType.USER_DEFINED)
                changes = True

        return changes

    def _get_stack_variable(self, addr: int, offset: int, **kwargs) -> Optional[StackVariable]:
        gstack_var = self._get_gstack_var(addr, offset)
        if gstack_var is None:
            return None

        return self._gstack_var_to_bsvar(gstack_var)

    def _stack_variables(self, func_addr: int, decompilation=None) -> Dict[int, StackVariable]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(func_addr))
        stack_variables = {}
        for sym in decompilation.getHighFunction().getLocalSymbolMap().getSymbols():
            if not sym.getStorage().isStackStorage():
                continue

            offset = int(sym.getStorage().getStackOffset())
            stack_variables[int(sym.getStorage().getStackOffset())] = StackVariable(
                stack_offset=offset, name=str(sym.getName()), type_=str(sym.getDataType()), size=sym.getSize(),
                addr=func_addr
            )

        return stack_variables

    def _set_function_header(self, fheader: FunctionHeader, decompilation=None, **kwargs) -> bool:
        from .compat.transaction import Transaction
        from .compat.imports import SourceType, HighFunctionDBUtil

        changes = False
        func_addr = fheader.addr
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)

        # func name
        if fheader.name and fheader.name != ghidra_func.getName():
            with Transaction(msg="BS::set_function_header::set_name"):
                ghidra_func.setName(fheader.name, SourceType.USER_DEFINED)
            changes = True

        # return type
        if fheader.type and decompilation is not None:
            parsed_type = self.typestr_to_gtype(fheader.type)
            if parsed_type is not None and \
                    parsed_type != str(decompilation.highFunction.getFunctionPrototype().getReturnType()):
                with Transaction(msg="BS::set_function_header::set_rettype"):
                    ghidra_func.setReturnType(parsed_type, SourceType.USER_DEFINED)
                changes = True

        # args
        # TODO: Only works for function arguments passed by register
        if fheader.args and decompilation is not None:
            params = ghidra_func.getParameters()
            if len(params) == 0:
                with Transaction(msg="BS::set_function_header::update_params"):
                    HighFunctionDBUtil.commitParamsToDatabase(decompilation.highFunction, True, SourceType.USER_DEFINED)

            with Transaction(msg="BS::set_function_header::set_arguments"):
                for offset, param in zip(fheader.args, params):
                    arg = fheader.args[offset]
                    gtype = self.typestr_to_gtype(arg.type)
                    param.setName(arg.name, SourceType.USER_DEFINED)
                    param.setDataType(gtype, SourceType.USER_DEFINED)
            changes = True

        return changes

    @ghidra_transaction
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        from .compat.imports import DataTypeConflictHandler, StructureDataType, ByteDataType


        struct: Struct = struct
        old_ghidra_struct = self._get_struct_by_name(struct.name)
        data_manager = self.currentProgram.getDataTypeManager()
        ghidra_struct = StructureDataType(struct.name, 0)
        for offset in struct.members:
            member = struct.members[offset]
            ghidra_struct.add(ByteDataType.dataType, 1, member.name, "")
            ghidra_struct.growStructure(member.size - 1)
            for dtc in ghidra_struct.getComponents():
                if dtc.getFieldName() == member.name:
                    gtype = self.typestr_to_gtype(member.type if member.type else 'undefined' + str(member.size))
                    for i in range(offset, offset + member.size):
                        ghidra_struct.clearAtOffset(i)
                    ghidra_struct.replaceAtOffset(offset, gtype, member.size, member.name, "")
                    break
        try:
            if old_ghidra_struct is not None:
                data_manager.replaceDataType(old_ghidra_struct, ghidra_struct, True)
            else:
                data_manager.addDataType(ghidra_struct, DataTypeConflictHandler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            print(f'Error filling struct {struct.name}: {ex}')
            return False

    def _get_struct(self, name) -> Optional[Struct]:
        ghidra_struct = self._get_struct_by_name(name)
        if ghidra_struct is None:
            return None

        return Struct(ghidra_struct.getName(), ghidra_struct.getLength(), self._struct_members_from_gstruct(name))

    def _structs(self) -> Dict[str, Struct]:

        structs = {}
        for struct in self.currentProgram.getDataTypeManager().getAllStructures():
            name = struct.getPathName()[1:]
            structs[name] = Struct(name=name, size=struct.getLength(), mambers=self._struct_members_from_gstruct(name))

        return structs

    @ghidra_transaction
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        from .compat.imports import CodeUnit, SetCommentCmd


        cmt_type = CodeUnit.PRE_COMMENT if comment.decompiled else CodeUnit.EOL_COMMENT
        if comment.addr == comment.func_addr:
            cmt_type = CodeUnit.PLATE_COMMENT

        if comment.comment:
            # TODO: check if comment already exists, and append?
            return SetCommentCmd(
                self.flat_api.toAddr(comment.addr), cmt_type, comment.comment
            ).applyTo(self.currentProgram)
        return True

    def _get_comment(self, addr) -> Optional[Comment]:
        # TODO: implement me!
        return None

    def _comments(self) -> Dict[int, Comment]:


        comments = {}
        for func in self.currentProgram.getFunctionManager().getFunctions(True):
            addr_set = func.getBody()
            for codeUnit in self.currentProgram.getListing().getCodeUnits(addr_set, True):
                # TODO: this could be bad if we have multiple comments at the same address (pre and eol)
                # eol comment
                addr = int(codeUnit.address)
                if codeUnit.getComment(0):
                    comments[addr] = Comment(
                        addr=addr, comment=str(codeUnit.getComment(0))
                    )
                # pre comment
                if codeUnit.getComment(1):
                    comments[addr] = Comment(
                        addr=addr, comment=str(codeUnit.getComment(1)), decompiled=True
                    )

        return comments

    @ghidra_transaction
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        from .compat.imports import EnumDataType, CategoryPath, DataTypeConflictHandler


        corrected_enum_name = "/" + enum.name
        old_ghidra_enum = self.currentProgram.getDataTypeManager().getDataType(corrected_enum_name)
        data_manager = self.currentProgram.getDataTypeManager()

        # Parse the libbs Enum name into category path and raw enum name for proper Enum creation
        split = corrected_enum_name.split('/')
        unpathed_name = split[-1]
        category_path = '/'.join(split[:-1])
        ghidra_enum = EnumDataType(CategoryPath(category_path), unpathed_name, 4)
        for m_name, m_val in enum.members.items():
            ghidra_enum.add(m_name, m_val)

        try:
            if old_ghidra_enum:
                data_manager.replaceDataType(old_ghidra_enum, ghidra_enum, True)
            else:
                data_manager.addDataType(ghidra_enum, DataTypeConflictHandler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            print(f'Error adding enum {enum.name}: {ex}')
            return False

    def _get_enum(self, name) -> Optional[Enum]:
        is_valid_enum = self._get_ghidra_enum(name)
        if is_valid_enum is None:
            return None

        members = self._get_enum_members(name)
        return Enum(name, members) if members else None

    def _enums(self) -> Dict[str, Enum]:
        from .compat.imports import EnumDB


        enums = {}
        for dType in self.currentProgram.getDataTypeManager().getAllDataTypes():
            if not isinstance(dType, EnumDB):
                continue

            enum_name = dType.getPathName()[1:]
            if self._get_ghidra_enum(enum_name) is None:
                continue

            enums[enum_name] = Enum(name=enum_name, members=self._get_enum_members(enum_name))

        return enums

    @ghidra_transaction
    def _set_global_variable(self, var_addr, user=None, artifact=None, **kwargs):
        """
        TODO: remove me and implement me properly as setters and getters
        """
        from .compat.imports import RenameLabelCmd, SourceType


        changes = False
        global_var: GlobalVariable = artifact
        all_global_vars = self._global_vars()

        for offset, gvar in all_global_vars.items():
            if offset != var_addr:
                continue

            if global_var.name and global_var.name != gvar.name:
                sym = self.flat_api.getSymbolAt(self.flat_api.toAddr(var_addr))
                cmd = RenameLabelCmd(sym, global_var.name, SourceType.USER_DEFINED)
                cmd.applyTo(self.currentProgram)
                changes = True

            if global_var.type:
                # TODO: set type
                pass

            break

        return changes

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        """
        TODO: remove me and implement me properly as setters and getters
        """
        light_global_vars = self._global_vars()
        for offset, global_var in light_global_vars.items():
            if offset == addr:
                lst = self.currentProgram.getListing()
                g_addr = self.flat_api.toAddr(addr)
                data = lst.getDataAt(g_addr)
                if not data or data.isStructure():
                    return None
                if str(data.getDataType()) == "undefined":
                    size = self.currentProgram.getDefaultPointerSize()
                else:
                    size = data.getLength()

                global_var.size = size
                return global_var

    def _global_vars(self) -> Dict[int, GlobalVariable]:
        """
        TODO: remove me and implement me properly as setters and getters
        """
        from .compat.imports import SymbolType


        symbol_table = self.currentProgram.getSymbolTable()
        gvars = {}
        for sym in symbol_table.getAllSymbols(True):
            if sym.getSymbolType() != SymbolType.LABEL:
                continue

            addr = int(sym.getAddress().getOffset())
            gvars[addr] = GlobalVariable(addr=addr, name=str(sym.getName()))

        return gvars

    #
    # Specialized print handlers
    #

    def print(self, msg, print_local=True, **kwargs):
        # TODO: this may all be removable now
        print(msg)

    def info(self, msg: str, **kwargs):
        _l.info(msg)
        self.print(self._fmt_log_msg(msg, "INFO"), print_local=False)

    def debug(self, msg: str, **kwargs):
        _l.debug(msg)
        if _l.level >= logging.DEBUG:
            self.print(self._fmt_log_msg(msg, "DEBUG"), print_local=False)

    def warning(self, msg: str, **kwargs):
        _l.warning(msg)
        self.print(self._fmt_log_msg(msg, "WARNING"), print_local=False)

    def error(self, msg: str, **kwargs):
        _l.error(msg)
        self.print(self._fmt_log_msg(msg, "ERROR"), print_local=False)

    @staticmethod
    def _fmt_log_msg(msg: str, level: str):
        full_filepath = Path(__file__)
        log_path = str(full_filepath.with_suffix("").name)
        for part in full_filepath.parts[:-1][::-1]:
            log_path = f"{part}." + log_path
            if part == "ghidra":
                break

        return f"[{level}] | {log_path} | {msg}"

    #
    # Ghidra Specific API
    #

    @property
    def currentProgram(self):
        from .compat.state import get_current_program
        return get_current_program(flat_api=self.flat_api)

    @ghidra_transaction
    def _update_local_variable_symbols(
        self, symbols: Dict["HighSymbol", Tuple[str, Optional["DataType"]]]
    ) -> bool:
        """
        @param decompilation:
        @param symbols: of form [Symbol] = (new_name, new_type)
        """
        from .compat.imports import HighFunctionDBUtil, SourceType

        success = False
        for sym, updates in symbols.items():
            r = HighFunctionDBUtil.updateDBVariable(sym, updates[0], updates[1], SourceType.ANALYSIS)
            success |= r is not None

        return success

    @requires_decompilation
    def _get_local_variable_symbols(self, func: Function) -> Dict[str, "HighSymbol"]:
        high_func = func.dec_obj.getHighFunction()
        return {
            sym.name: sym for sym in high_func.getLocalSymbolMap().getSymbols() if sym.name
        }

    def _get_struct_by_name(self, name: str) -> Optional["StructureDB"]:
        """
        Returns None if the struct does not exist or is not a struct.
        """
        from .compat.imports import StructureDB

        struct = self.currentProgram.getDataTypeManager().getDataType("/" + name)
        return struct if isinstance(struct, StructureDB) else None

    def _struct_members_from_gstruct(self, name: str) -> Dict[int, StructMember]:
        ghidra_struct = self._get_struct_by_name(name)
        if ghidra_struct is None:
            return {}

        members: Optional[List[Tuple[str, int, str, int]]] = self.ghidra.bridge.remote_eval(
            "[(m.getFieldName(), m.getOffset(), m.getDataType().getName(), m.getLength()) if m.getFieldName() else "
            "('field_'+hex(m.getOffset())[2:], m.getOffset(), m.getDataType().getName(), m.getLength()) "
            "for m in ghidra_struct.getComponents()]",
            ghidra_struct=ghidra_struct
        )
        return {
            offset: StructMember(name, offset, typestr, size) for name, offset, typestr, size in members
        } if members else {}

    def _get_enum_members(self, name: str) -> Optional[Dict[str, int]]:
        ghidra_enum = self._get_ghidra_enum(name)
        if ghidra_enum is None:
            return {}

        name_vals: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(name, ghidra_enum.getValue(name))"
            "for name in ghidra_enum.getNames()]",
            ghidra_enum=ghidra_enum
        )
        return {name: value for name, value in name_vals} if name_vals else {}

    def _get_nearest_function(self, addr: int) -> "GhidraFunction":
        func_manager = self.currentProgram.getFunctionManager()
        return func_manager.getFunctionContaining(self.flat_api.toAddr(addr))

    def _gstack_var_to_bsvar(self, gstack_var: "LocalVariableDB"):
        if gstack_var is None:
            return None

        bs_stack_var = StackVariable(
            gstack_var.getStackOffset(),
            gstack_var.getName(),
            str(gstack_var.getDataType()),
            gstack_var.getLength(),
            gstack_var.getFunction().getEntryPoint().getOffset()  # Unsure if this is what is wanted here
        )
        return bs_stack_var

    def _gfunc_to_bsfunc(self, gfunc: "GhidraFunction"):
        if gfunc is None:
            return None

        bs_func = Function(
            addr=gfunc.getEntryPoint().getOffset(), size=gfunc.getBody().getNumAddresses(),
            header=FunctionHeader(name=gfunc.getName(), addr=gfunc.getEntryPoint().getOffset()),
        )
        return bs_func

    def _ghidra_decompile_nearest(self, addr: int) -> Optional["DecompileResult"]:
        func = self._get_nearest_function(addr)
        if func is None:
            raise RuntimeError(f"Failed to get nearest function for decompilation at {hex(addr)}")

        dec = self._ghidra_decompile(func)
        if dec is None:
            raise RuntimeError(f"Failed to decompile function at {hex(addr)}")

        return dec

    def _ghidra_decompile(self, func: "GhidraFunction") -> "DecompileResult":
        """
        TODO: this needs to be cached!
        @param func:
        @return:
        """
        from .compat.imports import DecompInterface, ConsoleTaskMonitor

        dec_interface = DecompInterface()
        dec_interface.openProgram(self.currentProgram)
        dec_results = dec_interface.decompileFunction(func, 0, ConsoleTaskMonitor())
        return dec_results

    def _get_gstack_var(self, func: "GhidraFunction", offset: int) -> Optional["LocalVariableDB"]:
        """
        @param func:
        @param offset:
        @return:
        """
        for var in func.getAllVariables():
            if not var.isStackVariable():
                continue

            if var.getStackOffset() == offset:
                return var

        return None

    def typestr_to_gtype(self, typestr: str) -> Optional["DataType"]:
        """
        typestr should look something like:
        `int` or if a struct `struct name`.

        @param typestr:
        @return:
        """
        from .compat.imports import DataTypeParser, AutoAnalysisManager

        if not typestr:
            return None

        aam = AutoAnalysisManager.getAnalysisManager(self.currentProgram)
        dt_service = aam.getDataTypeManagerService()
        dt_parser = DataTypeParser(dt_service, DataTypeParser.AllowedDataTypes.ALL)
        try:
            parsed_type = dt_parser.parse(typestr)
        except Exception as e:
            _l.warning(f"Failed to parse type string: {typestr}")
            return None

        return parsed_type

    def prototype_str_to_gtype(self, progotype_str: str) -> Optional["FunctionDefinitionDataType"]:
        """
        Strings must look like:
        'void functions1(int p1, int p2)'
        """
        from .compat.imports import CParserUtils

        if not progotype_str:
            return None

        program = self.currentProgram
        return CParserUtils.parseSignature(program, progotype_str)

    def _run_until_server_closed(self, sleep_interval=30):
        while True:
            if not self.ghidra.ping():
                break

            time.sleep(sleep_interval)

    def _get_ghidra_enum(self, enum_name: str) -> Optional["EnumDB"]:
        from .compat.imports import EnumDB

        ghidra_enum = self.currentProgram.getDataTypeManager().getDataType("/" + enum_name)
        return ghidra_enum if self.ghidra.isinstance(ghidra_enum, EnumDB) else None
