import os
import sys
import time
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Union
import logging

from jfx_bridge.bridge import BridgedObject
from ghidra_bridge import GhidraBridge

from libbs.api import DecompilerInterface
from libbs.api.decompiler_interface import requires_decompilation
from libbs.artifacts import (
    Function, FunctionHeader, StackVariable, Comment, FunctionArgument, GlobalVariable, Struct, StructMember, Enum
)

from .artifact_lifter import GhidraArtifactLifter
from .compat.bridge import FlatAPIWrapper, connect_to_bridge, shutdown_bridge, run_until_bridge_closed, ui_remote_eval
from .compat.transaction import ghidra_transaction

_l = logging.getLogger(__name__)
bridge: Optional[GhidraBridge] = None


class GhidraDecompilerInterface(DecompilerInterface):
    CACHE_TIMEOUT = 5

    def __init__(
        self,
        flat_api=None,
        loop_on_plugin=True,
        start_headless_watchers=False,
        analyze=True,
        project_location: Optional[Union[str, Path]] = None,
        project_name: Optional[str] = None,
        **kwargs
    ):
        self.loop_on_plugin = loop_on_plugin
        self.flat_api = flat_api

        # headless-only attributes
        self._start_headless_watchers = start_headless_watchers
        self._headless_analyze = analyze
        self._headless_project_location = project_location
        self._headless_project_name = project_name
        self._project = None
        self._program = None

        # ui-only attributes
        self._data_monitor = None
        self._bridge = None

        # cachable attributes
        self._last_addr = None
        self._last_func = None
        self._binary_base_addr = None
        self._last_base_addr_access = time.time()
        self._default_pointer_size = None

        super().__init__(
            name="ghidra",
            artifact_lifter=GhidraArtifactLifter(self),
            supports_undo=True,
            **kwargs
        )

    def __del__(self):
        self.shutdown()

    def _init_gui_components(self, *args, **kwargs):
        global bridge
        self._bridge = connect_to_bridge()
        if self._bridge is None:
            raise RuntimeError("Failed to connect to Ghidra UI bridge.")

        # used for importing elsewhere
        bridge = self._bridge
        globals()["binsync_ghidra_bridge"] = self._bridge

        self.flat_api = FlatAPIWrapper()
        # XXX: yeah, this is bad naming!
        if self._start_headless_watchers:
            self.start_artifact_watchers()
        super()._init_gui_components(*args, **kwargs)

    def _shutdown_headless(self):
        if self._program is not None and self._project is not None:
            from .compat.headless import close_program
            close_program(self._program, self._project)
            self._project = None
            self._program = None

    def _init_headless_components(self, *args, **kwargs):
        if not self._binary_path.exists():
            raise FileNotFoundError(f"Binary path does not exist: {self._binary_path}")

        if os.getenv("GHIDRA_INSTALL_DIR", None) is None:
            raise RuntimeError("GHIDRA_INSTALL_DIR must be set in the environment to use Ghidra headless.")

        from .compat.headless import open_program
        flat_api, project, program = open_program(
            self._binary_path,
            analyze=self._headless_analyze,
            project_location=self._headless_project_location,
            project_name=self._headless_project_name,
        )
        if flat_api is None:
            raise RuntimeError("Failed to open program with Pyhidra")

        self.flat_api = flat_api
        self._program = program
        self._project = project

    def shutdown(self):
        super().shutdown()
        if self.headless and self._project is not None:
            self._shutdown_headless()

        if not self.headless and self._bridge is not None:
            try:
                shutdown_bridge(self._bridge)
            except Exception:
                pass
            self._bridge = None

    #
    # GUI
    #

    def start_artifact_watchers(self):
        if self.headless:
            _l.warning("Artifact watching is not supported in headless mode.")
            return

        from .hooks import create_data_monitor
        if not self._artifact_watchers_started:
            if self.flat_api is None:
                raise RuntimeError("Cannot start artifact watchers without Ghidra Bridge connection.")

            self._data_monitor = create_data_monitor(self)
            self.currentProgram.addListener(self._data_monitor)
            super().start_artifact_watchers()

    def stop_artifact_watchers(self):
        if self._artifact_watchers_started:
            self._data_monitor = None
            # TODO: generalize superclass method?
            super().stop_artifact_watchers()

    @property
    def gui_plugin(self):
        """
        TODO: fixme
        A special property to never exit this function if the remote server is running.
        This is used to standardize plugin access across all decompilers.

        WARNING: If you initialized with init_plugin=True, simply autocompleting (tab) in IPython will
        cause this to loop forever.
        """
        if self.loop_on_plugin and self._init_plugin:
            run_until_bridge_closed(self._bridge)
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
        ctx_menu_action = create_context_action(name, action_string, callback_func_wrap, category or "LibBS")
        self.flat_api.getState().getTool().addAction(ctx_menu_action)
        return True

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        answer = self._bridge.remote_eval(
            "askString(title, question)", title=title, question=question, timeout_override=-1
        )
        return answer if answer else ""

    def gui_ask_for_choice(self, question: str, choices: list, title="Plugin Question") -> str:
        answer = self._bridge.remote_eval(
            "askChoice(title, question, choices, choices[0])", title=title, question=question, choices=choices,
            timeout_override=-1
        )
        return answer if answer else ""

    def gui_active_context(self):
        active_addr = self.flat_api.currentLocation.getAddress().getOffset()
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

    @property
    def default_pointer_size(self) -> int:
        if self._default_pointer_size is None:
            self._default_pointer_size = int(self.currentProgram.getDefaultPointerSize())

        return self._default_pointer_size

    def undo(self):
        self.currentProgram.undo()

    @requires_decompilation
    def local_variable_names(self, func: Function) -> List[str]:
        symbols_by_name = self._get_local_variable_symbols(func)
        return list(name for name, _ in symbols_by_name)

    @requires_decompilation
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        symbols_by_name = {name: sym for name, sym in self._get_local_variable_symbols(func)}
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
        func_info = self.__functions()
        for addr, name, size in func_info:
            funcs[addr] = Function(
                addr=addr, size=size, header=FunctionHeader(name=name, addr=addr)
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
    def _set_stack_variables(self, svars: List[StackVariable], **kwargs) -> bool:
        from .compat.imports import SourceType
        changes = False
        if not svars:
            return changes

        first_svar = svars[0]
        func_addr = first_svar.addr
        decompilation = kwargs.get('decompilation', None) or self._ghidra_decompile(self._get_function(func_addr))
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)
        gstack_vars = self.__get_gstack_vars(ghidra_func)
        if not gstack_vars:
            return changes

        var_pairs = []
        for svar in svars:
            for gstack_var in gstack_vars:
                if svar.offset == gstack_var.getStackOffset():
                    var_pairs.append((svar, gstack_var))
                    break

        rename_pairs = []
        retype_pairs = []
        changes = False
        for svar, gstack_var in var_pairs:
            if svar.name and svar.name != gstack_var.getName():
                changes |= True
                rename_pairs.append((gstack_var, svar.name))

            if svar.type:
                parsed_type = self.typestr_to_gtype(svar.type)
                if parsed_type is not None and parsed_type != str(gstack_var.getDataType()):
                    changes |= True
                    retype_pairs.append((gstack_var, parsed_type))

        self.__set_sym_names(rename_pairs, SourceType.USER_DEFINED)
        self.__set_sym_types(retype_pairs, SourceType.USER_DEFINED)
        return changes

    def _get_stack_variable(self, addr: int, offset: int, **kwargs) -> Optional[StackVariable]:
        gstack_var = self._get_gstack_var(addr, offset)
        if gstack_var is None:
            return None

        return self._gstack_var_to_bsvar(gstack_var)

    def _stack_variables(self, func_addr: int, decompilation=None) -> Dict[int, StackVariable]:
        decompilation = decompilation or self._ghidra_decompile(self._get_nearest_function(func_addr))
        sv_info = self.__stack_variables(decompilation)
        stack_variables = {}
        for offset, name, type_, size in sv_info:
            stack_variables[offset] = StackVariable(
                stack_offset=offset, name=name, type_=type_, size=size, addr=func_addr
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
            with Transaction(self.flat_api, msg="BS::set_function_header::set_name"):
                ghidra_func.setName(fheader.name, SourceType.USER_DEFINED)
            changes = True

        # return type
        if fheader.type and decompilation is not None:
            parsed_type = self.typestr_to_gtype(fheader.type)
            if parsed_type is not None and \
                    parsed_type != str(decompilation.highFunction.getFunctionPrototype().getReturnType()):
                with Transaction(self.flat_api, msg="BS::set_function_header::set_rettype"):
                    ghidra_func.setReturnType(parsed_type, SourceType.USER_DEFINED)
                changes = True

        # args
        # TODO: Only works for function arguments passed by register
        if fheader.args and decompilation is not None:
            params = ghidra_func.getParameters()
            if len(params) == 0:
                with Transaction(self.flat_api, msg="BS::set_function_header::update_params"):
                    HighFunctionDBUtil.commitParamsToDatabase(decompilation.highFunction, True, SourceType.USER_DEFINED)

            with Transaction(self.flat_api, msg="BS::set_function_header::set_arguments"):
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

        return Struct(
            ghidra_struct.getName(), ghidra_struct.getLength(), self._struct_members_from_gstruct(ghidra_struct)
        )

    def _structs(self) -> Dict[str, Struct]:
        structs = {}
        gstructs = self.__gstructs()
        for name, gstruct in gstructs:
            structs[name] = Struct(
                name=name, size=gstruct.getLength(), members=self._struct_members_from_gstruct(gstruct)
            )

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
        # TODO: speedup needed here, see global vars for example
        comments = self._comments()
        return comments.get(addr, None)

    def _comments(self) -> Dict[int, Comment]:
        comments = {}
        funcs_code_units = self.__function_code_units()
        for code_units in funcs_code_units:
            for code_unit in code_units:
                # TODO: this could be bad if we have multiple comments at the same address (pre and eol)
                # eol comment
                eol_cmt = code_unit.getComment(0)
                if eol_cmt:
                    addr = int(code_unit.getAddress().getOffset())
                    comments[addr] = Comment(
                        addr=addr, comment=str(eol_cmt)
                    )
                # pre comment
                pre_cmt = code_unit.getComment(1)
                if pre_cmt:
                    addr = int(code_unit.getAddress().getOffset())
                    comments[addr] = Comment(
                        addr=addr, comment=str(pre_cmt), decompiled=True
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
        g_enum = self._get_ghidra_enum(name)
        if g_enum is None:
            return None

        members = {name: val for name, val in self.__get_enum_members(g_enum)}
        return Enum(name, members) if members else None

    def _enums(self) -> Dict[str, Enum]:
        enums = {}
        enums_by_name = self.__enum_names()
        for enum_name, g_enum in enums_by_name:
            members = {name: val for name, val in self.__get_enum_members(g_enum)}
            if members:
                enums[enum_name] = Enum(name=enum_name, members=members)

        return enums

    @ghidra_transaction
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs):
        from .compat.imports import RenameLabelCmd, SourceType

        changes = False
        g_gvars_info = self.__g_global_variables()
        for addr, name, sym_data, sym in g_gvars_info:
            if addr != gvar.addr:
                continue

            # we've found the global variable
            if gvar.name and gvar.name != name:
                cmd = RenameLabelCmd(sym, gvar.name, SourceType.USER_DEFINED)
                cmd.applyTo(self.currentProgram)
                changes = True

            type_str = str(sym_data.getDataType())
            if gvar.type and gvar.type != type_str:
                # TODO: set type
                pass

        return changes

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        gvars = self._global_vars(match_single_offset=addr)
        return gvars.get(addr, None)

    def _global_vars(self, match_single_offset=None, **kwargs) -> Dict[int, GlobalVariable]:
        g_gvars_info = self.__g_global_variables()
        gvars = {}
        for addr, name, sym_data, sym in g_gvars_info:
            # speed optimization for single offset lookups
            if match_single_offset is not None and match_single_offset != addr:
                continue

            type_str = str(sym_data.getDataType())
            size = int(self.currentProgram.getListing().getDataAt(sym.getAddress()).getLength()) \
                if type_str != "undefined" else self.default_pointer_size

            gvars[addr] = GlobalVariable(addr=addr, name=name, type_=type_str, size=size)

        return gvars

    #
    # Specialized print handlers
    #

    def print(self, msg, print_local=True, **kwargs):
        if print_local:
            print(msg)

        if self._bridge:
            self._bridge.remote_exec(f'print("{msg}")')

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
        return self.flat_api.currentProgram

    @ghidra_transaction
    def _update_local_variable_symbols(self, symbols: Dict["HighSymbol", Tuple[str, Optional["DataType"]]]) -> bool:
        return any([
            r is not None for r in self.__update_local_variable_symbols(symbols)
        ])

    def _get_struct_by_name(self, name: str) -> Optional["StructureDB"]:
        """
        Returns None if the struct does not exist or is not a struct.
        """
        from .compat.imports import StructureDB

        struct = self.currentProgram.getDataTypeManager().getDataType("/" + name)
        return struct if self.isinstance(struct, StructureDB) else None

    def _struct_members_from_gstruct(self, gstruct: "StructDB") -> Dict[int, StructMember]:
        gmemb_info = self.__gstruct_members(gstruct)
        members = {}
        for offset, field_name, type_, size in gmemb_info:
            name = field_name if field_name else f'field_{hex(offset)[2:]}'
            members[offset] = StructMember(name=name, offset=offset, type_=type_, size=size)

        return members

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
        gstack_vars = self.__get_gstack_vars(func)
        for var in gstack_vars:
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

    def _get_ghidra_enum(self, enum_name: str) -> Optional["EnumDB"]:
        from .compat.imports import EnumDB

        ghidra_enum = self.currentProgram.getDataTypeManager().getDataType("/" + enum_name)
        return ghidra_enum if self.isinstance(ghidra_enum, EnumDB) else None

    @staticmethod
    def isinstance(obj, cls):
        """
        A proxy self.isinstance function that can handle BridgedObjects. This is necessary because the `self.isinstance` function
        in the remote namespace will not recognize BridgedObjects as instances of classes in the local namespace.
        """
        return obj._bridge_isinstance(cls) if isinstance(obj, BridgedObject) else isinstance(obj, cls)

    #
    # Internal functions that are very dangerous
    #

    @ui_remote_eval
    def __functions(self) -> List[Tuple[int, str, int]]:
        return [
            (int(func.getEntryPoint().getOffset()), str(func.getName()), int(func.getBody().getNumAddresses()))
            for func in self.currentProgram.getFunctionManager().getFunctions(True)
        ]

    @ui_remote_eval
    def __update_local_variable_symbols(self, symbols: Dict["HighSymbol", Tuple[str, Optional["DataType"]]]) -> List:
        from .compat.imports import HighFunctionDBUtil, SourceType

        return [
            HighFunctionDBUtil.updateDBVariable(sym, updates[0], updates[1], SourceType.ANALYSIS)
            for sym, updates in symbols.items()
        ]

    @ui_remote_eval
    def _get_local_variable_symbols(self, func: Function) -> List[Tuple[str, "HighSymbol"]]:
        return [
            (sym.name, sym)
            for sym in func.dec_obj.getHighFunction().getLocalSymbolMap().getSymbols() if sym.name
        ]

    @ui_remote_eval
    def __get_gstack_vars(self, func: "GhidraFunction") -> List["LocalVariableDB"]:
        return [var for var in func.getAllVariables() if var.isStackVariable()]

    @ui_remote_eval
    def __enum_names(self) -> List[Tuple[str, "EnumDB"]]:
        from .compat.imports import EnumDB

        return [
            (dType.getPathName()[1:], dType)
            for dType in self.currentProgram.getDataTypeManager().getAllDataTypes()
            if isinstance(dType, EnumDB)
        ]

    @ui_remote_eval
    def __stack_variables(self, decompilation) -> List[Tuple[int, str, str, int]]:
        return [
            (int(sym.getStorage().getStackOffset()), str(sym.getName()), str(sym.getDataType()), int(sym.getSize()))
            for sym in decompilation.getHighFunction().getLocalSymbolMap().getSymbols()
            if sym.getStorage().isStackStorage()
        ]

    @ui_remote_eval
    def __set_sym_names(self, sym_pairs, source_type):
        return [
            sym.setName(new_name, source_type) for sym, new_name in sym_pairs
        ]

    @ui_remote_eval
    def __set_sym_types(self, sym_pairs, source_type):
        return [
            sym.setDataType(new_type, False, True, source_type) for sym, new_type in sym_pairs
        ]

    @ui_remote_eval
    def __gstruct_members(self, gstruct: "StructureDB") -> List[Tuple[int, str, str, int]]:
        return [
            (int(m.getOffset()), str(m.getFieldName()), str(m.getDataType().getName()), int(m.getLength()))
            for m in gstruct.getComponents()
        ]

    @ui_remote_eval
    def __get_enum_members(self, g_enum: "EnumDB") -> List[Tuple[str, int]]:
        return [
            (name, g_enum.getValue(name)) for name in g_enum.getNames()
        ]

    @ui_remote_eval
    def __g_global_variables(self):
        # TODO: this could be optimized more both in use and in implementation
        from .compat.imports import SymbolType

        return [
            (int(sym.getAddress().getOffset()), str(sym.getName()), self.currentProgram.getListing().getDataAt(sym.getAddress()), sym)
            for sym in self.currentProgram.getSymbolTable().getAllSymbols(True)
            if sym.getSymbolType() == SymbolType.LABEL and
            self.currentProgram.getListing().getDataAt(sym.getAddress()) and
            not self.currentProgram.getListing().getDataAt(sym.getAddress()).isStructure()
        ]

    @ui_remote_eval
    def __gstructs(self):
        return [
            (struct.getPathName()[1:], struct)
            for struct in self.currentProgram.getDataTypeManager().getAllStructures()
        ]

    @ui_remote_eval
    def __function_code_units(self):
        """
        Returns a list of code units for each function in the program.
        """
        return [
            [code_unit for code_unit in self.currentProgram.getListing().getCodeUnits(func.getBody(), True)]
            for func in self.currentProgram.getFunctionManager().getFunctions(True)
        ]

