import time
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import logging
from functools import wraps

from libbs.api import DecompilerInterface
from libbs.api.decompiler_interface import requires_decompilation
from libbs.data import (
    Function, FunctionHeader, StackVariable, Comment, FunctionArgument, GlobalVariable, Struct, StructMember, Enum
)

from .artifact_lifter import GhidraArtifactLifter
from .ghidra_api import GhidraAPIWrapper
from .hooks import create_context_action

_l = logging.getLogger(__name__)


def ghidra_transaction(f):
    @wraps(f)
    def _ghidra_transaction(self, *args, **kwargs):
        trans_name = f"{f.__name__}(args={args})"
        trans_id = self.ghidra.currentProgram.startTransaction(trans_name)
        ret_val = None
        try:
            ret_val = f(self, *args, **kwargs)
        except Exception as e:
            self.warning(f"Failed to do Ghidra Transaction {trans_name} because {e}")
        finally:
            self.ghidra.currentProgram.endTransaction(trans_id, True)

        return ret_val

    return _ghidra_transaction


class GhidraDecompilerInterface(DecompilerInterface):
    def __init__(self, loop_on_plugin=True, **kwargs):
        self.ghidra: Optional[GhidraAPIWrapper] = None
        super().__init__(name="ghidra", artifact_lifter=GhidraArtifactLifter(self), supports_undo=True, **kwargs)

        self._last_addr = None
        self._last_func = None
        self.base_addr = None

        self.loop_on_plugin = loop_on_plugin

    #
    # Controller API
    #

    def binary_hash(self) -> str:
        return self.ghidra.currentProgram.executableMD5

    def binary_path(self) -> Optional[str]:
        return self.ghidra.currentProgram.executablePath

    def get_func_size(self, func_addr) -> int:
        gfunc = self._get_nearest_function(func_addr)
        return int(gfunc.getBody().getNumAddresses())

    def rebase_addr(self, addr, up=True):
        if self.base_addr is None:
            self.base_addr = self.ghidra.base_addr

        if up:
            if addr > self.base_addr:
                return
            return addr + self.base_addr
        elif addr > self.base_addr:
            return addr - self.base_addr

    def connect_ghidra_bridge(self):
        self.ghidra = GhidraAPIWrapper(self)
        return self.ghidra.connected

    def decompile(self, addr: int) -> Optional[str]:
        # TODO: allow the super to do this again
        function = self.functions[addr]
        return self._decompile(function)

    def _decompile(self, function: Function) -> Optional[str]:
        dec_obj = self.get_decompilation_object(function)
        if dec_obj is None:
            return None

        dec_func = dec_obj.getDecompiledFunction()
        if dec_func is None:
            return None

        return str(dec_func.getC())

    def get_decompilation_object(self, function: Function) -> Optional[object]:
        return self._ghidra_decompile(self._get_nearest_function(function.addr))

    #
    # GUI API
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

    def _init_ui_components(self, *args, **kwargs):
        if not self.connect_ghidra_bridge():
            raise Exception("Failed to connect to remote Ghidra Bridge. Did you start it first?")
        super()._init_ui_components(*args, **kwargs)

    def register_ctx_menu_item(self, name, action_string, callback_func, category=None) -> bool:
        ctx_menu_action = create_context_action(self.ghidra, name, action_string, callback_func, category or "LibBS")
        self.ghidra.getState().getTool().addAction(ctx_menu_action)
        return True

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        answer = self.ghidra.bridge.remote_eval(
            "askString(title, question)", title=title, question=question, timeout_override=-1
        )
        return answer if answer else ""

    def active_context(self):
        active_addr = self.ghidra.currentLocation.getAddress().getOffset()
        if active_addr is None:
            return Function(0, 0)

        if active_addr != self._last_addr:
            self._last_addr = active_addr
            self._last_func = self._gfunc_to_bsfunc(self._get_nearest_function(active_addr))

        return self._last_func

    def goto_address(self, func_addr) -> None:
        self.ghidra.goTo(self.ghidra.toAddr(func_addr))

    #
    # Override Optional API:
    # There are API that provide extra introspection for plugins that may rely on LibBS Interface
    #

    def undo(self):
        self.ghidra.currentProgram.undo()

    def local_variable_names(self, func: Function) -> List[str]:
        symbols_by_name = self._get_local_variable_symbols(func)
        return list(symbols_by_name.keys())

    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str]) -> bool:
        symbols_by_name = self._get_local_variable_symbols(func)
        symbols_to_update = {}
        for name, new_name in name_map.items():
            if name not in symbols_by_name or symbols_by_name[name].name == new_name or new_name in symbols_by_name:
                continue

            sym: "HighSymbol" = symbols_by_name[name]
            symbols_to_update[sym] = (new_name, None)

        return self._update_local_variable_symbols(symbols_to_update) if symbols_to_update else False

    #
    # Artifact API
    #

    def _set_function(self, func: Function, **kwargs) -> bool:
        func_addr = func.header.addr
        decompilation = self._ghidra_decompile(self._get_nearest_function(func_addr))
        changes = super()._set_function(func, decompilation=decompilation, **kwargs)
        return changes

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        func = self._get_nearest_function(addr)
        dec = self._ghidra_decompile(func)
        # optimize on remote
        stack_variable_info: Optional[List[Tuple[int, str, str, int]]] = self.ghidra.bridge.remote_eval(
            "[(sym.getStorage().getStackOffset(), sym.getName(), str(sym.getDataType()), sym.getSize()) "
            "for sym in dec.getHighFunction().getLocalSymbolMap().getSymbols() "
            "if sym.getStorage().isStackStorage()]",
            dec=dec
        )
        stack_variables = {}
        if stack_variable_info:
            stack_variables = {
                offset: StackVariable(offset, name, typestr, size, addr) for offset, name, typestr, size in stack_variable_info
            }

        arg_variable_info: Optional[List[Tuple[int, str, str, int]]] = self.ghidra.bridge.remote_eval(
            "[(i, sym.getName(), str(sym.getDataType()), sym.getSize()) "
            "for i, sym in enumerate(dec.getHighFunction().getLocalSymbolMap().getSymbols()) "
            "if sym.isParameter()]",
            dec=dec
        )
        args = {}
        if arg_variable_info:
            args = {
                i: FunctionArgument(i, name, typestr, size, addr) for i, name, typestr, size in arg_variable_info
            }

        bs_func = Function(
            func.getEntryPoint().getOffset(), func.getBody().getNumAddresses(),
            header=FunctionHeader(func.getName(), func.getEntryPoint().getOffset(), args=args),
            stack_vars=stack_variables, dec_obj=dec
        )
        return bs_func

    def _functions(self) -> Dict[int, Function]:
        # optimization to speed up remote evaluation
        name_and_sizes: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(f.getName(), f.getEntryPoint().getOffset()) "
            "for f in currentProgram.getFunctionManager().getFunctions(True)]"
        )
        if name_and_sizes is None:
            _l.warning(f"Failed to get any functions from Ghidra. Did something break?")
            return {}

        funcs = {
            addr: Function(addr, 0, header=FunctionHeader(name, addr)) for name, addr in name_and_sizes
        }
        return funcs

    @ghidra_transaction
    def _set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        changes = False
        decompilation = kwargs.get('decompilation', None) or self._ghidra_decompile(self._get_function(svar.addr))
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(svar.addr)
        gstack_var = self._get_gstack_var(ghidra_func, svar.offset)
        src_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")

        if svar.name and svar.name != gstack_var.getName():
            gstack_var.setName(svar.name, src_type.USER_DEFINED)
            changes = True

        if svar.type:
            parsed_type = self.typestr_to_gtype(svar.type)
            if parsed_type is not None and parsed_type != str(gstack_var.getDataType()):
                gstack_var.setDataType(parsed_type, False, True, src_type.USER_DEFINED)
                changes = True

        return changes

    def _get_stack_variable(self, addr: int, offset: int, **kwargs) -> Optional[StackVariable]:
        gstack_var = self._get_gstack_var(addr, offset)
        if gstack_var is None:
            return None

        return self._gstack_var_to_bsvar(gstack_var)

    @ghidra_transaction
    def _set_function_header(self, fheader: FunctionHeader, decompilation=None, **kwargs) -> bool:
        changes = False
        func_addr = fheader.addr
        ghidra_func = decompilation.getFunction() if decompilation else self._get_nearest_function(func_addr)
        src_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")

        # func name
        if fheader.name and fheader.name != ghidra_func.getName():
            ghidra_func.setName(fheader.name, src_type.USER_DEFINED)
            changes = True

        # return type
        if fheader.type and decompilation is not None:
            parsed_type = self.typestr_to_gtype(fheader.type)
            if parsed_type is not None and \
                    parsed_type != str(decompilation.highFunction.getFunctionPrototype().getReturnType()):
                ghidra_func.setReturnType(parsed_type, src_type.USER_DEFINED)
                changes = True

        # args
        if fheader.args and decompilation is not None:
            # TODO: do arg names and types
            pass

        return changes

    @ghidra_transaction
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        struct: Struct = struct
        old_ghidra_struct = self._get_struct_by_name('/' + struct.name)
        data_manager = self.ghidra.currentProgram.getDataTypeManager()
        handler = self.ghidra.import_module_object("ghidra.program.model.data", "DataTypeConflictHandler")
        structType = self.ghidra.import_module_object("ghidra.program.model.data", "StructureDataType")
        byteType = self.ghidra.import_module_object("ghidra.program.model.data", "ByteDataType")
        ghidra_struct = structType(struct.name, 0)
        for offset in struct.members:
            member = struct.members[offset]
            ghidra_struct.add(byteType.dataType, 1, member.name, "")
            ghidra_struct.growStructure(member.size - 1)
            for dtc in ghidra_struct.getComponents():
                if dtc.getFieldName() == member.name:
                    gtype = self.typestr_to_gtype(member.type if member.type else 'undefined' + str(member.size))
                    for i in range(offset, offset + member.size):
                        ghidra_struct.clearAtOffset(i)
                    ghidra_struct.replaceAtOffset(offset, gtype, member.size, member.name, "")
                    break
        try:
            if old_ghidra_struct:
                data_manager.replaceDataType(old_ghidra_struct, ghidra_struct, True)
            else:
                data_manager.addDataType(ghidra_struct, handler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            print(f'Error filling struct {struct.name}: {ex}')
            return False

    def _get_struct(self, name) -> Optional[Struct]:
        ghidra_struct = self._get_struct_by_name(name)
        bs_struct = Struct(ghidra_struct.getName(), ghidra_struct.getLength(), self._struct_members_from_gstruct(name))
        return bs_struct

    def _structs(self) -> Dict[str, Struct]:
        name_sizes: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(s.getPathName(), s.getLength())"
            "for s in currentProgram.getDataTypeManager().getAllStructures()]"
        )
        return {
            name: Struct(name, size, members=self._struct_members_from_gstruct(name)) for name, size in name_sizes
        } if name_sizes else {}

    @ghidra_transaction
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        CodeUnit = self.ghidra.import_module_object("ghidra.program.model.listing", "CodeUnit")
        SetCommentCmd = self.ghidra.import_module_object("ghidra.app.cmd.comments", "SetCommentCmd")
        cmt_type = CodeUnit.PRE_COMMENT if comment.decompiled else CodeUnit.EOL_COMMENT
        if comment.addr == comment.func_addr:
            cmt_type = CodeUnit.PLATE_COMMENT

        if comment.comment:
            # TODO: check if comment already exists, and append?
            return SetCommentCmd(
                self.ghidra.toAddr(comment.addr), cmt_type, comment.comment
            ).applyTo(self.ghidra.currentProgram)
        return True

    def _get_comment(self, addr) -> Optional[Comment]:
        return None

    def _comments(self) -> Dict[int, Comment]:
        comments = {}
        for func in self.ghidra.currentProgram.getFunctionManager().getFunctions(True):
            addrSet = func.getBody()
            eol_text_addrs: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_exec(
                "[(codeUnit.getComment(0), codeUnit.address)"
                "for codeUnit in currentProgram.getListing().getCodeUnits(addrSet, True)"
                "if codeUnit.getComment(0)",
                addrSet=addrSet
            )
            pre_text_addrs: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_exec(
                "[(codeUnit.getComment(1), codeUnit.address)"
                "for codeUnit in currentProgram.getListing().getCodeUnits(addrSet, True)"
                "if codeUnit.getComment(1)",
                addrSet=addrSet
            )
            comments |= {addr: Comment(addr, text) for text, addr in eol_text_addrs}
            comments |= {addr: Comment(addr, text, decompiled=True) for text, addr in pre_text_addrs}
        return comments

    @ghidra_transaction
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        corrected_enum_name = "/" + enum.name
        old_ghidra_enum = self.ghidra.currentProgram.getDataTypeManager().getDataType(corrected_enum_name)
        data_manager = self.ghidra.currentProgram.getDataTypeManager()
        handler = self.ghidra.import_module_object("ghidra.program.model.data", "DataTypeConflictHandler")
        enumType = self.ghidra.import_module_object("ghidra.program.model.data", "EnumDataType")
        categoryPath = self.ghidra.import_module_object("ghidra.program.model.data", "CategoryPath")
        ghidra_enum = enumType(categoryPath('/'), enum.name, 4)
        for m_name, m_val in enum.members.items():
            ghidra_enum.add(m_name, m_val)

        try:
            if old_ghidra_enum:
                data_manager.replaceDataType(old_ghidra_enum, ghidra_enum, True)
            else:
                data_manager.addDataType(ghidra_enum, handler.DEFAULT_HANDLER)
            return True
        except Exception as ex:
            print(f'Error adding enum {enum.name}: {ex}')
            return False

    def _get_enum(self, name) -> Optional[Enum]:
        members = self._get_enum_members('/' + name)
        return Enum(name, members) if members else None

    def _enums(self) -> Dict[str, Enum]:
        names: Optional[List[str]] = self.ghidra.bridge.remote_eval(
            "[dType.getPathName() "
            "for dType in currentProgram.getDataTypeManager().getAllDataTypes()"
            "if str(type(dType)) == \"<type 'ghidra.program.database.data.EnumDB'>\"]"
        )
        return {name[1:]: Enum(name[1:], self._get_enum_members(name)) for name in names if name.count('/') == 1} if names else {}

    #
    # TODO: REMOVE ME THIS IS THE BINSYNC CODE
    # Filler/Setter API
    #

    @ghidra_transaction
    def fill_global_var(self, var_addr, user=None, artifact=None, **kwargs):
        changes = False
        global_var: GlobalVariable = artifact
        all_global_vars = self.global_vars()

        rename_label_cmd_cls = self.ghidra.import_module_object("ghidra.app.cmd.label", "RenameLabelCmd")
        src_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")
        for offset, gvar in all_global_vars.items():
            if offset != var_addr:
                continue

            if global_var.name and global_var.name != gvar.name:
                sym = self.ghidra.getSymbolAt(self.ghidra.toAddr(var_addr))
                cmd = rename_label_cmd_cls(sym, global_var.name, src_type.USER_DEFINED)
                cmd.applyTo(self.ghidra.currentProgram)
                changes = True

            if global_var.type:
                # TODO: set type
                pass

            break

        return changes

    def global_var(self, addr) -> Optional[GlobalVariable]:
        light_global_vars = self.global_vars()
        for offset, global_var in light_global_vars.items():
            if offset == addr:
                lst = self.ghidra.currentProgram.getListing()
                g_addr = self.ghidra.toAddr(addr)
                data = lst.getDataAt(g_addr)
                if not data or data.isStructure():
                    return None
                if str(data.getDataType()) == "undefined":
                    size = self.ghidra.currentProgram.getDefaultPointerSize()
                else:
                    size = data.getLength()

                global_var.size = size
                return global_var

    def global_vars(self) -> Dict[int, GlobalVariable]:
        symbol_type = self.ghidra.import_module_object("ghidra.program.model.symbol", "SymbolType")
        symbol_table = self.ghidra.currentProgram.getSymbolTable()
        # optimize by grabbing all symbols at once
        gvar_addr_and_name: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(sym.getName(), sym.getAddress().getOffset()) "
            "for sym in symbol_table.getAllSymbols(True) "
            "if sym.getSymbolType() == symbol_type.LABEL]",
            symbol_type=symbol_type, symbol_table=symbol_table
        )
        gvars = {
            addr: GlobalVariable(addr, name) for name, addr in gvar_addr_and_name
        }
        return gvars

    #
    # Specialized print handlers
    #

    def print(self, msg, print_local=True, **kwargs):
        self.ghidra.print(msg, print_local=print_local)

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

    @ghidra_transaction
    def _update_local_variable_symbols(
        self, symbols: Dict["HighSymbol", Tuple[str, Optional["DataType"]]]
    ) -> bool:
        """
        @param decompilation:
        @param symbols: of form [Symbol] = (new_name, new_type)
        """
        HighFunctionDBUtil = self.ghidra.import_module_object("ghidra.program.model.pcode", "HighFunctionDBUtil")
        SourceType = self.ghidra.import_module_object("ghidra.program.model.symbol", "SourceType")
        update_list = self.ghidra.bridge.remote_eval(
            "[HighFunctionDBUtil.updateDBVariable(sym, updates[0], updates[1], SourceType.ANALYSIS) "
            "for sym, updates in symbols.items()]",
            HighFunctionDBUtil=HighFunctionDBUtil, SourceType=SourceType, symbols=symbols
        )
        return any([u is not None for u in update_list])

    @requires_decompilation
    def _get_local_variable_symbols(self, func: Function) -> Dict[str, "HighSymbol"]:
        high_func = func.dec_obj.getHighFunction()
        return self.ghidra.bridge.remote_eval(
            "{sym.name: sym for sym in high_func.getLocalSymbolMap().getSymbols() if sym.name}",
            high_func=high_func
        )

    def _get_struct_by_name(self, name: str) -> "GhidraStructure":
        return self.ghidra.currentProgram.getDataTypeManager().getDataType(name)

    def _struct_members_from_gstruct(self, name: str) -> Dict[int, StructMember]:
        ghidra_struct = self._get_struct_by_name(name)
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
        ghidra_enum = self.ghidra.currentProgram.getDataTypeManager().getDataType(name)
        if not ghidra_enum:
            return None
        name_vals: Optional[List[Tuple[str, int]]] = self.ghidra.bridge.remote_eval(
            "[(name, ghidra_enum.getValue(name))"
            "for name in ghidra_enum.getNames()]",
            ghidra_enum=ghidra_enum
        )
        return {name: value for name, value in name_vals} if name_vals else {}

    def _get_nearest_function(self, addr: int) -> "GhidraFunction":
        func_manager = self.ghidra.currentProgram.getFunctionManager()
        return func_manager.getFunctionContaining(self.ghidra.toAddr(addr))

    def _gstack_var_to_bsvar(self, gstack_var: "LocalVariableDB"):
        if gstack_var is None:
            return None

        bs_stack_var = StackVariable(
            gstack_var.getStackOffset(),
            gstack_var.getName(),
            str(gstack_var.getDataType()),
            gstack_var.getLength(),
            gstack_var.getFunction().getEntryPoint().getOffset() # Unsure if this is what is wanted here
        )
        return bs_stack_var

    def _gfunc_to_bsfunc(self, gfunc: "GhidraFunction"):
        if gfunc is None:
            return None

        bs_func = Function(
            gfunc.getEntryPoint().getOffset(), gfunc.getBody().getNumAddresses(),
            header=FunctionHeader(gfunc.getName(), gfunc.getEntryPoint().getOffset()),
        )
        return bs_func

    def _ghidra_decompile(self, func: "GhidraFunction") -> "DecompileResult":
        """
        TODO: this needs to be cached!
        @param func:
        @return:
        """
        dec_interface_cls = self.ghidra.import_module_object("ghidra.app.decompiler", "DecompInterface")
        consle_monitor_cls = self.ghidra.import_module_object("ghidra.util.task", "ConsoleTaskMonitor")

        dec_interface = dec_interface_cls()
        dec_interface.openProgram(self.ghidra.currentProgram)
        dec_results = dec_interface.decompileFunction(func, 0, consle_monitor_cls())
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
        if not typestr:
            return None

        dtm_service_class = self.ghidra.import_module_object("ghidra.app.services", "DataTypeManagerService")
        dtp_class = self.ghidra.import_module_object("ghidra.util.data", "DataTypeParser")
        dt_service = self.ghidra.getState().getTool().getService(dtm_service_class)
        dt_parser = dtp_class(dt_service, dtp_class.AllowedDataTypes.ALL)
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
        if not progotype_str:
            return None

        c_parser_utils_cls = self.ghidra.import_module_object("ghidra.app.util.cparser.C", "CParserUtils")
        program = self.ghidra.currentProgram
        return c_parser_utils_cls.parseSignature(program, progotype_str)

    def _run_until_server_closed(self, sleep_interval=30):
        while True:
            if not self.ghidra.ping():
                break

            time.sleep(sleep_interval)
