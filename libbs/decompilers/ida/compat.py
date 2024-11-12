# ----------------------------------------------------------------------------
# This file is more of a library for making compatibility calls to IDA for
# things such as getting decompiled function names, start addresses, and
# asking for write permission to ida. This will mostly be called in the
# deci.
#
# Note that anything that requires write permission to IDA will need to pass
# through this program if it is not running in the main thread.
#
# ----------------------------------------------------------------------------
import datetime
import re
import threading
from functools import wraps
import typing
import logging
from packaging.version import Version

import idc, idaapi, ida_kernwin, ida_hexrays, ida_funcs, \
    ida_bytes, ida_idaapi, ida_typeinf, idautils, ida_kernwin, ida_segment

import libbs
from libbs.artifacts import (
    Struct, FunctionHeader, FunctionArgument, StackVariable, Function, GlobalVariable, Enum, Artifact, Context, Typedef,
    StructMember
)

from .artifact_lifter import IDAArtifactLifter
if typing.TYPE_CHECKING:
    from .interface import IDAInterface

_l = logging.getLogger(__name__)
_IDA_VERSION = None

FORM_TYPE_TO_NAME = None
FUNC_FORMS = {"decompilation", "disassembly"}

def get_form_to_type_name():
    global FORM_TYPE_TO_NAME
    if FORM_TYPE_TO_NAME is None:
        mapping = {
            idaapi.BWN_PSEUDOCODE: "decompilation",
            idaapi.BWN_DISASM: "disassembly",
            idaapi.BWN_FUNCS: "functions",
            idaapi.BWN_STRINGS: "strings"
        }
        if get_ida_version() >= Version("9.0"):
            mapping.update({
                idaapi.BWN_TILIST: "types"
            })
        else:
            mapping.update({
                idaapi.BWN_STRINGS: "structs",
                idaapi.BWN_ENUMS: "enums",
                0x3c: "types"
            })
        FORM_TYPE_TO_NAME = mapping

    return FORM_TYPE_TO_NAME

#
# Wrappers for IDA Main thread r/w operations
# a special note about these functions:
# Any operation that needs to do some type of write to the ida db (idb), needs to be in the main thread due to
# some ida constraints. Sometimes reads also need to be in the main thread. To make things efficient, most heavy
# things are done in the deci and just setters and getters are done here.
#


def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)


def execute_write(f):
    @wraps(f)
    def _execute_write(*args, **kwargs):
        output = [None]

        def thunk():
            output[0] = f(*args, **kwargs)
            return 1

        if is_mainthread():
            thunk()
        else:
            idaapi.execute_sync(thunk, idaapi.MFF_WRITE)

        # return the output of the synchronized execution
        return output[0]

    return _execute_write

#
# Decompilation
#


class DummyIDACodeView:
    def __init__(self, addr):
        self.cfunc = ida_hexrays.decompile(addr)
        self.addr = addr


def requires_decompilation(f):
    @wraps(f)
    def _requires_decompilation(*args, **kwargs):
        artifact = args[0]
        if isinstance(artifact, Artifact):
            addr = artifact.addr
        else:
            addr = artifact

        has_ui = not kwargs.get('headless', False)
        has_decompiler = kwargs.get('decompiler_available', True)
        ida_code_view = kwargs.get('ida_code_view', None)

        if ida_code_view is None and has_decompiler:
            kwargs['ida_code_view'] = acquire_pseudocode_vdui(addr) if has_ui else DummyIDACodeView(addr)

        return f(*args, **kwargs)

    return _requires_decompilation


@execute_write
def get_func_ret_type(ea):
    tinfo = ida_typeinf.tinfo_t()
    got_info = idaapi.get_tinfo(tinfo, ea)
    return str(tinfo.get_rettype()) if got_info else None


@execute_write
def get_func(ea):
    return idaapi.get_func(ea)


def set_func_ret_type(ea, return_type_str):
    tinfo = ida_typeinf.tinfo_t()
    if not idaapi.get_tinfo(tinfo, ea):
        _l.warning(f"Failed to get tinfo for function at {hex(ea)}")
        return False

    new_type = convert_type_str_to_ida_type(return_type_str)
    if new_type is None:
        _l.warning(f"Failed to convert type string {return_type_str} to ida type.")
        return False

    func_type_data = ida_typeinf.func_type_data_t()
    if not tinfo.get_func_details(func_type_data):
        _l.warning(f"Failed to get function details for function at {hex(ea)}")
        return False

    func_type_data.rettype = new_type
    new_func_type = ida_typeinf.tinfo_t()
    if not new_func_type.create_func(func_type_data):
        _l.warning(f"Failed to create new function type for function at {hex(ea)}")
        return False

    # Apply the new function type to the function
    if not idaapi.apply_tinfo(ea, new_func_type, idaapi.TINFO_DEFINITE):
        _l.warning(f"Failed to apply new function type for function at {hex(ea)}")
        return False

    return True

#
# Types
#


@execute_write
def _get_ida_version():
    return idaapi.get_kernel_version()


def get_ida_version():
    global _IDA_VERSION
    if _IDA_VERSION is None:
        _IDA_VERSION = Version(_get_ida_version())

    return _IDA_VERSION


def new_ida_typing_system():
    return get_ida_version() >= Version("8.4")


def get_ordinal_count():
    if new_ida_typing_system():
        return ida_typeinf.get_ordinal_count(idaapi.get_idati())
    else:
        return ida_typeinf.get_ordinal_qty(idaapi.get_idati())


@execute_write
def get_types(structs=True, enums=True, typedefs=True) -> typing.Dict[str, Artifact]:
    types = {}
    idati = idaapi.get_idati()

    for ord_num in range(1, get_ordinal_count()+1):
        tif = ida_typeinf.tinfo_t()
        success = tif.get_numbered_type(idati, ord_num)
        if not success:
            continue

        is_typedef, name, type_name = typedef_info(tif, use_new_check=True)
        # must check typedefs first, since they can be structs
        if is_typedef:
            if typedefs:
                types[name] = Typedef(name, type_name)
            continue

        if structs and tif.is_struct():
            bs_struct = bs_struct_from_tif(tif)
            types[bs_struct.name] = bs_struct
        elif enums and tif.is_enum():
            bs_enum = enum_from_tif(tif)
            types[bs_enum.name] = bs_enum

    return types


@execute_write
def get_ord_to_type_names() -> typing.Dict[int, typing.Tuple[str, typing.Type[Artifact]]]:
    idati = idaapi.get_idati()
    ord_to_name = {}
    for ord_num in range(1, get_ordinal_count()+1):
        tif = ida_typeinf.tinfo_t()
        success = tif.get_numbered_type(idati, ord_num)
        if not success:
            continue

        type_name = tif.get_type_name()
        if tif.is_typedef():
            type_type = Typedef
        elif tif.is_struct():
            type_type = Struct
        elif tif.is_enum():
            type_type = Enum
        else:
            type_type = None

        if type_name:
            ord_to_name[ord_num] = (type_name, type_type)

    return ord_to_name


def get_ida_type(ida_ord=None, name=None):
    tif = ida_typeinf.tinfo_t()
    idati = idaapi.get_idati()
    if ida_ord is not None:
        success = tif.get_numbered_type(idati, ida_ord)
        if not success:
            return None
    elif name is not None:
        success = tif.get_named_type(idati, name)
        if not success:
            return None
    else:
        return None

    return tif

#
# Type Converters
#

def type_str_to_size(type_str) -> typing.Optional[int]:
    ida_type = convert_type_str_to_ida_type(type_str)
    if ida_type is None:
        return None

    return ida_type.get_size()

@execute_write
def convert_type_str_to_ida_type(type_str) -> typing.Optional['ida_typeinf']:
    if type_str is None or not isinstance(type_str, str):
        return None

    tif = ida_typeinf.tinfo_t()
    if type_str.strip() == "void":
        valid_parse = tif.create_simple_type(ida_typeinf.BT_VOID)
    else:
        ida_type_str = type_str + ";"
        valid_parse = ida_typeinf.parse_decl(tif, None, ida_type_str, 1)

    return tif if valid_parse is not None else None

@execute_write
def convert_size_to_flag(size):
    """
    Converts a size to the arch specific flag.

    Inspired by: https://github.com/arizvisa/ida-minsc/blob/master/base/_interface.py

    :param size: in bytes
    :return: ida flag_t
    """

    size_map = {
        1: idaapi.byte_flag(),
        2: idaapi.word_flag(),
        4: idaapi.dword_flag(),
        8: idaapi.qword_flag()
    }

    try:
        flag = size_map[size]
    except KeyError:
        # just always assign something
        flag = idaapi.byte_flag()

    return flag


#
#   IDA Function r/w
#

@execute_write
def ida_func_addr(addr):
    ida_func = ida_funcs.get_func(addr)
    if ida_func is None:
        return None

    func_addr = ida_func.start_ea
    return func_addr


@execute_write
def get_func_name(ea) -> typing.Optional[str]:
    return idc.get_func_name(ea)


@execute_write
def get_func_size(ea):
    func = idaapi.get_func(ea)
    if not func:
        raise ValueError("Unable to find function!")

    return func.size()


@execute_write
def set_ida_func_name(func_addr, new_name):
    idaapi.set_name(func_addr, new_name, idaapi.SN_FORCE)
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASM)
    # XXX: why was this here?!?!?
    #ida_kernwin.request_refresh(ida_kernwin.IWID_STRUCTS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STKVIEW)

def get_segment_range(segment_name) -> typing.Tuple[bool, int, int]:
    # Find the segment by name
    seg = ida_segment.get_segm_by_name(segment_name)
    if seg is None:
        return False, None, None

    start_ea = seg.start_ea
    end_ea = seg.end_ea
    return True, start_ea, end_ea


@execute_write
def functions():
    blacklisted_segs = ["extern", ".plt", ".plt.sec"]
    seg_to_range = {}
    for seg in blacklisted_segs:
        success, start, end = get_segment_range(seg)
        if success:
            seg_to_range[seg] = (start, end)

    funcs = {}
    for func_addr in idautils.Functions():
        in_bad_seg = False
        for seg, (start, end) in seg_to_range.items():
            if start <= func_addr < end:
                in_bad_seg = True
                break

        if in_bad_seg:
            continue

        ida_func = idaapi.get_func(func_addr)
        func_name = idc.get_func_name(func_addr)
        func_size = ida_func.size()
        func = Function(addr=func_addr, size=func_size)
        func.name = func_name
        funcs[func_addr] = func

    return funcs


@execute_write
@requires_decompilation
def function(addr, decompiler_available=True, ida_code_view=None, **kwargs):
    ida_func = ida_funcs.get_func(addr)
    if ida_func is None:
        _l.warning(f"IDA function does not exist for {hex(addr)}.")
        return None

    func_addr = ida_func.start_ea
    change_time = datetime.datetime.now(tz=datetime.timezone.utc)
    func = Function(func_addr, get_func_size(func_addr), last_change=change_time)

    if not decompiler_available:
        func.header = FunctionHeader(get_func_name(func_addr), func_addr, last_change=change_time)
        return func

    def _get_func_info(code_view):
        if code_view is None:
            _l.warning(f"IDA function {hex(func_addr)} is not decompilable")
            return func

        func_header: FunctionHeader = function_header(code_view)
        stack_vars = {
            offset: var
            for offset, var in get_func_stack_var_info(ida_func.start_ea).items()
        }
        func.header = func_header
        func.stack_vars = stack_vars

        return func

    if ida_code_view is not None:
        func = _get_func_info(ida_code_view)
    else:
        with IDAViewCTX(func_addr) as ida_code_view:
            func = _get_func_info(ida_code_view)

    func.dec_obj = ida_code_view.cfunc if ida_code_view is not None else None
    return func


@execute_write
def set_function(func: Function, decompiler_available=True, **kwargs):
    changes = False

    # acquire decompilation if it is needed
    ida_code_view = kwargs.get('ida_code_view', None)
    headless = kwargs.get('headless', False)
    # these changes require a decompiler
    needs_decompilation = bool(func.stack_vars) or bool(func.header.args)
    if needs_decompilation and ida_code_view is None and decompiler_available:
        ida_code_view = acquire_pseudocode_vdui(func.addr) if not headless else DummyIDACodeView(func.addr)

    # function header, may be only name if no decompiler
    if func.header and needs_decompilation and ida_code_view is not None:
        changes |= set_function_header(func.header, ida_code_view=ida_code_view)
    elif func.header:
        if func.name:
            set_ida_func_name(func.addr, func.name)
            changes |= True
        if func.type:
            changes |= set_func_ret_type(func.addr, func.type)

    # stack vars
    if func.stack_vars and ida_code_view is not None:
        changes |= set_stack_variables(func.stack_vars, ida_code_view=ida_code_view)

    if changes and ida_code_view is not None:
        ida_code_view.refresh_view(changes)
        ida_code_view.cfunc.refresh_func_ctext()

    return changes

@execute_write
def function_header(ida_code_view) -> FunctionHeader:
    func_addr = ida_code_view.cfunc.entry_ea

    # collect the function arguments
    func_args = {}
    for idx, arg in enumerate(ida_code_view.cfunc.arguments):
        size = arg.width
        name = arg.name
        type_str = str(arg.type())
        func_args[idx] = FunctionArgument(idx, name, type_str, size)

    # collect the header ret_type and name
    func_name = get_func_name(func_addr)
    try:
        ret_type_str = str(ida_code_view.cfunc.type.get_rettype())
    except Exception:
        ret_type_str = ""

    ida_function_info = FunctionHeader(func_name, func_addr, type_=ret_type_str, args=func_args,
                                       last_change=datetime.datetime.now(tz=datetime.timezone.utc))
    return ida_function_info

@execute_write
@requires_decompilation
def set_function_header(bs_header: libbs.artifacts.FunctionHeader, exit_on_bad_type=False, ida_code_view=None):
    data_changed = False
    func_addr = ida_code_view.cfunc.entry_ea
    cur_ida_func = function_header(ida_code_view)

    #
    # FUNCTION NAME
    #

    if bs_header.name and bs_header.name != cur_ida_func.name:
        set_ida_func_name(func_addr, bs_header.name)

    #
    # FUNCTION RET TYPE
    #

    func_name = get_func_name(func_addr)
    cur_ret_type_str = str(ida_code_view.cfunc.type.get_rettype())
    if bs_header.type and bs_header.type != cur_ret_type_str:
        old_prototype = str(ida_code_view.cfunc.type).replace("(", f" {func_name}(", 1)
        new_prototype = old_prototype.replace(cur_ret_type_str, bs_header.type, 1)
        success = bool(
            ida_typeinf.apply_tinfo(func_addr, convert_type_str_to_ida_type(new_prototype), ida_typeinf.TINFO_DEFINITE)
        )

        # we may need to reload types
        if success is None and exit_on_bad_type:
            return False

        data_changed |= success is True
        ida_code_view.refresh_view(data_changed)

    #
    # FUNCTION ARGS
    #

    types_to_change = {}
    for idx, bs_arg in bs_header.args.items():
        if not bs_arg:
            continue

        if idx >= len(cur_ida_func.args):
            break

        cur_ida_arg = cur_ida_func.args[idx]

        # record the type to change
        if bs_arg.type and bs_arg.type != cur_ida_arg.type:
            types_to_change[idx] = (cur_ida_arg.type, bs_arg.type)

        # change the name
        if bs_arg.name and bs_arg.name != cur_ida_arg.name:
            success = ida_code_view.rename_lvar(ida_code_view.cfunc.arguments[idx], bs_arg.name, 1)
            data_changed |= success

    # crazy prototype parsing
    func_prototype = str(ida_code_view.cfunc.type).replace("(", f" {func_name}(", 1)
    proto_split = func_prototype.split("(", maxsplit=1)
    proto_head, proto_body = proto_split[0], "(" + proto_split[1]
    arg_strs = proto_body.split(",")

    # update prototype body from left to right
    for idx in range(len(cur_ida_func.args)):
        try:
            old_t, new_t = types_to_change[idx]
        except KeyError:
            continue

        arg_strs[idx] = arg_strs[idx].replace(old_t, new_t, 1)

    # set the change
    proto_body = ",".join(arg_strs)
    new_prototype = proto_head + proto_body
    success = idc.SetType(func_addr, new_prototype)

    # we may need to reload types
    if success is None and exit_on_bad_type:
        return False

    data_changed |= success is True
    return data_changed


def bs_header_from_tif(tif, name=None, addr=None):
    """
    Takes a ida_typeinf.tinfo_t and converts it into a BinSync FunctionHeader.
    You can optionally specify the name of the function, which is usually not in the tif, otherwise it will be None.

    TODO: its kinda broken, better to use vdui ptr and grab artifacts
    """
    ret_type = str(tif.get_rettype())
    bs_header = FunctionHeader(name, addr, type_=ret_type, args={})

    nargs = tif.get_nargs()
    if not nargs:
        return bs_header

    bs_args = {}
    # construct a really wack regex which essentially finds where the args are in the prototype
    proto_str_regex = "\\("
    for idx in range(nargs):
        arg_ida_type = tif.get_nth_arg(idx)
        bs_arg = FunctionArgument(idx, None, str(arg_ida_type), arg_ida_type.get_size())
        bs_args[bs_arg.offset] = bs_arg

        # make sure the * does not make it into the regex
        arg_type_str = bs_arg.type.replace("*", "\\*").replace("(", "\\(").replace(")", "")
        # every arg has some space and a name, group the name
        proto_str_regex += rf"\s*{arg_type_str}\s*(.+?)"
        if idx != nargs - 1:
            proto_str_regex += ","

    proto_str_regex += "\\)"
    matches = re.findall(proto_str_regex, str(tif))
    if not matches:
        _l.warning(f"Failed to parse a function header with header: {str(tif)}")
        return bs_header

    match = matches[0]
    for i, name in enumerate(match):
        bs_args[i].name = name

    return bs_header


#
# Variables
#


def lvars_to_bs(lvars: list, vdui=None, var_names: list = None, recover_offset=False) -> list[typing.Union[FunctionArgument, StackVariable]]:
    bs_vars = []
    arg_name_to_off = {}
    if var_names and len(var_names) == len(lvars):
        if recover_offset:
            for offset, _lvar in enumerate(vdui.cfunc.lvars):
                if _lvar.is_arg_var:
                    arg_name_to_off[_lvar.name] = offset

    for lvar_off, lvar in enumerate(lvars):
        if lvar is None:
            # this should really never happen
            continue

        if vdui is None:
            _l.warning("Cannot gather local variables from decompilation that does not exist!")
            return bs_vars

        if lvar.is_arg_var:
            if recover_offset:
                offset = arg_name_to_off.get(lvar.name, None)
                if offset is None:
                    continue
            else:
                offset = lvar_off
            bs_cls = FunctionArgument
        elif lvar.is_stk_var():
            offset = lvar.location.stkoff()
            bs_cls = StackVariable
        elif lvar.is_reg_var():
            # TODO: implement register variables
            continue
        else:
            continue

        name = None
        if var_names:
            name = var_names[lvar_off]
        if not name:
            name = lvar.name
        type_ = str(lvar.type())
        size = lvar.width

        var = bs_cls(name=name, type_=type_, size=size)
        var.offset = offset
        if isinstance(var, StackVariable):
            var.addr = vdui.cfunc.entry_ea

        bs_vars.append(var)

    return bs_vars


@execute_write
@requires_decompilation
def rename_local_variables_by_names(func: Function, name_map: typing.Dict[str, str], ida_code_view=None) -> bool:
    lvars = {
        lvar.name: lvar for lvar in ida_code_view.cfunc.get_lvars() if lvar.name
    }
    update = False
    for name, lvar in lvars.items():
        new_name = name_map.get(name, None)
        if new_name is None:
            continue

        ida_hexrays.rename_lvar(func.addr, lvar.name, new_name)
        update |= True

    if update and ida_code_view is not None:
        ida_code_view.cfunc.refresh_func_ctext()
        ida_code_view.refresh_view(True)

    return update


#
# Stack Vars
#

def _deprecated_ida_to_bs_offset(func_addr, ida_stack_off):
    frame = idaapi.get_frame(func_addr)
    if not frame:
        return ida_stack_off

    frame_size = idc.get_struc_size(frame)

    if frame_size == 0:
        return ida_stack_off

    last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))
    bs_soff = ida_stack_off - frame_size + last_member_size
    return bs_soff

def _deprecated_bs_to_ida_offset(func_addr, bs_stack_off):
    frame = idaapi.get_frame(func_addr)
    if not frame:
        return bs_stack_off

    frame_size = idc.get_struc_size(frame)

    if frame_size == 0:
        return bs_stack_off

    last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))
    ida_soff = bs_stack_off + frame_size - last_member_size
    return ida_soff


def get_func_stack_tif(func):
    if isinstance(func, int):
        func = idaapi.get_func(func)

    if func is None:
        return None

    tif = ida_typeinf.tinfo_t()
    if not tif.get_func_frame(func):
        return None

    return tif

def get_frame_info(func_addr) -> typing.Tuple[int, int]:
    func = idaapi.get_func(func_addr)
    if not func:
        raise ValueError(f"Function {hex(func_addr)} does not exist.")

    stack_tif = get_func_stack_tif(func)
    if stack_tif is None:
        _l.warning(f"Function {hex(func_addr)} does not have a stack frame.")
        return None, None

    frame_size = stack_tif.get_size()
    if frame_size == 0:
        _l.warning(f"Function {hex(func_addr)} has a stack frame size of 0.")
        return None, None

    # get the last member size
    udt_data = ida_typeinf.udt_type_data_t()
    stack_tif.get_udt_details(udt_data)
    membs = [m for m in udt_data]
    if not membs:
        _l.warning(f"Function {hex(func_addr)} has a stack frame with no members.")
        return None, None

    last_member_type = membs[-1].type
    if not last_member_type:
        _l.warning(f"Function {hex(func_addr)} has a stack frame with a member with no type.")
        return None, None

    last_member_size = last_member_type.get_size()
    return frame_size, last_member_size

def ida_to_bs_stack_offset(func_addr: int, ida_stack_off: int):
    if get_ida_version() < Version("9.0"):
        return _deprecated_ida_to_bs_offset(func_addr, ida_stack_off)

    frame_size, last_member_size = get_frame_info(func_addr)
    if frame_size is None or last_member_size is None:
        return ida_stack_off

    bs_soff = ida_stack_off - frame_size + last_member_size
    return bs_soff

def bs_to_ida_stack_offset(func_addr: int, bs_stack_off: int):
    if get_ida_version() < Version("9.0"):
        # maintain backwards compatibility
        return _deprecated_bs_to_ida_offset(func_addr, bs_stack_off)

    frame_size, last_member_size = get_frame_info(func_addr)
    if frame_size is None or last_member_size is None:
        return bs_stack_off

    ida_soff = bs_stack_off + frame_size - last_member_size
    return ida_soff

def set_stack_variables(svars: list[StackVariable], decompiler_available=True, **kwargs) -> bool:
    """
    This function should only be called in a function that is already used in main-thread.
    This should also mean decompilation is passed in.
    """
    ida_code_view = kwargs.get('ida_code_view', None)
    changes = False
    if ida_code_view is None:
        # TODO: support decompilation-less stack var setting
        _l.warning("Cannot set stack variables without a decompiler.")
        return changes

    lvars = {v.location.stkoff(): v for v in ida_code_view.cfunc.lvars if v.is_stk_var()}
    if not lvars:
        _l.warning("No stack variables found in decompilation to set. Making new ones is not supported")
        return changes

    for bs_off, bs_var in svars.items():
        if bs_off not in lvars:
            _l.warning(f"Stack variable at offset {bs_off} not found in decompilation.")
            continue

        lvar = lvars[bs_off]

        # naming:
        if bs_var.name and bs_var.name != lvar.name:
            ida_code_view.rename_lvar(lvar, bs_var.name, 1)
            changes |= True
            ida_code_view.cfunc.refresh_func_ctext()
            lvars = {v.location.stkoff(): v for v in ida_code_view.cfunc.lvars if v.is_stk_var()}

        # typing
        if bs_var.type:
            curr_ida_type_str = str(lvar.type()) if lvar.type() else None
            curr_ida_type = IDAArtifactLifter.lift_ida_type(curr_ida_type_str) if curr_ida_type_str else None
            if curr_ida_type and bs_var.type != curr_ida_type:
                new_type = convert_type_str_to_ida_type(bs_var.type)
                if new_type is None:
                    _l.warning(f"Failed to convert type string {bs_var.type} to ida type.")
                    continue

                updated_type = ida_code_view.set_lvar_type(lvar, new_type)
                if updated_type:
                    changes |= True
                    ida_code_view.cfunc.refresh_func_ctext()
                    lvars = {v.location.stkoff(): v for v in ida_code_view.cfunc.lvars if v.is_stk_var()}

    if changes:
        ida_code_view.refresh_view(True)

    return changes


@execute_write
def get_func_stack_var_info(func_addr) -> typing.Dict[int, StackVariable]:
    try:
        decompilation = ida_hexrays.decompile(func_addr)
    except ida_hexrays.DecompilationFailure:
        _l.debug("Decompiling too many functions too fast! Slow down and try that operation again.")
        return {}

    if decompilation is None:
        _l.warning("Decompiled something that gave no decompilation")
        return {}

    stack_var_info = {}

    for var in decompilation.lvars:
        if not var.is_stk_var():
            continue

        size = var.width
        name = var.name

        ida_offset = var.location.stkoff() - decompilation.get_stkoff_delta()
        bs_offset = ida_to_bs_stack_offset(func_addr, ida_offset)
        type_str = str(var.type())
        stack_var_info[bs_offset] = StackVariable(
            ida_offset, name, type_str, size, func_addr
        )

    return stack_var_info


@execute_write
def _deprecated_set_stack_vars_types(var_type_dict, ida_code_view) -> bool:
    """
    Sets the type of a stack variable, which should be a local variable.
    Take special note of the types of first two parameters used here:
    var_type_dict is a dictionary of the offsets and the new proposed type info for each offset.
    This typeinfo should be gotten either by manully making a new typeinfo object or using the
    parse_decl function. code_view is a _instance of vdui_t, which should be gotten through
    open_pseudocode() from ida_hexrays.

    This function also is special since it needs to iterate all of the stack variables an unknown amount
    of times until a fixed point of variables types not changing is met.


    @param var_type_dict:       Dict[stack_offset, ida_typeinf_t]
    @param ida_code_view:           A pointer to a vdui_t screen
    @param deci:          The libbs deci to do operations on
    @return:
    """

    data_changed = False
    fixed_point = False
    func_addr = ida_code_view.cfunc.entry_ea
    while not fixed_point:
        fixed_point = True
        for lvar in ida_code_view.cfunc.lvars:
            if lvar.is_stk_var():
                # TODO: this algorithm may need be corrected for programs with func args on the stack
                cur_off = abs(ida_to_bs_stack_offset(func_addr, lvar.location.stkoff()))
                if cur_off in var_type_dict:
                    if str(lvar.type()) != str(var_type_dict[cur_off]):
                        data_changed |= ida_code_view.set_lvar_type(lvar, var_type_dict.pop(cur_off))
                        fixed_point = False
                        # make sure to break, in case the size of lvars array has now changed
                        break

    return data_changed


#
#   IDA Comment r/w
#

@execute_write
def set_ida_comment(addr, cmt, decompiled=False):
    func = ida_funcs.get_func(addr)
    if not func:
        _l.info(f"No function found at {addr}")
        return False

    rpt = 1
    ida_code_view = None
    if decompiled:
        try:
            ida_code_view = acquire_pseudocode_vdui(func.start_ea)
        except Exception:
            pass

    # function comment
    if addr == func.start_ea:
        idc.set_func_cmt(addr, cmt, rpt)
        if ida_code_view:
            ida_code_view.refresh_view(True)
        return True

    # a comment in decompilation
    elif decompiled:
        if ida_code_view is None:
            ida_bytes.set_cmt(addr, cmt, rpt)
            return True

        eamap = ida_code_view.cfunc.get_eamap()
        decomp_obj_addr = eamap[addr][0].ea
        tl = idaapi.treeloc_t()

        # try to set a comment using the cfunc obj and normal address
        for a in [addr, decomp_obj_addr]:
            tl.ea = a
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                ida_code_view.cfunc.set_user_cmt(tl, cmt)
                ida_code_view.cfunc.save_user_cmts()
                ida_code_view.cfunc.refresh_func_ctext()

                # attempt to set until it does not fail (orphan itself)
                if not ida_code_view.cfunc.has_orphan_cmts():
                    ida_code_view.cfunc.save_user_cmts()
                    ida_code_view.refresh_view(True)
                    return True
                ida_code_view.cfunc.del_orphan_cmts()
        return False
    # a comment in disassembly
    else:
        ida_bytes.set_cmt(addr, cmt, rpt)
        return True


def get_ida_comment(addr, decompiled=True):
    # TODO: support more than just functions
    # TODO: support more than just function headers
    if decompiled and not ida_hexrays.init_hexrays_plugin():
        raise ValueError("Decompiler is not available, but you are requesting a decompiled comment")

    func = idaapi.get_func(addr)
    if func is None:
        return None

    if func.start_ea == addr:
        cmt = idc.get_func_cmt(addr, 1)
        return cmt if cmt else None


@execute_write
def set_decomp_comments(func_addr, cmt_dict: typing.Dict[int, str]):
    for addr in cmt_dict:
        ida_cmts = ida_hexrays.user_cmts_new()

        comment = cmt_dict[addr]
        tl = ida_hexrays.treeloc_t()
        tl.ea = addr
        # XXX: need a real value here at some point
        tl.itp = 90
        ida_cmts.insert(tl, ida_hexrays.citem_cmt_t(comment))

        ida_hexrays.save_user_cmts(func_addr, ida_cmts)


#
#   IDA Struct r/w
#

def bs_struct_from_tif(tif):
    if not tif.is_struct():
        return None

    size = tif.get_size()
    name = tif.get_type_name()

    # get members
    members = {}
    if size > 0:
        udt_data = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt_data):
            for udt_memb in udt_data:
                # TODO: warning if offset is not a multiple of 8 (a bit offset), we are in trouble
                byte_offset = udt_memb.offset // 8
                m_name = udt_memb.name
                m_type = udt_memb.type
                type_name = m_type.get_type_name() or str(m_type)
                m_size = m_type.get_size()
                members[byte_offset] = StructMember(name=m_name, type_=type_name, size=m_size, offset=byte_offset)

    return Struct(name=name, size=size, members=members)


@execute_write
def structs():
    if new_ida_typing_system():
        _structs = get_types(structs=True, enums=False, typedefs=False)
    else:
        _l.warning("You are using an old IDA, this will be deprecated in the future!")
        _structs = {}
        for struct_item in idautils.Structs():
            idx, sid, name = struct_item[:]
            sptr = idc.get_struc(sid)
            size = idc.get_struc_size(sptr)
            _structs[name] = Struct(name, size, {})

    return _structs

def _deprecated_get_struct(name):

    sid = idc.get_struc_id(name)
    if sid == idaapi.BADADDR:
        return None
    
    sptr = idc.get_struc(sid)
    size = idc.get_struc_size(sptr)
    _struct = Struct(name, size, {}, last_change=datetime.datetime.now(tz=datetime.timezone.utc))
    for mptr in sptr.members:
        mid = mptr.id
        m_name = idc.get_member_name(mid)
        m_off = mptr.soff
        m_type = ida_typeinf.idc_get_type(mptr.id) if mptr.has_ti() else ""
        m_size = idc.get_member_size(mptr)
        _struct.add_struct_member(m_name, m_off, m_type, m_size)

    return _struct

@execute_write
def struct(name):
    if not new_ida_typing_system():
        return _deprecated_get_struct(name)

    tid = ida_typeinf.get_named_type_tid(name)
    tif = ida_typeinf.tinfo_t()
    if tid != idaapi.BADADDR and tif.get_type_by_tid(tid) and tif.is_udt():
        return bs_struct_from_tif(tif)

    return None

@execute_write
def del_ida_struct(name) -> bool:
    sid = idc.get_struc_id(name)
    if sid == idaapi.BADADDR:
        return False

    sptr = sid if new_ida_typing_system() else idc.get_struc(sid)
    return idc.del_struc(sptr)


def expand_ida_struct(sid, new_size):
    """
    Only works in IDA 9 and up
    """
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(sid) and tif.is_udt():
        if tif.get_size() == new_size:
            return True

        udm = ida_typeinf.udm_t()
        udm.offset = 0
        idx = tif.find_udm(udm, ida_typeinf.STRMEM_LOWBND|ida_typeinf.STRMEM_SKIP_GAPS)
        if idx != -1:
            return tif.expand_udt(idx, new_size)

    return False


@execute_write
def set_ida_struct(struct: Struct) -> bool:
    new_struct_system = new_ida_typing_system()
    # first, delete any struct by the same name if it exists
    sid = idc.get_struc_id(struct.name)
    if sid != idaapi.BADADDR:
        sptr = sid if new_struct_system else idc.get_struc(sid)
        idc.del_struc(sptr)

    # now make a struct header
    idc.add_struc(ida_idaapi.BADADDR, struct.name, False)
    sid = idc.get_struc_id(struct.name)

    struct_identifier = sid if new_struct_system else idc.get_struc(sid)

    # expand the struct to the desired size
    # XXX: do not increment API here, why? Not sure, but you cant do it here.
    if get_ida_version() >= Version("9.0"):
        expand_ida_struct(sid, struct.size)
    else:
        idc.expand_struc(struct_identifier, 0, struct.size, False)

    # add every member of the struct
    for off, member in struct.members.items():
        if member.size is None:
            if member.type is None:
                raise ValueError("Member size and type cannot both be None when setting a struct!")

            type_size = type_str_to_size(member.type)
            if type_size is None:
                _l.warning(f"Failed to get size for member %s of struct %s, assuming 8!", member.name, struct.name)
                type_size = 8

            member.size = type_size

        if member.offset is None:
            member.offset = off

        # convert to ida's flag system
        mflag = convert_size_to_flag(member.size)

        # create the new member
        idc.add_struc_member(
            struct_identifier,
            member.name,
            member.offset,
            mflag,
            -1,
            member.size,
        )

    return True

def _depreacated_set_ida_struct_member_types(struct: Struct) -> bool:
    # find the specific struct
    sid = idc.get_struc_id(struct.name)
    sptr = idc.get_struc(sid)
    data_changed = False

    for idx, member in enumerate(struct.members.values()):
        # set the new member type if it has one
        if member.type == "":
            continue

        # assure its convertible
        tif = convert_type_str_to_ida_type(member.type)
        if tif is None:
            continue

        # set the type
        mptr = sptr.get_member(idx)
        was_set = idc.set_member_tinfo(
            sptr,
            mptr,
            0,
            tif,
            mptr.flag
        )
        data_changed |= was_set == 1

    return data_changed


@execute_write
def set_ida_struct_member_types(bs_struct: Struct):
    if not new_ida_typing_system():
        return _depreacated_set_ida_struct_member_types(bs_struct)

    struct_tif = get_ida_type(name=bs_struct.name)
    if struct_tif is None:
        return False

    udt_data = ida_typeinf.udt_type_data_t()
    if not struct_tif.get_udt_details(udt_data):
        return False

    data_changed = False
    for member_index, udt_memb in enumerate(udt_data):
        if udt_memb.offset % 8 != 0:
            _l.warning(
                f"Struct member %s of struct %s is not byte aligned! This is currently unsupported.",
                udt_memb.name,
                bs_struct.name
            )
            continue

        byte_offset = udt_memb.offset // 8
        bs_member = bs_struct.members.get(byte_offset, None)
        if bs_member is None:
            continue

        member_tif = convert_type_str_to_ida_type(bs_member.type)
        if member_tif is None:
            _l.warning(f"Failed to convert type %s for struct member %s", bs_member.type, bs_member.name)
            continue

        if member_tif != udt_memb.type:
            struct_tif.set_udm_type(member_index, member_tif)
            data_changed |= True

    return data_changed

#
# Global Vars
#


@execute_write
def global_vars():
    gvars = {}
    known_segs = [".artifacts", ".bss"]
    for seg_name in known_segs:
        seg = idaapi.get_segm_by_name(seg_name)
        if not seg:
            continue

        for seg_ea in range(seg.start_ea, seg.end_ea):
            xrefs = idautils.XrefsTo(seg_ea)
            try:
                next(xrefs)
            except StopIteration:
                continue

            name = idaapi.get_name(seg_ea)
            if not name:
                continue

            gvars[seg_ea] = GlobalVariable(seg_ea, name)

    return gvars


@execute_write
def global_var(addr):
    name = idaapi.get_name(addr)
    if not name:
        return None

    type_ = idc.get_type(addr)
    size = idaapi.get_item_size(addr)
    return GlobalVariable(addr, name, size=size, last_change=datetime.datetime.now(tz=datetime.timezone.utc), type_=type_)


@execute_write
def set_global_var_name(var_addr, name):
    return idaapi.set_name(var_addr, name)

@execute_write
def set_global_var_type(var_addr, type_str):
    """
    To make sure the type is correctly displayed (especially for arrays of structs, or arrayy of chars, a.k.a. strings),
    we first undefine the items where the type is going to be applied.
    Parse the applied type string to infer its size, and thus the number of bytes to undefine.
    """
    tif = convert_type_str_to_ida_type(type_str)
    if tif is None:
        idc.del_items(var_addr, flags=idc.DELIT_SIMPLE)
    else:
        type_size = tif.get_size()
        idc.del_items(var_addr, flags=idc.DELIT_SIMPLE, nbytes=type_size)
    return idc.SetType(var_addr, type_str)


def ida_type_from_serialized(typ: bytes, fields: bytes):
    tif = ida_typeinf.tinfo_t()
    if not tif.deserialize(ida_typeinf.get_idati(), typ, fields):
        tif = None

    return tif

#
# Enums
#


def _deprecated_get_enum_mmebers(_enum_id, max_size=100) -> typing.Dict[str, int]:
    enum_members = {}

    member = idc.get_first_enum_member(_enum_id)
    member_addr = idc.get_enum_member(_enum_id, member, 0, 0)
    member_name = idc.get_enum_member_name(member_addr)
    if member_name is None:
        return enum_members

    enum_members[member_name] = member
    
    member = idc.get_next_enum_member(_enum_id, member, 0)
    for _ in range(max_size):
        if member == idaapi.BADADDR:
            break

        member_addr = idc.get_enum_member(_enum_id, member, 0, 0)
        member_name = idc.get_enum_member_name(member_addr)
        if member_name:
            enum_members[member_name] = member

        member = idc.get_next_enum_member(_enum_id, member, 0)
    else:
        _l.critical(f"IDA failed to iterate all enum members for enum %s", _enum_id)

    return enum_members


def get_enum_members(_enum: typing.Union["ida_typeinf.tinfo_t", int], max_size=100) -> typing.Dict[str, int]:
    """
    _enum can either be an ida_typeinf.tinfo_t or an int (the old enum id system)

    """
    if not new_ida_typing_system():
        _enum_id: int = _enum
        return _deprecated_get_enum_mmebers(_enum_id, max_size=max_size)

    # this is an enum tif if we are here
    enum_tif: "ida_typeinf.tinfo_t" = _enum
    ei = ida_typeinf.enum_type_data_t()
    if not enum_tif.get_enum_details(ei):
        _l.error(f"IDA failed to get enum details for %s", enum_tif)
        return {}

    enum_members = {}
    for e_memb in ei:
        val = e_memb.value
        if val == -1:
            _l.warning(f"IDA failed to get enum member value for %s", e_memb)
            break

        name = e_memb.name
        if name is None:
            _l.warning(f"IDA failed to get enum member name for %s", e_memb)
            break

        enum_members[name] = val

    return enum_members


def enum_from_tif(tif):
    enum_name = tif.get_type_name()
    if not enum_name:
        return None

    enum_members = get_enum_members(tif)
    return Enum(enum_name, enum_members)


@execute_write
def enums() -> typing.Dict[str, Enum]:
    return get_types(structs=False, enums=True, typedefs=False)


@execute_write
def enum(name) -> typing.Optional[Enum]:
    new_enums = new_ida_typing_system()
    _enum = get_ida_type(name=name) if new_enums else idc.get_enum(name)
    if _enum is None or _enum == idaapi.BADADDR:
        return None

    enum_name = str(_enum.get_type_name()) if new_enums else idc.get_enum_name(_enum)
    enum_members = get_enum_members(_enum)
    return Enum(enum_name, enum_members)


@execute_write
def set_enum(bs_enum: Enum):
    _enum = idc.get_enum(bs_enum.name)
    if not _enum:
        return False

    idc.del_enum(_enum)
    ords = get_ordinal_count()
    enum_id = idc.add_enum(ords, bs_enum.name, 0)

    if enum_id is None:
        _l.warning(f"IDA failed to create a new enum with {bs_enum.name}")
        return False

    for member_name, value in bs_enum.members.items():
        idc.add_enum_member(enum_id, member_name, value)

    return True

#
# Typedefs
#


def use_new_typedef_check():
    return get_ida_version() >= Version("8.4")


def typedef_info(tif, use_new_check=False) -> typing.Tuple[bool, typing.Optional[str], typing.Optional[str]]:
    invalid_typedef = False, None, None
    tdef_checker = lambda t: t.is_typedef() if use_new_check else t.is_typeref()
    if not tdef_checker(tif):
        return invalid_typedef

    name = tif.get_type_name()
    type_name = tif.get_next_type_name()
    if not name:
        return invalid_typedef

    # in older versions we have to parse the type directly (thanks @arizvisa)
    if not type_name:
        ser_info = idaapi.get_named_type(None, name, idaapi.NTF_TYPE)
        ser_bytes = ser_info[1]
        if ser_info is not None:
            base_tif = ida_typeinf.tinfo_t()
            found_base_type = base_tif.deserialize(idaapi.get_idati(), ser_bytes, None, None)
            if not base_tif.is_struct():
                type_name = str(base_tif) if found_base_type else None

    if not name or not type_name or name == type_name:
        return invalid_typedef

    return True, name, type_name


@execute_write
def typedefs() -> typing.Dict[str, Typedef]:
    return get_types(structs=False, enums=False, typedefs=True)


@execute_write
def typedef(name) -> typing.Optional[Typedef]:
    idati = idaapi.get_idati()
    tif = ida_typeinf.tinfo_t()
    success = tif.get_named_type(idati, name)
    if not success:
        return None

    is_typedef, name, type_name = typedef_info(tif, use_new_check=use_new_typedef_check())
    if not is_typedef:
        return None

    return Typedef(name=name, type_=type_name)


def make_typedef_tif(name, type_str):
    tif = ida_typeinf.tinfo_t()
    ida_type_str = f"typedef {type_str} {name};"
    valid_parse = ida_typeinf.parse_decl(tif, None, ida_type_str, 1)
    return tif if valid_parse is not None else None


@execute_write
def set_typedef(bs_typedef: Typedef):
    type_tif = convert_type_str_to_ida_type(bs_typedef.type)
    if type_tif is None:
        _l.critical(f"Attempted to set a typedef with an invalid type: {bs_typedef.type} (does not exist)")
        return False

    typedef_tif = make_typedef_tif(bs_typedef.name, bs_typedef.type)
    typedef_tif.set_named_type(idaapi.get_idati(), bs_typedef.name, ida_typeinf.NTF_TYPE)
    return True

#
#   IDA GUI r/w
#

@execute_write
def get_image_base():
    return idaapi.get_imagebase()


@execute_write
def acquire_pseudocode_vdui(addr):
    """
    Acquires a IDA HexRays vdui pointer, which is a pointer to a pseudocode view that contains
    the cfunc which describes the code on the screen. Using this function optimizes the switching of code views
    by using in-place switching if a view is already present.

    @param addr:
    @return:
    """
    func = ida_funcs.get_func(addr)
    if not func:
        return None

    names = ["Pseudocode-%c" % chr(ord("A") + i) for i in range(5)]
    for name in names:
        widget = ida_kernwin.find_widget(name)
        if not widget:
            continue

        vu = ida_hexrays.get_widget_vdui(widget)
        break
    else:
        vu = ida_hexrays.open_pseudocode(func.start_ea, False)

    if func.start_ea != vu.cfunc.entry_ea:
        target_cfunc = ida_hexrays.decompile(func.start_ea)
        if target_cfunc is None:
            return None
        vu.switch_to(target_cfunc, False)
    else:
        vu.refresh_view(True)

    return vu


@execute_write
def refresh_pseudocode_view(ea, set_focus=True):
    """Refreshes the pseudocode view in IDA."""
    names = ["Pseudocode-%c" % chr(ord("A") + i) for i in range(5)]
    for name in names:
        widget = ida_kernwin.find_widget(name)
        if widget:
            vu = ida_hexrays.get_widget_vdui(widget)

            # Check if the address is in the same function
            func_ea = vu.cfunc.entry_ea
            func = ida_funcs.get_func(func_ea)
            if ida_funcs.func_contains(func, ea):
                vu.refresh_view(True)
                ida_kernwin.activate_widget(widget, set_focus)


class IDAViewCTX:
    @execute_write
    def __init__(self, func_addr):
        self.view = ida_hexrays.open_pseudocode(func_addr, 0)

    def __enter__(self):
        return self.view

    @execute_write
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_pseudocode_view(self.view)

    @execute_write
    def close_pseudocode_view(self, ida_vdui_t):
        if ida_vdui_t is None:
            return
        widget = ida_vdui_t.toplevel
        idaapi.close_pseudocode(widget)


def get_screen_ea():
    return idc.get_screen_ea()


@execute_write
def get_function_cursor_at():
    curr_addr = get_screen_ea()
    if curr_addr is None:
        return None, None

    return curr_addr, ida_func_addr(curr_addr)


#
# Other Utils
#

@execute_write
def get_ptr_size():
    """
    Gets the size of the ptr, which in affect tells you the bit size of the binary.

    Taken from: https://github.com/arizvisa/ida-minsc/blob/master/base/database.py
    :return: int, size in bytes
    """
    tif = ida_typeinf.tinfo_t()
    tif.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BT_VOID))
    return tif.get_size()


@execute_write
def get_binary_path():
    return idaapi.get_input_file_path()


@execute_write
def jumpto(addr):
    """
    Changes the pseudocode view to the function address provided.

    @param addr: Address of function to jump to
    @return:
    """
    idaapi.jumpto(addr)


@execute_write
def jumpto_type(type_name: str) -> None:
    """
    Changes the view to the Local Types window, focusing on the specified type.
    Does nothing if type is not found

    @param type_name: Name of the user-defined type to jump to
    @return:
    """
    tif = convert_type_str_to_ida_type(type_name)
    if tif is not None:
        ida_kernwin.open_loctypes_window(tif.get_ordinal())


@execute_write
def xrefs_to(addr):
    return list(idautils.XrefsTo(addr))


@execute_write
def wait_for_idc_initialization():
    idc.auto_wait()


def initialize_decompiler():
    return bool(ida_hexrays.init_hexrays_plugin())


def has_older_hexrays_version():
    wait_for_idc_initialization()
    try:
        vers = ida_hexrays.get_hexrays_version()
    except Exception:
        return False
    
    if not isinstance(vers, str):
        return False 

    return not vers.startswith("8.2")


@execute_write
def get_decompiler_version() -> typing.Optional[Version]:
    wait_for_idc_initialization()
    try:
        _vers = ida_hexrays.get_hexrays_version()
    except Exception as e:
        _l.critical("Failed to get decompiler version: %s", e)
        return None

    try:
        vers = Version(_vers)
    except TypeError:
        return None

    return vers


def view_to_bs_context(view, get_var=True, action: str = Context.ACT_UNKNOWN) -> typing.Optional[Context]:
    form_type = idaapi.get_widget_type(view)
    if form_type is None:
        return None

    form_to_type_name = get_form_to_type_name()
    view_name = form_to_type_name.get(form_type, "unknown")
    ctx = Context(screen_name=view_name, action=action)
    if view_name in FUNC_FORMS:
        ctx.addr = idaapi.get_screen_ea()
        func = idaapi.get_func(ctx.addr)
        if func is not None:
            ctx.func_addr = func.start_ea
            # exit early when we are still rendering the screen (no real click info)
            if action == Context.ACT_MOUSE_MOVE:
                return ctx

            if view_name == "decompilation" and get_var:
                # get lvar info at cursor
                vu = idaapi.get_widget_vdui(view)
                if vu and vu.item:
                    lvar = vu.item.get_lvar()
                    if lvar:
                        ctx.variable = lvar.name
                    if vu.cpos is not None:
                        ctx.line_number = vu.cpos.lnnum
                        ctx.col_number = vu.cpos.x

    return ctx


#
# IDA Classes
#

def generate_generic_ida_plugic_cls(cls_name=None):
    """
    This code is pretty complicated, but the gist is that we need to dynamically create this IDA Plugin entry point
    for two main reasons:
    1. We can't import PyQt5 until load time, which means this class can't be in the import
    2. Plugins are not allowed to share the same name in IDA Pro plugin init, but we want many downstream people
        to be able to import this class and modify it

    Below the class gets dynamically created and, if you provide a name, we copy the direct contents of that class
    into a new Python type, essentially making a new class of the exact same contents
    """
    from PyQt5.Qt import QObject

    class GenericIDAPlugin(QObject, idaapi.plugin_t):
        """Plugin entry point. Does most of the skinning magic."""
        flags = idaapi.PLUGIN_FIX

        def __init__(self, *args, name=None, comment=None, interface=None, **kwargs):
            QObject.__init__(self, *args, **kwargs)
            idaapi.plugin_t.__init__(self)
            self.wanted_name = name or "generic_libbs_plugin"
            self.comment = comment or "A generic LibBS plugin"
            self.interface: "IDAInterface" = interface

        def init(self):
            self.interface._init_gui_hooks()
            return idaapi.PLUGIN_KEEP

        def run(self, arg):
            pass

        def term(self):
            self.interface.decompiler_closed_event()
            del self.interface

    cls = GenericIDAPlugin
    if cls_name is not None:
        cls = type(cls_name, (QObject, idaapi.plugin_t), dict(GenericIDAPlugin.__dict__))

    return cls


class GenericAction(idaapi.action_handler_t):
    def __init__(self, action_target, action_function, deci=None):
        idaapi.action_handler_t.__init__(self)
        self.action_target = action_target
        self.action_function = action_function
        self.deci: IDAInterface = deci

    def activate(self, ctx):
        if ctx is None or ctx.action != self.action_target:
            return

        bs_ctx = view_to_bs_context(ctx.widget)
        if bs_ctx is None:
            return

        bs_ctx = self.deci.art_lifter.lift(bs_ctx)
        dec_view = ida_hexrays.get_widget_vdui(ctx.widget)
        self.action_function(bs_ctx, deci=self.deci, context=bs_ctx)

        if dec_view is not None:
            dec_view.refresh_view(False)

        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def ask_choice(question, choices, title="Choose an option"):
    class MyForm(idaapi.Form):
        def __init__(self, options):
            self.dropdown = idaapi.Form.DropdownListControl(items=options)
            form_string = ("STARTITEM 0\n"
                           f"{title}\n"
                           f"{question}\n"
                           "<Options:{dropdown}>")
            idaapi.Form.__init__(self, form_string, {'dropdown': self.dropdown})

    # Instantiate and display the form
    form = MyForm(choices)
    form.Compile()
    ok = form.Execute()
    if ok == 1:
        selected_index = form.dropdown.value
        selected_item = choices[selected_index]
    else:
        selected_item = ""
    form.Free()
    return selected_item

