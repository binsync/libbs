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

import idc, idaapi, ida_kernwin, ida_hexrays, ida_funcs, \
    ida_bytes, ida_struct, ida_idaapi, ida_typeinf, idautils, ida_enum, ida_kernwin

import libbs
from libbs.artifacts import (
    Struct, FunctionHeader, FunctionArgument, StackVariable, Function, GlobalVariable, Enum, Artifact
)

from PyQt5.Qt import QObject

if typing.TYPE_CHECKING:
    from .interface import IDAInterface

_l = logging.getLogger(__name__)

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
        self.cfunc = idaapi.decompile(addr)
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
#   Data Type Converters
#

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
def ida_to_bs_stack_offset(func_addr, ida_stack_off):
    frame = idaapi.get_frame(func_addr)
    if not frame:
        return ida_stack_off

    frame_size = idc.get_struc_size(frame)
    last_member_size = idaapi.get_member_size(frame.get_member(frame.memqty - 1))
    bs_soff = ida_stack_off - frame_size + last_member_size
    return bs_soff


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
    ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STRUCTS)
    ida_kernwin.request_refresh(ida_kernwin.IWID_STKVIEW)


@execute_write
def functions():
    blacklisted_segs = ["extern", ".plt", ".plt.sec"]
    func_addrs = list(idautils.Functions())
    funcs = {}
    for func_addr in func_addrs:
        # skip non-text segments
        if idc.get_segm_name(func_addr) in blacklisted_segs:
            continue

        func_name = get_func_name(func_addr)
        func_size = get_func_size(func_addr)
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
        for svar in func.stack_vars.values():
            changes |= set_stack_variable(
                svar, decompiler_available=decompiler_available, ida_code_view=ida_code_view, **kwargs
            )

    if changes and ida_code_view is not None:
        ida_code_view.refresh_view(changes)

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


def lvar_to_bs_var(lvar, vdui=None, var_name=None) -> typing.Optional[FunctionArgument]:
    # only func args are supported right now
    if lvar is None or vdui is None or not lvar.is_arg_var or vdui.cfunc is None or not vdui.cfunc.lvars:
        return None

    # find the offset
    var_name = var_name or lvar.name
    for offset, _lvar in enumerate(vdui.cfunc.lvars):
        if _lvar.name == var_name:
            break
    else:
        return None

    # construct the type
    type_ = str(_lvar.type())
    size = _lvar.width
    return FunctionArgument(offset, var_name, type_, size)


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

        lvar.name = new_name
        update |= True

    if update:
        ida_code_view.cfunc.refresh_func_ctext()

    return update


#
# Stack Vars
#

@execute_write
@requires_decompilation
def set_stack_variable(svar: StackVariable, decompiler_available=True, **kwargs):
    ida_code_view = kwargs.get('ida_code_view', None)
    frame = idaapi.get_frame(svar.addr)
    changes = False
    if frame is None or frame.memqty <= 0:
        _l.warning(f"Function {svar.addr:x} does not have an associated function frame. Stopping sync here!")
        return False

    if svar.type:
        ida_type = convert_type_str_to_ida_type(svar.type)
        if ida_type is None:
            _l.warning(f"IDA Failed to parse type for stack var {svar}")
            return changes

        changes |= set_stack_vars_types({svar.offset: ida_type}, ida_code_view)
        if changes:
            ida_code_view.cfunc.refresh_func_ctext()

    frame = idaapi.get_frame(svar.addr)
    if svar.name and ida_struct.set_member_name(frame, svar.offset, svar.name):
        changes |= True

    return changes

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
#   IDA Stack Var r/w
#

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
def set_stack_vars_types(var_type_dict, ida_code_view) -> bool:
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

@execute_write
def ida_get_frame(func_addr):
    return idaapi.get_frame(func_addr)


#
#   IDA Struct r/w
#

@execute_write
def structs():
    _structs = {}
    for struct_item in idautils.Structs():
        idx, sid, name = struct_item[:]
        sptr = ida_struct.get_struc(sid)
        size = ida_struct.get_struc_size(sptr)
        _structs[name] = Struct(name, size, {})
        
    return _structs

@execute_write
def struct(name):
    sid = ida_struct.get_struc_id(name)
    if sid == 0xffffffffffffffff:
        return None
    
    sptr = ida_struct.get_struc(sid)
    size = ida_struct.get_struc_size(sptr)
    _struct = Struct(name, size, {}, last_change=datetime.datetime.now(tz=datetime.timezone.utc))
    for mptr in sptr.members:
        mid = mptr.id
        m_name = ida_struct.get_member_name(mid)
        m_off = mptr.soff
        m_type = ida_typeinf.idc_get_type(mptr.id) if mptr.has_ti() else ""
        m_size = ida_struct.get_member_size(mptr)
        _struct.add_struct_member(m_name, m_off, m_type, m_size)

    return _struct

@execute_write
def set_struct_member_name(ida_struct, frame, offset, name):
    ida_struct.set_member_name(frame, offset, name)

@execute_write
def set_ida_struct(struct: Struct) -> bool:
    # first, delete any struct by the same name if it exists
    sid = ida_struct.get_struc_id(struct.name)
    if sid != 0xffffffffffffffff:
        sptr = ida_struct.get_struc(sid)
        ida_struct.del_struc(sptr)

    # now make a struct header
    ida_struct.add_struc(ida_idaapi.BADADDR, struct.name, False)
    sid = ida_struct.get_struc_id(struct.name)
    sptr = ida_struct.get_struc(sid)

    # expand the struct to the desired size
    # XXX: do not increment API here, why? Not sure, but you cant do it here.
    ida_struct.expand_struc(sptr, 0, struct.size)

    # add every member of the struct
    for off, member in struct.members.items():
        # convert to ida's flag system
        mflag = convert_size_to_flag(member.size)

        # create the new member
        ida_struct.add_struc_member(
            sptr,
            member.name,
            member.offset,
            mflag,
            None,
            member.size,
        )

    return True


@execute_write
def set_ida_struct_member_types(struct: Struct) -> bool:
    # find the specific struct
    sid = ida_struct.get_struc_id(struct.name)
    sptr = ida_struct.get_struc(sid)
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
        was_set = ida_struct.set_member_tinfo(
            sptr,
            mptr,
            0,
            tif,
            mptr.flag
        )
        data_changed |= was_set == 1

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

    size = idaapi.get_item_size(addr)
    return GlobalVariable(addr, name, size=size, last_change=datetime.datetime.now(tz=datetime.timezone.utc))


@execute_write
def set_global_var_name(var_addr, name):
    return idaapi.set_name(var_addr, name)


def ida_type_from_serialized(typ: bytes, fields: bytes):
    tif = ida_typeinf.tinfo_t()
    if not tif.deserialize(ida_typeinf.get_idati(), typ, fields):
        tif = None

    return tif

#
# Enums
#

def get_enum_members(_enum) -> typing.Dict[str, int]:
    enum_members = {}

    member = ida_enum.get_first_enum_member(_enum)
    member_addr = ida_enum.get_enum_member(_enum, member, 0, 0)
    member_name = ida_enum.get_enum_member_name(member_addr)
    if member_name is None:
        return enum_members

    enum_members[member_name] = member
    
    member = ida_enum.get_next_enum_member(_enum, member, 0)
    while member:
        if member == 0xffffffffffffffff: break
        member_addr = ida_enum.get_enum_member(_enum, member, 0, 0)
        member_name = ida_enum.get_enum_member_name(member_addr)
        if member_name:
            enum_members[member_name] = member

        member = ida_enum.get_next_enum_member(_enum, member, 0)
    return enum_members


@execute_write
def enums() -> typing.Dict[str, Enum]:
    _enums: typing.Dict[str, Enum] = {}
    for i in range(ida_enum.get_enum_qty()):
        _enum = ida_enum.getn_enum(i)
        enum_name = ida_enum.get_enum_name(_enum)
        enum_members = get_enum_members(_enum)
        _enums[enum_name] = Enum(enum_name, enum_members)
    return _enums


@execute_write
def enum(name) -> typing.Optional[Enum]:
    _enum = ida_enum.get_enum(name)
    if not _enum:
        return None
    enum_name = ida_enum.get_enum_name(_enum)
    enum_members = get_enum_members(_enum)
    return Enum(enum_name, enum_members)


@execute_write
def set_enum(bs_enum: Enum):
    _enum = ida_enum.get_enum(bs_enum.name)
    if not _enum:
        return False

    ida_enum.del_enum(_enum)
    enum_id = ida_enum.add_enum(ida_enum.get_enum_qty(), bs_enum.name, 0)

    if enum_id is None:
        _l.warning(f"IDA failed to create a new enum with {bs_enum.name}")
        return False

    for member_name, value in bs_enum.members.items():
        ida_enum.add_enum_member(enum_id, member_name, value)

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
        target_cfunc = idaapi.decompile(func.start_ea)
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
        widget = ida_vdui_t.toplevel
        idaapi.close_pseudocode(widget)


def get_screen_ea():
    return idc.get_screen_ea()


@execute_write
def get_function_cursor_at():
    curr_addr = get_screen_ea()
    if curr_addr is None:
        return None

    return ida_func_addr(curr_addr)


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
def xrefs_to(addr):
    return list(idautils.XrefsTo(addr))


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


#
# IDA Classes
#

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
        del self.interface


class GenericAction(idaapi.action_handler_t):
    def __init__(self, action_target, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_target = action_target
        self.action_function = action_function

    def activate(self, ctx):
        if ctx is None or ctx.action != self.action_target:
            return

        dec_view = ida_hexrays.get_widget_vdui(ctx.widget)
        # show a thing while we work
        #prg = QProgressDialog("Querying...", "Stop", 0, 1, None)
        #prg.show()

        self.action_function()

        # close the panel we showed while running
        #prg.setValue(1)
        #prg.close()

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
                           f"{title}\n\n"
                           f"{question}:\n"
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

