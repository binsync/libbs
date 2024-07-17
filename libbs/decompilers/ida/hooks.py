# ----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#
# This program describes each hook in IDA that we want to overwrite on the
# startup of IDA. Each hook function/class describes a different scenario
# that we try to track when a user makes a change. For _instance, the function
# `cmt_changed` is activated every time a user changes a disassembly comment,
# allowing us to send the new comment to be queued in the Controller actions.
#
# ----------------------------------------------------------------------------
import functools
import logging
from typing import TYPE_CHECKING

from PyQt5 import QtCore
from PyQt5.QtGui import QKeyEvent

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idp
import ida_kernwin
import ida_struct
import ida_typeinf
import ida_enum
import idaapi
import idc

from . import compat
from libbs.artifacts import (
    FunctionHeader, StackVariable,
    Comment, GlobalVariable, Enum, Struct
)


if TYPE_CHECKING:
    from .interface import IDAInterface

_l = logging.getLogger(__name__)

IDA_STACK_VAR_PREFIX = "$"
IDA_CMT_CMT = "cmt"
IDA_RANGE_CMT = "range"
IDA_EXTRA_CMT = "extra"
IDA_CMT_TYPES = {IDA_CMT_CMT, IDA_EXTRA_CMT, IDA_RANGE_CMT}


def while_should_watch(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.interface.should_watch_artifacts():
            return func(self, *args, **kwargs)
        else:
            return 0

    return wrapper


#
# IDA GUI Hooks
#

class ContextMenuHooks(idaapi.UI_Hooks):
    def __init__(self, *args, menu_strs=None, **kwargs):
        idaapi.UI_Hooks.__init__(self)
        self.menu_strs = menu_strs or []

    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            for menu_str, category in self.menu_strs:
                idaapi.attach_action_to_popup(form, popup, menu_str, f"{category}/")


class ScreenHook(ida_kernwin.View_Hooks):
    def __init__(self, interface: "IDAInterface"):
        self.interface = interface
        super(ScreenHook, self).__init__()

    def view_click(self, view, event):
        form_type = idaapi.get_widget_type(view)
        decomp_view = idaapi.get_widget_vdui(view)
        if not form_type:
            return

        # check if view is decomp or disassembly before doing expensive ea lookup
        if not decomp_view and not form_type == idaapi.BWN_DISASM:
            return

        ea = idc.get_screen_ea()
        if not ea:
            return

        self.interface.update_active_context(ea)


class IDAHotkeyHook(ida_kernwin.UI_Hooks):
    def __init__(self, keys_to_pass, uiptr):
        super().__init__()
        self.keys_to_pass = keys_to_pass
        self.ui = uiptr

    def preprocess_action(self, action_name):
        uie = ida_kernwin.input_event_t()
        ida_kernwin.get_user_input_event(uie)
        key_event = uie.get_source_QEvent()
        keycode = key_event.key()
        if keycode[0] in self.keys_to_pass:
            ke = QKeyEvent(QtCore.QEvent.KeyPress, keycode[0], QtCore.Qt.NoModifier)
            # send new event
            self.ui.event(ke)
            # consume the event so ida doesn't take it
            return 1
        return 0


#
# Data Change Hooks (excludes decompilation changes)
#

class IDBHooks(ida_idp.IDB_Hooks):
    def __init__(self, interface):
        ida_idp.IDB_Hooks.__init__(self)
        self.interface: "IDAInterface" = interface
        self._seen_function_prototypes = {}

    @while_should_watch
    def local_types_changed(self):
        return 0

    @while_should_watch
    def ti_changed(self, ea, type_, fields):
        pfn = ida_funcs.get_func(ea)
        # only record return type changes
        if pfn and pfn.start_ea == ea:
            proto_tif = compat.ida_type_from_serialized(type_, fields)
            curr_ret_type = str(proto_tif.get_rettype())
            seen_ret_type = self._seen_function_prototypes.get(ea, None)
            if seen_ret_type is None:
                self._seen_function_prototypes[ea] = curr_ret_type
            elif curr_ret_type != seen_ret_type:
                self._seen_function_prototypes[ea] = curr_ret_type
                self.interface.function_header_changed(
                    FunctionHeader(None, ea, type_=curr_ret_type, args={})
                )

        return 0

    #
    # Enum Hooks
    #

    @while_should_watch
    def ida_enum_changed(self, enum_id, new_name=None, deleted=False):
        name = ida_enum.get_enum_name(enum_id)
        _enum = compat.enum(name) if not deleted else Enum(name, {})
        if new_name:
            _enum.name = new_name

        self.interface.enum_changed(_enum, deleted=deleted)

    @while_should_watch
    def enum_created(self, enum):
        self.ida_enum_changed(enum)
        return 0

    # XXX - use enum_deleted(self, id) instead?
    @while_should_watch
    def deleting_enum(self, id):
        self.ida_enum_changed(id, deleted=True)
        return 0

    # XXX - use enum_renamed(self, id) instead?
    @while_should_watch
    def renaming_enum(self, id, is_enum, newname):
        enum_id = id
        if not is_enum:
            enum_id = ida_enum.get_enum_member_enum(id)

        # delete it
        self.ida_enum_changed(enum_id, deleted=True)
        # readd it with the new name
        self.ida_enum_changed(enum_id, new_name=newname)
        return 0

    @while_should_watch
    def enum_bf_changed(self, id):
        return 0

    @while_should_watch
    def enum_cmt_changed(self, tid, repeatable_cmt):
        return 0

    @while_should_watch
    def enum_member_created(self, id, cid):
        self.ida_enum_changed(id)
        return 0

    # XXX - use enum_member_deleted(self, id, cid) instead?
    @while_should_watch
    def deleting_enum_member(self, id, cid):
        self.ida_enum_changed(id)
        return 0

    #
    # Struct & Stack Var Hooks
    #

    def ida_struct_changed(self, sid: int, new_name=None, deleted=False):
        # parse the info of the current struct
        struct_name = new_name if new_name else ida_struct.get_struc_name(sid)
        if struct_name.startswith(IDA_STACK_VAR_PREFIX) or struct_name.startswith("__"):
            _l.info(f"Not recording change to {struct_name} since its likely an internal IDA struct.")
            return 0

        if deleted:
            self.interface.struct_changed(Struct(struct_name, -1, {}), deleted=True)
            return 0

        struct_ptr = ida_struct.get_struc(sid)
        bs_struct = Struct(
            struct_name,
            ida_struct.get_struc_size(struct_ptr),
            {},
        )

        for mptr in struct_ptr.members:
            m_name = ida_struct.get_member_name(mptr.id)
            m_off = mptr.soff
            m_type = ida_typeinf.idc_get_type(mptr.id) if mptr.has_ti() else ""
            m_size = ida_struct.get_member_size(mptr)
            bs_struct.add_struct_member(m_name, m_off, m_type, m_size)

        self.interface.struct_changed(bs_struct, deleted=False)
        return 0

    def ida_stack_var_changed(self, sptr, mptr):
        func_addr = idaapi.get_func_by_frame(sptr.id)
        try:
            stack_var_info = compat.get_func_stack_var_info(func_addr)[
                compat.ida_to_bs_stack_offset(func_addr, mptr.soff)
            ]
        except KeyError:
            _l.debug(f"Failed to track an internal changing stack var: {mptr.id}.")
            return 0

        # find the properties of the changed stack var
        bs_offset = compat.ida_to_bs_stack_offset(func_addr, stack_var_info.offset)
        size = stack_var_info.size
        type_str = stack_var_info.type

        # TODO: correct this fix in the get_func_stack_var_info
        new_name = ida_struct.get_member_name(mptr.id)
        self.interface.stack_variable_changed(
            StackVariable(bs_offset, new_name, type_str, size, func_addr)
        )

    @while_should_watch
    def struc_created(self, tid):
        sptr = ida_struct.get_struc(tid)
        if not sptr.is_frame():
            self.ida_struct_changed(tid)

        return 0

    # XXX - use struc_deleted(self, struc_id) instead?
    @while_should_watch
    def deleting_struc(self, sptr):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id, deleted=True)

        return 0

    @while_should_watch
    def struc_align_changed(self, sptr):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    # XXX - use struc_renamed(self, sptr) instead?
    @while_should_watch
    def renaming_struc(self, id, oldname, newname):
        sptr = ida_struct.get_struc(id)
        if not sptr.is_frame():
            # delete it
            self.ida_struct_changed(id, deleted=True)
            # add it
            self.ida_struct_changed(id, new_name=newname)
        return 0

    @while_should_watch
    def struc_expanded(self, sptr):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    @while_should_watch
    def struc_member_created(self, sptr, mptr):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    @while_should_watch
    def struc_member_deleted(self, sptr, off1, off2):
        if not sptr.is_frame():
            self.ida_struct_changed(sptr.id)

        return 0

    @while_should_watch
    def struc_member_renamed(self, sptr, mptr):
        if sptr.is_frame():
            self.ida_stack_var_changed(sptr, mptr)
        else:
            self.ida_struct_changed(sptr.id)

        return 0

    @while_should_watch
    def struc_member_changed(self, sptr, mptr):
        if sptr.is_frame():
            self.ida_stack_var_changed(sptr, mptr)
        else:
            self.ida_struct_changed(sptr.id)

        return 0

    @while_should_watch
    def renamed(self, ea, new_name, local_name):
        # ignore any changes landing here for structs and stack vars
        if ida_struct.is_member_id(ea) or ida_struct.get_struc(ea) or ida_enum.get_enum_name(ea):
            return 0

        ida_func = idaapi.get_func(ea)
        # symbols changing without any corresponding func is assumed to be global var
        if ida_func is None:
            self.interface.global_variable_changed(
                GlobalVariable(ea, new_name, size=idaapi.get_item_size(ea))
            )
        # function name renaming
        elif ida_func.start_ea == ea:
            self.interface.function_header_changed(
                FunctionHeader(idc.get_func_name(ida_func.start_ea), ida_func.start_ea)
            )

        return 0

    #
    # Comment handlers
    #

    def ida_comment_changed(self, comment: str, address: int, cmt_type: str):
        if cmt_type not in IDA_CMT_TYPES:
            _l.debug("An unknown IDA comment type was changed, unknown how to handle!")
            return 0

        ida_func = idaapi.get_func(address)
        func_addr = ida_func.start_ea if ida_func else None
        bs_cmt = Comment(address, comment, func_addr=func_addr)
        if cmt_type == IDA_RANGE_CMT:
            bs_cmt.decompiled = True

        if cmt_type != IDA_EXTRA_CMT:
            self.interface.comment_changed(bs_cmt, deleted=not comment)

        return 0

    @while_should_watch
    def cmt_changed(self, ea, repeatable_cmt):
        if repeatable_cmt:
            cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
            if cmt:
                self.ida_comment_changed(cmt, ea, IDA_CMT_CMT)
        return 0

    @while_should_watch
    def range_cmt_changed(self, kind, a, cmt, repeatable):
        cmt = idc.get_func_cmt(a.start_ea, repeatable)
        if cmt:
            self.ida_comment_changed(cmt, a.start_ea, IDA_RANGE_CMT)
        return 0

    @while_should_watch
    def extra_cmt_changed(self, ea, line_idx, cmt):
        cmt = ida_bytes.get_cmt(ea, 0)
        if cmt:
            self.ida_comment_changed(cmt, ea, IDA_CMT_CMT)
        return 0

    #
    # Unused handlers, to be implemented eventually
    #

    @while_should_watch
    def struc_cmt_changed(self, id, repeatable_cmt):
        """
        fullname = ida_struct.get_struc_name(id)
        if "." in fullname:
            sname, smname = fullname.split(".", 1)
        else:
            sname = fullname
            smname = ""
        cmt = ida_struct.get_struc_cmt(id, repeatable_cmt)
        """
        return 0

    @while_should_watch
    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        return 0

    @while_should_watch
    def byte_patched(self, ea, old_value):
        return 0

#
# Special event hooks
#


class IDPHooks(ida_idp.IDP_Hooks):
    def __init__(self, interface):
        self.interface: "IDAInterface" = interface
        ida_idp.IDP_Hooks.__init__(self)

    def ev_adjust_argloc(self, *args):
        return ida_idp.IDP_Hooks.ev_adjust_argloc(self, *args)

    def ev_ending_undo(self, action_name, is_undo):
        """
        This is the hook called by IDA when an undo event occurs
        action name is a vague String description of what changes occured
        is_undo specifies if this action was an undo or a redo
        """
        return 0

    def ev_replaying_undo(self, action_name, vec, is_undo):
        """
        This hook is also called by IDA during the undo
        contains the same information as ev_ending_undo
        vec also contains a short summary of changes incurred
        """
        return 0


#
# Decompilation change hooks
#

class HexraysHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self, interface, *args, **kwargs):
        # this needs to be set from the ourside before hook
        self.interface: "IDAInterface" = interface
        ida_hexrays.Hexrays_Hooks.__init__(self)

    @while_should_watch
    def lvar_name_changed(self, vdui, lvar, new_name, *args):
        self.func_arg_changed(vdui, lvar, reset_type=True, var_name=new_name)
        return 0

    @while_should_watch
    def lvar_type_changed(self, vdui, lvar, *args):
        self.func_arg_changed(vdui, lvar, reset_name=True)
        return 0

    @while_should_watch
    def cmt_changed(self, cfunc, treeloc, cmt_str, *args):
        self.interface.comment_changed(
            Comment(treeloc.ea, cmt_str, func_addr=cfunc.entry_ea, decompiled=True), deleted=not cmt_str
        )
        return 0

    #
    # helpers
    #

    def func_arg_changed(self, vdui, lvar, reset_type=False, reset_name=False, var_name=None):
        func_addr = vdui.cfunc.entry_ea
        bs_var = compat.lvar_to_bs_var(lvar, vdui=vdui, var_name=var_name)
        if not bs_var:
            return

        if reset_type:
            bs_var.type = None
        if reset_name:
            bs_var.name = None

        # proxy the change through the func header
        self.interface.function_header_changed(
            FunctionHeader(None, func_addr, args={bs_var.offset: bs_var}),
            fargs={bs_var.offset: bs_var},
        )