import logging
from typing import Dict, Optional, List
from collections import OrderedDict, defaultdict

import idc
import idaapi
import ida_hexrays

import libbs
from libbs.api.decompiler_interface import DecompilerInterface
from libbs.artifacts import (
    StackVariable, Function, FunctionHeader, Struct, Comment, GlobalVariable, Enum, Patch, Artifact
)
from libbs.api.decompiler_interface import requires_decompilation
from . import compat
from .artifact_lifter import IDAArtifactLifter
from .hooks import ContextMenuHooks, ScreenHook, IDBHooks, IDPHooks, HexraysHooks

_l = logging.getLogger(name=__name__)


#
#   Controller
#

class IDAInterface(DecompilerInterface):
    def __init__(self, **kwargs):
        self._ctx_menu_names = []
        self._ui_hooks = []
        self._artifact_watcher_hooks = []

        super().__init__(
            name="ida", qt_version="PyQt5", artifact_lifter=IDAArtifactLifter(self),
            decompiler_available=compat.initialize_decompiler(), **kwargs
        )

        self._max_patch_size = 0xff
        self._decompiler_available = None
        self._crashing_version = False

        # GUI properties
        self._updated_ctx = None

    def _init_gui_hooks(self):
        """
        This function can only be called from inside the compat.GenericIDAPlugin and is meant for IDA code which
        should be run as a plugin.
        """
        self._ui_hooks = [
            ScreenHook(self),
            ContextMenuHooks(self, menu_strs=self._ctx_menu_names),
            IDPHooks(self),
        ]
        for hook in self._ui_hooks:
            hook.hook()

    def _init_gui_plugin(self, *args, **kwargs):
        return compat.GenericIDAPlugin(*args, name=self._plugin_name, interface=self, **kwargs)

    #
    # GUI
    #

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        resp = idaapi.ask_str("", 0, question)
        return resp if resp else ""

    def gui_ask_for_choice(self, question: str, choices: list, title="Plugin Question") -> str:
        return compat.ask_choice(question, choices, title=title)

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None) -> bool:
        # Function explaining action
        explain_action = idaapi.action_desc_t(
            name,
            action_string,
            compat.GenericAction(name, callback_func),
            "",
            action_string,
            199
        )
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(
            f"Edit/{category}/{name}" if category else f"Edit/{name}",
            name,
            idaapi.SETMENU_APP
        )
        self._ctx_menu_names.append((name, category or ""))
        return True

    #
    # Mandatory API
    #

    @property
    def binary_base_addr(self) -> int:
        return compat.get_image_base()

    @property
    def binary_hash(self) -> str:
        return idc.retrieve_input_file_md5().hex()

    @property
    def binary_path(self) -> Optional[str]:
        return compat.get_binary_path()

    def get_func_size(self, func_addr) -> int:
        func_addr = self.art_lifter.lower_addr(func_addr)
        return compat.get_func_size(func_addr)

    @property
    def decompiler_available(self) -> bool:
        if self._decompiler_available is None:
            self._decompiler_available = ida_hexrays.init_hexrays_plugin()

        return self._decompiler_available

    def xrefs_to(self, artifact: Artifact) -> List[Artifact]:
        if not isinstance(artifact, Function):
            _l.warning("xrefs_to is only implemented for functions.")
            return []

        function: Function = self.art_lifter.lower(artifact)
        ida_xrefs = compat.xrefs_to(function.addr)
        if not ida_xrefs:
            return []

        xrefs = []
        for ida_xref in ida_xrefs:
            from_func_addr = compat.ida_func_addr(ida_xref.frm)
            if from_func_addr is None:
                continue

            xrefs.append(Function(from_func_addr, 0))

        return xrefs

    def get_decompilation_object(self, function: Function, do_lower=True, **kwargs) -> Optional[object]:
        function = self.art_lifter.lower(function) if do_lower else function
        dec = idaapi.decompile(function.addr)
        if dec is None:
            return None

        return dec

    def _decompile(self, function: Function) -> Optional[str]:
        try:
            cfunc = ida_hexrays.decompile(function.addr)
        except Exception:
            return None

        return str(cfunc)

    #
    # GUI API
    #

    def start_artifact_watchers(self):
        self._artifact_watcher_hooks = [
            IDBHooks(self),
            # this hook is special because it relies on the decompiler being present, which can only be checked
            # after the plugin loading phase. this means the user will need to manually init this hook in the UI
            # either through scripting or a UI.
            HexraysHooks(self),
        ]
        for hook in self._artifact_watcher_hooks:
            hook.hook()

    def stop_artifact_watchers(self):
        for hook in self._artifact_watcher_hooks:
            hook.unhook()

    def gui_active_context(self):
        if not self._init_plugin:
            bs_func = self._ea_to_func(compat.get_screen_ea())
            if bs_func is None:
                return None

            bs_func.addr = self.art_lifter.lift_addr(bs_func.addr)
            return bs_func

        return self._updated_ctx

    def gui_goto(self, func_addr) -> None:
        func_addr = self.art_lifter.lower_addr(func_addr)
        compat.jumpto(func_addr)

    #
    # Optional API
    #

    @requires_decompilation
    def local_variable_names(self, func: Function) -> List[str]:
        dec = func.dec_obj
        if dec is None:
            return []

        return [lvar.name for lvar in dec.get_lvars() if lvar.name]

    @requires_decompilation
    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        func = self.art_lifter.lower(func)
        return compat.rename_local_variables_by_names(func, name_map)

    #
    # Artifact API
    #

    # functions
    def _set_function(self, func: Function, **kwargs) -> bool:
        """
        Overrides the normal _set_function for speed optimizations
        """
        return compat.set_function(func, headless=self.headless, decompiler_available=self.decompiler_available, **kwargs)

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        return compat.function(addr, headless=self.headless, decompiler_available=self.decompiler_available, **kwargs)

    def _functions(self) -> Dict[int, Function]:
        return compat.functions()

    # stack vars
    def _set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        return compat.set_stack_variable(svar, headless=self.headless, decompiler_available=self.decompiler_available, **kwargs)

    # global variables
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs) -> bool:
        # TODO: needs type setting implementation!
        if gvar.name:
            return compat.set_global_var_name(gvar.addr, gvar.name)

        return False

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        return compat.global_var(addr)

    def _global_vars(self, **kwargs) -> Dict[int, GlobalVariable]:
        """
        Returns a dict of libbs.GlobalVariable that contain the addr and size of each global var.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return compat.global_vars()

    # structs
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        data_changed = False
        if self._crashing_version and struct.name == "gcc_va_list":
            _l.critical(f"Syncing the struct {struct.name} in IDA Pro 8.2 <= will cause a crash. Skipping...")
            return False

        if header:
            data_changed |= compat.set_ida_struct(struct)

        if members:
            data_changed |= compat.set_ida_struct_member_types(struct)

        return data_changed

    def _get_struct(self, name) -> Optional[Struct]:
        return compat.struct(name)

    def _structs(self) -> Dict[str, Struct]:
        """
        Returns a dict of libbs.Structs that contain the name and size of each struct in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return compat.structs()

    # enums
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        return compat.set_enum(enum)

    def _get_enum(self, name) -> Optional[Enum]:
        return compat.enum(name)

    def _enums(self) -> Dict[str, Enum]:
        """
        Returns a dict of libbs.Enum that contain the name of the enums in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return compat.enums()

    # patches
    def _set_patch(self, patch: Patch, **kwargs) -> bool:
        idaapi.patch_bytes(patch.addr, patch.bytes)
        return True

    def _get_patch(self, addr) -> Optional[Patch]:
        patches = self._collect_continuous_patches(min_addr=addr-1, max_addr=addr+self._max_patch_size, stop_after_first=True)
        return patches.get(addr, None)

    def _patches(self) -> Dict[int, Patch]:
        """
        Returns a dict of libbs.Patch that contain the addr of each Patch and the bytes.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return self._collect_continuous_patches()

    # comments
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        return compat.set_ida_comment(comment.addr, comment.comment, decompiled=comment.decompiled)

    def _get_comment(self, addr) -> Optional[Comment]:
        # TODO: implement me!
        return None

    def _comments(self) -> Dict[int, Comment]:
        # TODO: implement me!
        return {}

    # others...
    def _set_function_header(self, fheader: FunctionHeader, **kwargs) -> bool:
        return compat.set_function_header(fheader)

    #
    # utils
    #

    def update_active_context(self, addr):
        bs_func = self._ea_to_func(addr)
        if bs_func is None:
            return

        bs_func.addr = self.art_lifter.lift_addr(bs_func.addr)
        self._updated_ctx = bs_func

    @staticmethod
    def _ea_to_func(addr):
        if not addr or addr == idaapi.BADADDR:
            return None

        func_addr = compat.ida_func_addr(addr)
        if func_addr is None:
            return None

        func = libbs.artifacts.Function(
            func_addr, 0, header=FunctionHeader(compat.get_func_name(func_addr), func_addr)
        )
        return func

    @staticmethod
    def _collect_continuous_patches(min_addr=None, max_addr=None, stop_after_first=False) -> Dict[int, Patch]:
        patches = {}

        def _patch_collector(ea, fpos, org_val, patch_val):
            patches[ea] = bytes([patch_val])

        if min_addr is None:
            min_addr = idaapi.inf_get_min_ea()
        if max_addr is None:
            max_addr = idaapi.inf_get_max_ea()

        if min_addr is None or max_addr is None:
            return patches

        idaapi.visit_patched_bytes(min_addr, max_addr, _patch_collector)

        # now convert into continuous patches
        continuous_patches = defaultdict(bytes)
        patch_start = None
        last_pos = None
        for pos, patch in patches.items():
            should_break = False
            if last_pos is None or pos != last_pos + 1:
                patch_start = pos

                if last_pos is not None and stop_after_first:
                    should_break = True

            continuous_patches[patch_start] += patch
            if should_break:
                break

            last_pos = pos

        # convert the patches
        continuous_patches = dict(continuous_patches)
        normalized_patches = {
            offset: Patch(offset, _bytes)
            for offset, _bytes in continuous_patches.items()
        }

        return normalized_patches

