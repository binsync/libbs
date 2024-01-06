import inspect
import logging
import re
import threading
from collections import defaultdict
from functools import wraps
from typing import Dict, Optional, Union, Tuple, List, Callable, Type

import libbs
from libbs.api.artifact_lifter import ArtifactLifter
from libbs.api.artifact_dict import ArtifactDict
from libbs.api.type_parser import CTypeParser, CType
from libbs.data import (
    Artifact,
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct
)
from libbs.decompilers import SUPPORTED_DECOMPILERS, ANGR_DECOMPILER, \
    BINJA_DECOMPILER, IDA_DECOMPILER, GHIDRA_DECOMPILER

_l = logging.getLogger(name=__name__)


def requires_decompilation(f):
    @wraps(f)
    def _requires_decompilation(self, *args, **kwargs):
        if self._decompiler_available:
            for arg in args:
                if isinstance(arg, Function) and arg.dec_obj is None:
                    arg.dec_obj = self.get_decompilation_object(arg)

        return f(self, *args, **kwargs)
    return _requires_decompilation


def artifact_write_event(f):
    @wraps(f)
    def _artifact_set_event(self: "DecompilerInterface", *args, **kwargs):
        return self.artifact_set_event_handler(f, *args, **kwargs)

    return _artifact_set_event


class DummyArtifactSetLock:
    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class DecompilerInterface:
    def __init__(
        self,
        # these should usually go unchanged in public API use
        name: str = "generic",
        qt_version: str = "PySide6",
        artifact_lifter: Optional[ArtifactLifter] = None,
        error_on_artifact_duplicates: bool = False,
        decompiler_available: bool = True,
        supports_undo: bool = False,
        # these will be changed often by public API use
        headless: bool = False,
        init_plugin: bool = False,
        plugin_name: str = f"generic_libbs_plugin",
        # [category/name] = (action_string, callback_func)
        gui_ctx_menu_actions: Optional[dict] = None,
        ui_init_args: Optional[Tuple] = None,
        ui_init_kwargs: Optional[Dict] = None,
        # [artifact_class] = list(callback_func)
        artifact_write_callbacks: Optional[Dict[Type[Artifact], List[Callable]]] = None,
    ):
        self.name = name
        self.artifact_lifer = artifact_lifter
        self.type_parser = CTypeParser()
        self.supports_undo = supports_undo
        self.qt_version = qt_version
        self._error_on_artifact_duplicates = error_on_artifact_duplicates

        # GUI things
        self.headless = headless
        self._init_plugin = init_plugin
        self._unparsed_gui_ctx_actions = gui_ctx_menu_actions or {}
        # (category, name, action_string, callback_func)
        self._gui_ctx_menu_actions = []
        self._plugin_name = plugin_name
        self.gui_plugin = None
        self._artifact_watchers_started = False

        # locks
        self.artifact_write_lock = threading.Lock()

        # callback functions, keyed by Artifact class
        self.artifact_write_callbacks = artifact_write_callbacks or defaultdict(list)

        # artifact dict aliases
        self.functions = ArtifactDict(Function, self, error_on_duplicate=error_on_artifact_duplicates)
        self.comments = ArtifactDict(Comment, self, error_on_duplicate=error_on_artifact_duplicates)
        self.enums = ArtifactDict(Enum, self, error_on_duplicate=error_on_artifact_duplicates)
        self.structs = ArtifactDict(Struct, self, error_on_duplicate=error_on_artifact_duplicates)
        self.patches = ArtifactDict(Patch, self, error_on_duplicate=error_on_artifact_duplicates)
        #self.stack_vars = ArtifactDict(StackVariable, self, error_on_duplicate=error_on_artifact_duplicates)

        self._decompiler_available = decompiler_available
        if not self.headless:
            args = ui_init_args or []
            kwargs = ui_init_kwargs or {}
            self._init_ui_components(*args, **kwargs)

    #
    # Decompiler GUI API
    #

    def start_artifact_watchers(self):
        """
        Starts the artifact watchers for the decompiler. This is a special function that is called
        by the decompiler interface when the decompiler is ready to start watching for changes in the
        decompiler. This is useful for plugins that want to watch for changes in the decompiler and
        react to them.

        @return:
        """
        self.info("Starting BinSync artifact watchers...")
        self._artifact_watchers_started = True

    def stop_artifact_watchers(self):
        """
        Stops the artifact watchers for the decompiler. This is a special function that is called
        by the decompiler interface when the decompiler is ready to stop watching for changes in the
        decompiler. This is useful for plugins that want to watch for changes in the decompiler and
        react to them.
        """
        self.info("Stopping BinSync artifact watchers...")
        self._artifact_watchers_started = False

    def _init_ui_components(self, *args, **kwargs):
        from libbs.ui.version import set_ui_version
        set_ui_version(self.qt_version)

        # register a real plugin in the GUI
        if self._init_plugin:
            self.gui_plugin = self._init_gui_plugin(*args, **kwargs)

        # parse all context menu actions
        for combined_name, items in self._unparsed_gui_ctx_actions.items():
            slashes = list(re.finditer("/", combined_name))
            if not slashes:
                category = ""
                name = combined_name
            else:
                last_slash = slashes[-1]
                category = combined_name[:last_slash.start()]
                name = combined_name[last_slash.start()+1:]

            self._gui_ctx_menu_actions.append((category, name,) + items)

        # register all context menu actions
        for action in self._gui_ctx_menu_actions:
            category, name, action_string, callback_func = action
            self.register_ctx_menu_item(name, action_string, callback_func, category=category)

    def _init_gui_plugin(self, *args, **kwargs):
        return None

    def active_context(self) -> libbs.data.Function:
        """
        Returns an libbs Function. Currently only functions are supported as current contexts.
        This function will be called very frequently, so its important that its implementation is fast
        and can be done many times in the decompiler.
        """
        raise NotImplementedError

    def goto_address(self, func_addr) -> None:
        """
        Relocates decompiler display to provided address

        @param func_addr:
        @return:
        """
        raise NotImplementedError

    def register_ctx_menu_item(self, name, action_string, callback_func, category=None) -> bool:
        raise NotImplementedError

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        from libbs.ui.utils import gui_ask_for_string
        return gui_ask_for_string(question, title=title)


    #
    # Override Mandatory API:
    # These functions create a public API for things that hold a reference to the Controller from either another
    # thread or object. This is most useful for use in the UI, which can use this API to make general requests from
    # the decompiler regardless of internal decompiler API.
    #

    @property
    def binary_hash(self) -> str:
        """
        Returns a hex string of the currently loaded binary in the decompiler. For most cases,
        this will simply be a md5hash of the binary.

        @rtype: hex string
        """
        raise NotImplementedError

    @property
    def binary_path(self) -> Optional[str]:
        """
        Returns a string that is the path of the currently loaded binary. If there is no binary loaded
        then None should be returned.

        @rtype: path-like string (/path/to/binary)
        """
        raise NotImplementedError

    def get_func_size(self, func_addr) -> int:
        """
        Returns the size of a function

        @param func_addr:
        @return:
        """
        raise NotImplementedError

    @property
    def decompiler_available(self) -> bool:
        """
        @return: True if decompiler is available for decompilation, False if otherwise
        """
        return True

    def decompile(self, addr: int) -> Optional[str]:
        if not self.decompiler_available:
            _l.error("Decompiler is not available.")
            return None

        # TODO: make this a function call after transitioning decompiler artifacts to LiveState
        for search_addr in (addr, self.artifact_lifer.lower_addr(addr)):
            func_found = False
            for func_addr, func in self._functions().items():
                if func.addr <= search_addr < (func.addr + func.size):
                    func_found = True
                    break
            else:
                func = None

            if func_found:
                break
        else:
            return None

        try:
            decompilation = self._decompile(func)
        except Exception as e:
            _l.warning(f"Failed to decompile function at {hex(addr)}: {e}")
            decompilation = None

        return decompilation

    def xrefs_to(self, artifact: Artifact) -> List[Artifact]:
        """
        Returns a list of artifacts that reference the provided artifact.
        @param artifact: Artifact to find references to
        @return: List of artifacts that reference the provided artifact
        """
        return []

    def get_func_containing(self, addr: int) -> Optional[Function]:
        raise NotImplementedError

    def _decompile(self, function: Function) -> Optional[str]:
        raise NotImplementedError

    def get_decompilation_object(self, function: Function) -> Optional[object]:
        raise NotImplementedError

    #
    # Override Optional API:
    # These are API that provide extra introspection for plugins that may rely on LibBS Interface
    #

    def undo(self):
        """
        Undoes the last change made to the decompiler.
        """
        raise NotImplementedError

    def local_variable_names(self, func: Function) -> List[str]:
        """
        Returns a list of local variable names for a function. Note, these also include register variables
        that are normally not liftable in LibBS.
        @param func: Function to get local variable names for
        @return: List of local variable names
        """
        return []

    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str]) -> bool:
        """
        Renames local variables in a function by a name map. Note, these also include register variables
        that are normally not liftable in LibBS.
        @param func: Function to rename local variables in
        @param name_map: Dictionary of old name to new name
        @return: True if any local variables were renamed, False if otherwise
        """
        return False

    #
    # Artifact API:
    # These functions are the main API for interacting with the decompiler artifacts. Generally, these functions
    # should all be implemented by the decompiler interface, but in the case that they are not, they should not
    # crash the LibBS Interface.
    #

    # functions
    def _set_function(self, func: Function, **kwargs) -> bool:
        update = False
        header = func.header
        if header is not None:
            update |= self._set_function_header(header, **kwargs)

        if func.stack_vars:
            for variable in func.stack_vars.values():
                update |= self._set_stack_variable(variable, **kwargs)

        return update

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        return None

    def _functions(self) -> Dict[int, Function]:
        """
        Returns a dict of libbs.Functions that contain the addr, name, and size of each function in the decompiler.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    # stack vars
    def _set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        return False

    def _get_stack_variable(self, addr: int, offset: int, **kwargs) -> Optional[StackVariable]:
        func = self._get_function(addr, **kwargs)
        if func is None:
            return None

        return func.stack_vars.get(offset, None)

    def _stack_variables(self, **kwargs) -> Dict[int,Dict[int, StackVariable]]:
        stack_vars = defaultdict(dict)
        for addr in self._functions():
            func = self._get_function(addr, **kwargs)
            for svar in func.stack_vars.values():
                stack_vars[addr][svar.offset] = svar

        return dict(stack_vars)

    # global variables
    def _set_global_variable(self, gvar: GlobalVariable, **kwargs) -> bool:
        return False

    def _get_global_var(self, addr) -> Optional[GlobalVariable]:
        return None

    def _global_vars(self) -> Dict[int, GlobalVariable]:
        """
        Returns a dict of libbs.GlobalVariable that contain the addr and size of each global var.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    # structs
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        return False

    def _get_struct(self, name) -> Optional[Struct]:
        return None

    def _structs(self) -> Dict[str, Struct]:
        """
        Returns a dict of libbs.Structs that contain the name and size of each struct in the decompiler.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    # enums
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        return False

    def _get_enum(self, name) -> Optional[Enum]:
        return None

    def _enums(self) -> Dict[str, Enum]:
        """
        Returns a dict of libbs.Enum that contain the name of the enums in the decompiler.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    # patches
    def _set_patch(self, patch: Patch, **kwargs) -> bool:
        return False

    def _get_patch(self, addr) -> Optional[Patch]:
        return None

    def _patches(self) -> Dict[int, Patch]:
        """
        Returns a dict of libbs.Patch that contain the addr of each Patch and the bytes.
        Note: this does not contain the live data of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live data, use the singleton function of the same name.

        @return:
        """
        return {}

    # comments
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        return False

    def _get_comment(self, addr) -> Optional[Comment]:
        return None

    def _comments(self) -> Dict[int, Comment]:
        return {}

    # others...
    def _set_function_header(self, fheader: FunctionHeader, **kwargs) -> bool:
        return False

    #
    # special
    #

    def global_artifacts(self):
        """
        Returns a light version of all artifacts that are global (non function associated):
        - structs, gvars, enums

        @return:
        """
        g_artifacts = {}
        for f in [self._structs, self._global_vars, self._enums]:
            g_artifacts.update(f())

        return g_artifacts

    def global_artifact(self, lookup_item: Union[str, int]):
        """
        Returns a live libbs.data version of the Artifact located at the lookup_item location, which can
        lookup any artifact supported in `global_artifacts`

        @param lookup_item:
        @return:
        """

        if isinstance(lookup_item, int):
            return self._get_global_var(lookup_item)
        elif isinstance(lookup_item, str):
            artifact = self._get_struct(lookup_item)
            if artifact:
                return artifact

            artifact = self._get_enum(lookup_item)
            return artifact

        return None

    def set_artifact(self, artifact: Artifact, lower=True, **kwargs) -> bool:
        """
        Sets a libbs Artifact into the decompilers local database. This operations allows you to change
        what the native decompiler sees with libbs Artifacts. This is different from opertions on a libbs State,
        since this is native to the decompiler

        >>> func = Function(0xdeadbeef, 0x800)
        >>> func.name = "main"
        >>> controller.set_artifact(func)

        @param artifact:
        @param lower:       Wether to convert the Artifacts types and offset into the local decompilers format
        @return:            True if the Artifact was succesfuly set into the decompiler
        """
        set_map = {
            Function: self._set_function,
            FunctionHeader: self._set_function_header,
            StackVariable: self._set_stack_variable,
            Comment: self._set_comment,
            GlobalVariable: self._set_global_variable,
            Struct: self._set_struct,
            Enum: self._set_enum,
            Patch: self._set_patch,
            Artifact: None,
        }

        if lower:
            artifact = self.lower_artifact(artifact)

        setter = set_map.get(type(artifact), None)
        if setter is None:
            _l.critical(f"Unsupported object is attempting to be set, please check your object: {artifact}")
            return False

        return setter(artifact, **kwargs)

    #
    # Change Callback API
    # TODO: all the code in this category on_* is experimental and not ready for production use
    # all this code should be implemented in the other decompilers or moved to a different project
    #

    def function_header_changed(self, fheader: FunctionHeader, **kwargs):
        for callback_func in self.artifact_write_callbacks[FunctionHeader]:
            callback_func(fheader, **kwargs)

    def stack_variable_changed(self, svar: StackVariable, **kwargs):
        for callback_func in self.artifact_write_callbacks[StackVariable]:
            callback_func(svar, **kwargs)

    def comment_changed(self, comment: Comment, **kwargs):
        for callback_func in self.artifact_write_callbacks[Comment]:
            callback_func(comment, **kwargs)

    def struct_changed(self, struct: Struct, deleted=False, **kwargs):
        for callback_func in self.artifact_write_callbacks[Struct]:
            callback_func(struct, deleted=deleted, **kwargs)

    def enum_changed(self, enum: Enum, deleted=False, **kwargs):
        for callback_func in self.artifact_write_callbacks[Enum]:
            callback_func(enum, deleted=deleted, **kwargs)

    def global_variable_changed(self, gvar: GlobalVariable, **kwargs):
        for callback_func in self.artifact_write_callbacks[GlobalVariable]:
            callback_func(gvar, **kwargs)

    #
    # Client API & Shortcuts
    #

    def lift_artifact(self, artifact: Artifact) -> Artifact:
        return self.artifact_lifer.lift(artifact)

    def lower_artifact(self, artifact: Artifact) -> Artifact:
        return self.artifact_lifer.lower(artifact)

    #
    # Fillers:
    # A filler function is generally responsible for pulling down data from a specific user state
    # and reflecting those changes in decompiler view (like the text on the screen). Normally, these changes
    # will also be accompanied by a Git commit to the master users state to save the changes from pull and
    # fill into their BS database. In special cases, a filler may only update the decompiler UI but not directly
    # cause a save of the BS state.
    #

    def artifact_set_event_handler(
        self, setter_func, artifact: Artifact, *args, **kwargs
    ):
        """
        This function handles any event which tries to set an Artifact into the decompiler. This handler does two
        important tasks:
        1. Locks callback handlers, so you don't get infinite callbacks
        2. "Lowers" the artifact, so it's data types match the decompilers

        Because of this, it's recommended that when overriding this function you always call super() at the end of
        your override so it's set correctly in the decompiler.

        :param setter_func:
        :param artifact:
        :param args:
        :param kwargs:
        :return:
        """

        lowered_artifact = self.lower_artifact(artifact)
        lock = self.artifact_write_lock if not self.artifact_write_lock.locked() else DummyArtifactSetLock()
        with lock:
            try:
                had_changes = setter_func(lowered_artifact, **kwargs)
            except ValueError:
                had_changes = False

        return had_changes

    #
    # Special Loggers and Printers
    #

    def print(self, msg: str, **kwargs):
        print(msg)

    def info(self, msg: str, **kwargs):
        _l.info(msg)

    def debug(self, msg: str, **kwargs):
        _l.debug(msg)

    def warning(self, msg: str, **kwargs):
        _l.warning(msg)

    def error(self, msg: str, **kwargs):
        _l.error(msg)

    #
    # Utils
    #

    def type_is_user_defined(self, type_str, state=None):
        if not type_str:
            return None

        type_: CType = self.type_parser.parse_type(type_str)
        if not type_:
            # it was not parseable
            return None

        # type is known and parseable
        if not type_.is_unknown:
            return None

        base_type_str = type_.base_type.type
        return base_type_str if base_type_str in state._structs.keys() else None

    @staticmethod
    def _find_global_in_call_frames(global_name, max_frames=10):
        curr_frame = inspect.currentframe()
        outer_frames = inspect.getouterframes(curr_frame, max_frames)
        for frame in outer_frames:
            global_data = frame.frame.f_globals.get(global_name, None)
            if global_data is not None:
                return global_data
        else:
            return None

    @staticmethod
    def find_current_decompiler():
        # IDA Pro
        try:
            import idaapi
            return IDA_DECOMPILER
        except ImportError:
            pass

        # Binary Ninja
        try:
            import binaryninja
            if DecompilerInterface._find_global_in_call_frames('bv') is not None:
                return BINJA_DECOMPILER
        except ImportError:
            pass

        # angr-management
        try:
            import angr
            import angrmanagement
            if DecompilerInterface._find_global_in_call_frames('workspace') is not None:
                return ANGR_DECOMPILER
        except ImportError:
            pass

        # Ghidra (over remote) is default
        # TODO: add search for known port being open for remote Ghidra
        return GHIDRA_DECOMPILER

    @staticmethod
    def discover_interface(
        force_decompiler: str = None,
        interface_overrides: Optional[Dict[str, "DecompilerInterface"]] = None,
        **interface_kwargs
    ) -> Optional["DecompilerInterface"]:
        """
        This function is a special API helper that will attempt to detect the decompiler it is running in and
        return the valid BSController for that decompiler. You may also force the chosen controller.

        @param force_decompiler:    The optional string used to force a specific decompiler interface
        @param interface_overrides: The optional dict used to override the class of a decompiler interface
        @return:                    The DecompilerInterface associated with the current decompiler env
        """
        if force_decompiler and force_decompiler not in SUPPORTED_DECOMPILERS:
            raise ValueError(f"Unsupported decompiler {force_decompiler}")

        current_decompiler = DecompilerInterface.find_current_decompiler()
        if force_decompiler == IDA_DECOMPILER or current_decompiler == IDA_DECOMPILER:
            from libbs.decompilers.ida.interface import IDAInterface
            deci_class = IDAInterface
            extra_kwargs = {}
        elif force_decompiler == BINJA_DECOMPILER or current_decompiler == BINJA_DECOMPILER:
            from libbs.decompilers.binja.interface import BinjaInterface
            deci_class = BinjaInterface
            extra_kwargs = {"bv": DecompilerInterface._find_global_in_call_frames('bv')}
        elif force_decompiler == ANGR_DECOMPILER or current_decompiler == ANGR_DECOMPILER:
            from libbs.decompilers.angr.interface import AngrInterface
            deci_class = AngrInterface
            extra_kwargs = {"workspace": DecompilerInterface._find_global_in_call_frames('workspace')}
        elif force_decompiler == GHIDRA_DECOMPILER or current_decompiler == GHIDRA_DECOMPILER:
            from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface
            deci_class = GhidraDecompilerInterface
            extra_kwargs = {}
        else:
            raise ValueError("Please use LibBS with our supported decompiler set!")

        if interface_overrides is not None and current_decompiler in interface_overrides:
            deci_class = interface_overrides[current_decompiler]

        interface_kwargs.update(extra_kwargs)
        return deci_class(**interface_kwargs)
