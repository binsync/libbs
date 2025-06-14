import inspect
import logging
import re
import threading
from collections import defaultdict
from functools import wraps
from typing import Dict, Optional, Tuple, List, Callable, Type, Union
from pathlib import Path
import os

import networkx as nx

import libbs
from libbs.api.artifact_lifter import ArtifactLifter
from libbs.api.artifact_dict import ArtifactDict
from libbs.api.type_parser import CTypeParser, CType
from libbs.configuration import LibbsConfig
from libbs.artifacts import (
    Artifact,
    Function, FunctionHeader, StackVariable,
    Comment, GlobalVariable, Patch,
    Enum, Struct, FunctionArgument, Context, Decompilation, Typedef
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


class DecompilerInterface:
    def __init__(
        self,
        # these flags should mostly be unchanged when passed through subclasses
        name: str = "generic",
        qt_version: str = "PySide6",
        default_func_prefix: str = "sub_",
        artifact_lifter: Optional[ArtifactLifter] = None,
        error_on_artifact_duplicates: bool = False,
        decompiler_available: bool = True,
        supports_undo: bool = False,
        supports_type_scopes: bool = False,
        # these flags can be changed by subclassed decis
        headless: bool = False,
        binary_path: Optional[Union[Path, str]] = None,
        init_plugin: bool = False,
        plugin_name: str = f"generic_libbs_plugin",
        config: Optional[LibbsConfig] = None,
        # [category/name] = (action_string, callback_func)
        gui_ctx_menu_actions: Optional[dict] = None,
        gui_init_args: Optional[Tuple] = None,
        gui_init_kwargs: Optional[Dict] = None,
        # [artifact_class] = list(callback_func)
        artifact_change_callbacks: Optional[Dict[Type[Artifact], List[Callable]]] = None,
        undo_event_callbacks: Optional[List[Callable]] = None,
        decompiler_opened_callbacks: Optional[List[Callable]] = None,
        decompiler_closed_callbacks: Optional[List[Callable]] = None,
        thread_artifact_callbacks: bool = True,
        force_click_recording: bool = False,
        track_mouse_moves: bool = False,
    ):
        self.name = name
        self.art_lifter = artifact_lifter
        self.type_parser = CTypeParser()
        self.supports_undo = supports_undo
        self.supports_type_scopes = supports_type_scopes
        self.qt_version = qt_version
        self.default_func_prefix = default_func_prefix
        self._error_on_artifact_duplicates = error_on_artifact_duplicates

        self.headless = headless
        self._binary_path = Path(binary_path) if binary_path else None
        self._init_plugin = init_plugin
        self._unparsed_gui_ctx_actions: dict[str, tuple[str, Callable]] = gui_ctx_menu_actions or {}
        # (category, name, action_string, callback_func)
        self._gui_ctx_menu_actions = []
        self._plugin_name = plugin_name
        self.gui_plugin = None
        self.artifact_watchers_started = False
        self.force_click_recording = force_click_recording
        self.track_mouse_moves = track_mouse_moves

        # locks
        self.artifact_write_lock = threading.Lock()

        # callback functions, keyed by Artifact class
        self.artifact_change_callbacks = artifact_change_callbacks or defaultdict(list)
        self.undo_event_callbacks = undo_event_callbacks or []
        self.decompiler_opened_callbacks = decompiler_opened_callbacks or []
        self.decompiler_closed_callbacks = decompiler_closed_callbacks or []
        self._thread_artifact_callbacks = thread_artifact_callbacks

        # artifact dict aliases:
        # these are the public API for artifacts that are used by the decompiler interface
        self.functions = ArtifactDict(Function, self, error_on_duplicate=error_on_artifact_duplicates)
        self.comments = ArtifactDict(Comment, self, error_on_duplicate=error_on_artifact_duplicates)
        self.patches = ArtifactDict(Patch, self, error_on_duplicate=error_on_artifact_duplicates)
        self.global_vars = ArtifactDict(GlobalVariable, self, error_on_duplicate=error_on_artifact_duplicates)
        self.structs = ArtifactDict(Struct, self, error_on_duplicate=error_on_artifact_duplicates, scopable=True)
        self.enums = ArtifactDict(Enum, self, error_on_duplicate=error_on_artifact_duplicates, scopable=True)
        self.typedefs = ArtifactDict(Typedef, self, error_on_duplicate=error_on_artifact_duplicates, scopable=True)

        self._decompiler_available = decompiler_available
        # override the file-saved config when one is passed in manually, otherwise
        # either load it from the filesystem or create a new one and place it there
        self.config = config if config is not None else LibbsConfig.update_or_make()

        if not self.headless:
            args = gui_init_args or []
            kwargs = gui_init_kwargs or {}
            self._init_gui_components(*args, **kwargs)
        else:
            self._init_headless_components()

        self.debug(f"Using configuration file: {self.config.save_location}")
        self.config.save()

    def _init_headless_components(self, *args, **kwargs):
        if not self._binary_path.exists():
            raise FileNotFoundError("You must provide a valid target binary path when using headless mode.")

    def _deinit_headless_components(self):
        pass

    def _init_gui_components(self, *args, **kwargs):
        from libbs.ui.version import set_ui_version
        set_ui_version(self.qt_version)

        # register a real plugin in the GUI
        if self._init_plugin:
            self.gui_plugin = self._init_gui_plugin(*args, **kwargs)

        # parse & register all context menu actions
        self.gui_register_ctx_menu_many(self._unparsed_gui_ctx_actions)

    def _init_gui_plugin(self, *args, **kwargs):
        return None

    def shutdown(self):
        if self.artifact_watchers_started:
            self.stop_artifact_watchers()
        if self.headless:
            self._deinit_headless_components()

    #
    # Public API:
    # These functions are the main API for interacting with the decompiler. In general, every function that takes
    # an Artifact (including addresses) should be in the lifted form. Additionally, every function that returns an
    # Artifact should be in the lifted form. This is to ensure that the decompiler interface is always in sync with
    # the lifter. For getting and setting artifacts, the ArtifactDicts defined in the init should be used.
    #

    #
    # GUI API
    #

    def gui_active_context(self) -> Optional[libbs.artifacts.Context]:
        """
        Returns the active location that the user is currently _clicked_ on in the decompiler.
        This is returned as a Context object, which can address and screen naming information dependent
        on the decompilers exposed data.
        """
        raise NotImplementedError

    def gui_goto(self, func_addr) -> None:
        """
        Relocates decompiler display to provided address

        @param func_addr:
        @return:
        """
        raise NotImplementedError

    def gui_show_type(self, type_name: str) -> None:
        """
        Relocates decompiler display to type definition

        Does nothing if not implemented in a subclass
        """
        pass

    def gui_register_ctx_menu(self, name, action_string, callback_func, category=None) -> bool:
        raise NotImplementedError

    def gui_ask_for_string(self, question, title="Plugin Question") -> str:
        """
        Opens a GUI dialog box that asks the user for a string. If not overriden by the decompiler interface,
        this will default to a Qt dialog box that is based on the decompilers Qt version.
        """
        from libbs.ui.utils import gui_ask_for_string
        return gui_ask_for_string(question, title=title)

    def gui_ask_for_choice(self, question: str, choices: list, title="Plugin Question") -> str:
        """
        Opens a GUI dialog box that asks the user for a choice. If not overriden by the decompiler interface,
        this will default to a Qt dialog box that is based on the decompilers Qt version.
        """
        from libbs.ui.utils import gui_ask_for_choice
        return gui_ask_for_choice(question, choices, title=title)

    def gui_popup_text(self, text: str, title: str = "Plugin Message") -> bool:
        """
        Opens a GUI dialog box that displays a message. If not overriden by the decompiler interface,
        this will default to a Qt dialog box that is based on the decompilers Qt version.
        """
        from libbs.ui.utils import gui_popup_text
        return gui_popup_text(text, title=title)

    def gui_run_on_main_thread(self, func: Callable, *args, **kwargs):
        """
        Runs the provided function on the main thread of the GUI. This is useful for updating the GUI from a
        background thread. Only in Ghidra is this useful.
        """
        return func(*args, **kwargs)

    def gui_attach_qt_window(self, qt_window: type["QWidgt"], title: str, target_window=None, position=None, *args, **kwargs) -> bool:
        """
        Attaches a Qt window to the decompiler interface. This is useful for embedding custom Qt windows
        into the decompiler interface.
        """
        raise NotImplementedError

    @staticmethod
    def _parse_ctx_menu_actions(actions:  dict[str, tuple[str, Callable]]) -> List[Tuple[str, str, str, Callable]]:
        gui_ctx_menu_actions = []
        for combined_name, items in actions.items():
            slashes = list(re.finditer("/", combined_name))
            if not slashes:
                category = ""
                name = combined_name
            else:
                last_slash = slashes[-1]
                category = combined_name[:last_slash.start()]
                name = combined_name[last_slash.start()+1:]

            gui_ctx_menu_actions.append((category, name,) + items)

        return gui_ctx_menu_actions

    def gui_register_ctx_menu_many(self, actions: dict[str, tuple[str, Callable]]):
        parsed_actions = self._parse_ctx_menu_actions(actions)
        for action in parsed_actions:
            category, name, action_string, callback_func = action
            self.gui_register_ctx_menu(name, action_string, callback_func, category=category)

    #
    # Override Mandatory API
    #

    def start_artifact_watchers(self):
        """
        Starts the artifact watchers for the decompiler. This is a special function that is called
        by the decompiler interface when the decompiler is ready to start watching for changes in the
        decompiler. This is useful for plugins that want to watch for changes in the decompiler and
        react to them.

        @return:
        """
        self.debug("Starting BinSync artifact watchers...")
        self.artifact_watchers_started = True

    def stop_artifact_watchers(self):
        """
        Stops the artifact watchers for the decompiler. This is a special function that is called
        by the decompiler interface when the decompiler is ready to stop watching for changes in the
        decompiler. This is useful for plugins that want to watch for changes in the decompiler and
        react to them.
        """
        self.debug("Stopping BinSync artifact watchers...")
        self.artifact_watchers_started = False

    @property
    def binary_base_addr(self) -> int:
        """
        Returns the base address of the binary in the decompiler. This is useful for calculating offsets
        in the binary. Also mandatory for using the lifting and lowering API.
        """
        raise NotImplementedError

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
        return self._binary_path

    def fast_get_function(self, func_addr) -> Optional[Function]:
        """
        Attempts to get a light version of the Function at func_addr.
        This function implements special logic to be faster than grabbing all light-functions, or grabbing
        a decompiled function. Use this API in the case where you may need to get a single functions info
        many times in a loop.

        @param func_addr:
        @return:
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

    def decompile(self, addr: int, map_lines=False, **kwargs) -> Optional[Decompilation]:
        lowered_addr = self.art_lifter.lower_addr(addr)
        if not self.decompiler_available:
            _l.error("Decompiler is not available.")
            return None

        sorted_funcs = sorted(self._functions().items(), key=lambda x: x[0])
        func_by_addr = {_addr: func for _addr, func in sorted_funcs}
        func = None
        if lowered_addr in func_by_addr:
            func = func_by_addr[lowered_addr]
        else:
            _l.debug(f"Address is not a function start, searching for function...")
            for func_addr, _func in sorted_funcs:
                if _func.addr <= lowered_addr < (_func.addr + _func.size):
                    func = _func
                    break

        if func is None:
            self.warning(f"Failed to find function for address {hex(lowered_addr)}")
            return None

        try:
            decompilation = self._decompile(func, map_lines=map_lines, **kwargs)
        except Exception as e:
            self.warning(f"Failed to decompile function at {hex(lowered_addr)}: {e}")
            decompilation = None

        if decompilation is not None:
            decompilation = self.art_lifter.lift(decompilation)

        return decompilation

    def xrefs_to(self, artifact: Artifact, decompile=False, only_code=False) -> List[Artifact]:
        """
        Returns a list of artifacts that reference the provided artifact.
        @param artifact: Artifact to find references to
        @param decompile: If True, decompile the function before searching for xrefs
        @return: List of artifacts that reference the provided artifact
        """
        if not isinstance(artifact, Function):
            raise ValueError("Only functions are supported for xrefs_to")

        return []

    def get_callgraph(self, only_names=False) -> nx.DiGraph:
        """
        Returns the callgraph of the binary. This is a dict of function addresses to a list of function addresses
        that the function calls.
        """
        callgraph = nx.DiGraph()
        for func in self.functions.values():
            callers = self.xrefs_to(func)
            for caller in callers:
                if isinstance(caller, Function):
                    if only_names:
                        callgraph.add_edge(caller.name, func.name)
                    else:
                        callgraph.add_edge(caller, func)

        return callgraph

    def get_dependencies(self, artifact: Artifact, decompile=True, max_resolves=50, **kwargs) -> List[Artifact]:
        if not isinstance(artifact, Function):
            raise ValueError("Only functions are supported for get_dependencies")

        # collect all xrefs to the function (for global variables)
        if decompile:
            # the function was never decompiled
            if artifact.dec_obj is None:
                # TODO: this needs to be fixed so that it still works without redecompiling. What if we want
                #   to do analysis on a function that is not set yet.
                artifact = self.functions[artifact.addr]

        art_users = self.xrefs_to(artifact, decompile=decompile)
        gvars = [art for art in art_users if isinstance(art, GlobalVariable)]

        # collect all structs/enums used in the function types
        imported_types = set()
        imported_types.add(self.get_defined_type(artifact.header.type))
        for arg in artifact.header.args.values():
            imported_types.add(self.get_defined_type(arg.type))
        for svar in artifact.stack_vars.values():
            imported_types.add(self.get_defined_type(svar.type))

        # start resolving dependencies in structs
        for _ in range(max_resolves):
            new_imports = False
            for imported_type in list(imported_types):
                if isinstance(imported_type, Struct):
                    for member in imported_type.members.values():
                        new_type = self.get_defined_type(member.type)
                        if new_type is not None and new_type not in imported_types:
                            imported_types.add(new_type)
                            new_imports = True
                            break

                    if new_imports:
                        break

                if isinstance(imported_type, Typedef):
                    new_type = self.get_defined_type(imported_type.type)
                    if new_type is not None and new_type not in imported_types:
                        imported_types.add(new_type)
                        new_imports = True

            if not new_imports:
                break
        else:
            self.warning("Max dependency resolves reached, returning partial results")

        all_deps = [art for art in list(imported_types) + gvars if art is not None]
        return all_deps

    def get_func_containing(self, addr: int) -> Optional[Function]:
        raise NotImplementedError

    def _decompile(self, function: Function, map_lines=False, **kwargs) -> Optional[Decompilation]:
        raise NotImplementedError

    def get_decompilation_object(self, function: Function, **kwargs) -> Optional[object]:
        raise NotImplementedError

    def should_watch_artifacts(self) -> bool:
        return True

    #
    # Override Optional API:
    # These are API that provide extra introspection for plugins that may rely on LibBS Interface
    #

    @property
    def default_pointer_size(self) -> int:
        """
        Returns the default pointer size of the binary. This is useful for calculating offsets
        in the binary.
        """
        raise NotImplementedError

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

    def rename_local_variables_by_names(self, func: Function, name_map: Dict[str, str], **kwargs) -> bool:
        """
        Renames local variables in a function by a name map. Note, these also include register variables
        that are normally not liftable in LibBS.
        @param func: Function to rename local variables in
        @param name_map: Dictionary of old name to new name
        @return: True if any local variables were renamed, False if otherwise
        """
        return False

    #
    # Private Artifact API:
    # Unlike the public API, every function in this section should take and return artifacts in their native (lowered)
    # form.
    #

    # functions
    def _set_function(self, func: Function, **kwargs) -> bool:
        update = False
        header = func.header
        if header is not None:
            update |= self._set_function_header(header, **kwargs)

        if func.stack_vars:
            update |= self._set_stack_variables(list(func.stack_vars.values()), **kwargs)

        return update

    def _get_function(self, addr, **kwargs) -> Optional[Function]:
        return None

    def _del_function(self, addr, **kwargs) -> bool:
        return False

    def _functions(self) -> Dict[int, Function]:
        """
        Returns a dict of libbs.Functions that contain the addr, name, and size of each function in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # stack vars
    def _set_stack_variables(self, svars: List[StackVariable], **kwargs) -> bool:
        update = False
        for svar in svars:
            update |= self._set_stack_variable(svar, **kwargs)

        return update

    def _set_stack_variable(self, svar: StackVariable, **kwargs) -> bool:
        return False

    def _get_stack_variable(self, addr: int, offset: int, **kwargs) -> Optional[StackVariable]:
        func = self._get_function(addr, **kwargs)
        if func is None:
            return None

        return func.stack_vars.get(offset, None)

    def _del_stack_variable(self, addr: int, offset: int, **kwargs) -> bool:
        return False

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

    def _del_global_var(self, addr) -> bool:
        return False

    def _global_vars(self, **kwargs) -> Dict[int, GlobalVariable]:
        """
        Returns a dict of libbs.GlobalVariable that contain the addr and size of each global var.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # structs
    def _set_struct(self, struct: Struct, header=True, members=True, **kwargs) -> bool:
        return False

    def _get_struct(self, name) -> Optional[Struct]:
        return None

    def _del_struct(self, name) -> bool:
        return False

    def _structs(self) -> Dict[str, Struct]:
        """
        Returns a dict of libbs.Structs that contain the name and size of each struct in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # enums
    def _set_enum(self, enum: Enum, **kwargs) -> bool:
        return False

    def _get_enum(self, name) -> Optional[Enum]:
        return None

    def _del_enum(self, name) -> bool:
        return False

    def _enums(self) -> Dict[str, Enum]:
        """
        Returns a dict of libbs.Enum that contain the name of the enums in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # typedefs
    def _set_typedef(self, typedef: Typedef, **kwargs) -> bool:
        return False

    def _get_typedef(self, name) -> Optional[Typedef]:
        return None

    def _del_typedef(self, name) -> bool:
        return False

    def _typedefs(self) -> Dict[str, Typedef]:
        """
        Returns a dict of libbs.Typedef that contain the name of the typedefs in the decompiler.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # patches
    def _set_patch(self, patch: Patch, **kwargs) -> bool:
        return False

    def _get_patch(self, addr) -> Optional[Patch]:
        return None

    def _del_patch(self, addr) -> bool:
        return False

    def _patches(self) -> Dict[int, Patch]:
        """
        Returns a dict of libbs.Patch that contain the addr of each Patch and the bytes.
        Note: this does not contain the live artifacts of the Artifact, only the minimum knowledge to that the Artifact
        exists. To get live artifacts, use the singleton function of the same name.

        @return:
        """
        return {}

    # comments
    def _set_comment(self, comment: Comment, **kwargs) -> bool:
        return False

    def _get_comment(self, addr) -> Optional[Comment]:
        return None

    def _del_comment(self, addr) -> bool:
        return False

    def _comments(self) -> Dict[int, Comment]:
        return {}

    # others...
    def _set_function_header(self, fheader: FunctionHeader, **kwargs) -> bool:
        return False

    #
    # Change Callback API:
    # Every callback in this group assumes the input will be decompiler-specific (lowered) and will
    # lift it ONCE inside this function. Each one will return the lifted form, for easier overriding.
    #

    def decompiler_opened_event(self, **kwargs):
        """
        This function is called when the decompiler platform this interface is running on is opened for the first time.
        In the presence of a decompiler with multiple tabs, this function will still only be called once.
        """
        for callback_func in self.decompiler_opened_callbacks:
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(**kwargs)

    def decompiler_closed_event(self, **kwargs):
        """
        This function is called when the decompiler platform this interface is running on is closing/closed.
        In the presence of a decompiler with multiple tabs, this function will still only be called once.
        """
        for callback_func in self.decompiler_closed_callbacks:
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(**kwargs)

    def gui_undo_event(self, **kwargs):
        for callback_func in self.undo_event_callbacks:
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(**kwargs)

    def gui_context_changed(self, ctx: Context, **kwargs) -> libbs.artifacts.Context:
        # XXX: should this be lifted?
        for callback_func in self.artifact_change_callbacks[Context]:
            args = (ctx,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return ctx

    def function_header_changed(self, fheader: FunctionHeader, **kwargs) -> FunctionHeader:
        lifted_fheader = self.art_lifter.lift(fheader)
        for callback_func in self.artifact_change_callbacks[FunctionHeader]:
            args = (lifted_fheader,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_fheader

    def stack_variable_changed(self, svar: StackVariable, **kwargs) -> StackVariable:
        lifted_svar = self.art_lifter.lift(svar)
        for callback_func in self.artifact_change_callbacks[StackVariable]:
            args = (lifted_svar,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_svar

    def comment_changed(self, comment: Comment, deleted=False, **kwargs) -> Comment:
        kwargs["deleted"] = deleted
        lifted_cmt = self.art_lifter.lift(comment)
        for callback_func in self.artifact_change_callbacks[Comment]:
            args = (lifted_cmt,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_cmt

    def struct_changed(self, struct: Struct, deleted=False, **kwargs) -> Struct:
        kwargs["deleted"] = deleted
        lifted_struct = self.art_lifter.lift(struct)
        for callback_func in self.artifact_change_callbacks[Struct]:
            args = (lifted_struct,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_struct

    def enum_changed(self, enum: Enum, deleted=False, **kwargs) -> Enum:
        kwargs["deleted"] = deleted
        lifted_enum = self.art_lifter.lift(enum)
        for callback_func in self.artifact_change_callbacks[Enum]:
            args = (lifted_enum,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_enum

    def typedef_changed(self, typedef: Typedef, deleted=False, **kwargs) -> Typedef:
        kwargs["deleted"] = deleted
        lifted_typedef = self.art_lifter.lift(typedef)
        for callback_func in self.artifact_change_callbacks[Typedef]:
            args = (lifted_typedef,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_typedef

    def global_variable_changed(self, gvar: GlobalVariable, **kwargs) -> GlobalVariable:
        lifted_gvar = self.art_lifter.lift(gvar)
        for callback_func in self.artifact_change_callbacks[GlobalVariable]:
            args = (lifted_gvar,)
            if self._thread_artifact_callbacks:
                threading.Thread(target=callback_func, args=args, kwargs=kwargs, daemon=True).start()
            else:
                callback_func(*args, **kwargs)

        return lifted_gvar

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

    def set_artifact(self, artifact: Artifact, lower=True, **kwargs) -> bool:
        """
        Sets a libbs Artifact into the decompilers local database. This operations allows you to change
        what the native decompiler sees with libbs Artifacts. This is different from opertions on a libbs State,
        since this is native to the decompiler

        >>> func = Function(0xdeadbeef, 0x800)
        >>> func.name = "main"
        >>> deci.set_artifact(func)

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
            artifact = self.art_lifter.lower(artifact)

        setter = set_map.get(type(artifact), None)
        if setter is None:
            _l.critical(f"Unsupported object is attempting to be set, please check your object: {artifact}")
            return False

        return setter(artifact, **kwargs)

    @staticmethod
    def get_identifiers(artifact: Artifact) -> Tuple:
        if isinstance(artifact, (Function, FunctionHeader, GlobalVariable, Patch, Comment)):
            return (artifact.addr,)
        elif isinstance(artifact, StackVariable):
            return artifact.addr, artifact.offset
        elif isinstance(artifact, FunctionArgument):
            # TODO: add addr to function arguments
            return (artifact.offset,)
        elif isinstance(artifact, (Struct, Enum, Typedef)):
            return (artifact.name,)
        else:
            raise ValueError(f"Unsupported artifact type: {type(artifact)}")

    def get_defined_type(self, type_str) -> Optional[Artifact]:
        if not type_str:
            return None

        normalized_type, scope = self.art_lifter.parse_scoped_type(type_str)
        type_: CType = self.type_parser.parse_type(normalized_type)
        if not type_:
            # it was not parseable
            return None

        # type is a primitive that returns no base type
        base_type = type_.base_type
        if base_type is None:
            return None

        # if we trigger here, it means it's not a user-defined type
        if not base_type.is_unknown:
            return None

        base_type_str = base_type.type
        lifted_scoped_type = self.art_lifter.scoped_type_to_str(base_type_str, scope)
        if lifted_scoped_type in self.structs:
            return self.structs[lifted_scoped_type]
        elif lifted_scoped_type in self.enums:
            return self.enums[lifted_scoped_type]
        elif lifted_scoped_type in self.typedefs:
            return self.typedefs[lifted_scoped_type]
        else:
            return None

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
    def find_current_decompiler(force: str = None) -> Optional[str]:
        """
        Finds the name of the current decompiler that this function is running inside of. Note, this function
        does not create an interface, but instead finds the name of the decompiler that is currently running.
        """
        available = set()

        # IDA Pro
        try:
            import idaapi
            if not force:
                return IDA_DECOMPILER
            available.add(IDA_DECOMPILER)
        except ImportError:
            pass
        try:
            import ida
            available.add(IDA_DECOMPILER)
        except ImportError:
            pass

        # angr-management
        try:
            import angr
            available.add(ANGR_DECOMPILER)
            import angrmanagement
            if DecompilerInterface._find_global_in_call_frames('workspace') is not None:
                if not force:
                    return ANGR_DECOMPILER
        except ImportError:
            pass

        # Ghidra
        # It is always available, and we don't have an import check, because when started in headless mode we create
        # the interface by which ghidra can now be imported.
        available.add(GHIDRA_DECOMPILER)
        import socket
        from libbs.decompiler_stubs.ghidra_libbs.libbs_vendored.ghidra_bridge_port import DEFAULT_SERVER_PORT
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # 2 Second Timeout
        try:
            if sock.connect_ex(('127.0.0.1', DEFAULT_SERVER_PORT)) == 0:
                if not force:
                    return GHIDRA_DECOMPILER
        except ConnectionError:
            pass
        this_obj = DecompilerInterface._find_global_in_call_frames("__this__")
        if (this_obj is not None) and (hasattr(this_obj, "currentProgram")):
            if not force:
                return GHIDRA_DECOMPILER

        # Binary Ninja
        # this check needs to be done last since there is no way to traverse the stack frame to find the correct
        # BV at this point in time.
        try:
            import binaryninja
            if not force:
                return BINJA_DECOMPILER
            available.add(BINJA_DECOMPILER)
        # error can be thrown for an invalid license
        except Exception as e:
            if "License is not valid" in str(e):
                _l.warning("Binary Ninja license is invalid, skipping...")

        if not available:
            _l.critical("LibBS was unable to find the current decompiler you are running in or any headless instances!")
            return None

        if force is not None and force not in available:
            _l.critical("LibBS was unable to force the decompiler you requested... please check your environment.")
            return None

        if force is None:
            return available.pop()

        if force in available:
            return force

    @staticmethod
    def discover(
        force_decompiler: str = None,
        interface_overrides: Optional[Dict[str, "DecompilerInterface"]] = None,
        **interface_kwargs
    ) -> Optional["DecompilerInterface"]:
        """
        This function is a special API helper that will attempt to detect the decompiler it is running in and
        return the valid BSController for that decompiler. You may also force the chosen deci.

        @param force_decompiler:    The optional string used to force a specific decompiler interface
        @param interface_overrides: The optional dict used to override the class of a decompiler interface
        @return:                    The DecompilerInterface associated with the current decompiler env
        """
        if force_decompiler and force_decompiler not in SUPPORTED_DECOMPILERS:
            raise ValueError(f"Unsupported decompiler {force_decompiler}")

        current_decompiler = DecompilerInterface.find_current_decompiler(force=force_decompiler)
        if current_decompiler == IDA_DECOMPILER:
            from libbs.decompilers.ida.interface import IDAInterface
            deci_class = IDAInterface
            extra_kwargs = {}
        elif current_decompiler == BINJA_DECOMPILER:
            from libbs.decompilers.binja.interface import BinjaInterface
            deci_class = BinjaInterface
            extra_kwargs = {"bv": DecompilerInterface._find_global_in_call_frames('bv')}
        elif current_decompiler == ANGR_DECOMPILER:
            from libbs.decompilers.angr.interface import AngrInterface
            deci_class = AngrInterface
            extra_kwargs = {"workspace": DecompilerInterface._find_global_in_call_frames('workspace')}
        elif current_decompiler == GHIDRA_DECOMPILER:
            from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface
            deci_class = GhidraDecompilerInterface
            extra_kwargs = {"flat_api": DecompilerInterface._find_global_in_call_frames('__this__')}
        else:
            raise ValueError("Please use LibBS with our supported decompiler set!")

        if interface_overrides is not None and current_decompiler in interface_overrides:
            deci_class = interface_overrides[current_decompiler]

        interface_kwargs.update(extra_kwargs)
        return deci_class(**interface_kwargs)
