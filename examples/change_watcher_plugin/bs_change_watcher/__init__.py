from pathlib import Path

from libbs.plugin_installer import LibBSPluginInstaller


def create_plugin(*args, **kwargs):
    """
    This is the entry point that all decompilers will call in various ways. To remain agnostic,
    always pass the args and kwargs to the gui_init_args and gui_init_kwargs of DecompilerInterface, inited
    through the discover api.
    """

    from libbs.api import DecompilerInterface
    from libbs.artifacts import (
        FunctionHeader, StackVariable, Enum, Struct, GlobalVariable, Comment
    )

    deci = DecompilerInterface.discover(
        plugin_name="ArtifactChangeWatcher",
        init_plugin=True,
        gui_init_args=args,
        gui_init_kwargs=kwargs
    )
    # create a function to print a string in the decompiler console
    decompiler_printer = lambda *x, **y: deci.print(f"Changed {x}{y}")
    # register the callback for all the types we want to print
    deci.artifact_write_callbacks = {
        typ: [decompiler_printer] for typ in (FunctionHeader, StackVariable, Enum, Struct, GlobalVariable, Comment,)
    }

    # register a menu to open when you right click on the psuedocode view
    deci.register_ctx_menu_item(
        "StartArtifactChangeWatcher",
        "Start watching artifact changes",
        lambda: deci.start_artifact_watchers(),
        category="ArtifactChangeWatcher"
    )

    # return a plugin so the decompiler sets up the UI
    return deci.gui_plugin


class BSChangeWatcherInstaller(LibBSPluginInstaller):
    """
    This acts as a simple installer for the plugin
    """

    def __init__(self):
        super().__init__()
        self.pkg_path = self.find_pkg_files("bs_change_watcher")

    def _copy_plugin_to_path(self, path):
        src = self.pkg_path / "bs_change_watcher_plugin.py"
        dst = Path(path) / "bs_change_watcher_plugin.py"
        self.link_or_copy(src, dst, symlink=True)

    def display_prologue(self):
        print("Now installing BSChangeWatcher plugin...")

    def install_ida(self, path=None, interactive=True):
        path = super().install_ida(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_ghidra(self, path=None, interactive=True):
        path = super().install_ghidra(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_binja(self, path=None, interactive=True):
        path = super().install_binja(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_angr(self, path=None, interactive=True):
        path = super().install_angr(path=path, interactive=interactive)
        if not path:
            return

        path = path / "bs_change_watcher"
        path.mkdir(parents=True, exist_ok=True)
        src = self.pkg_path / "plugin.toml"
        dst = Path(path) / "plugin.toml"
        self.link_or_copy(src, dst, symlink=True)
        self._copy_plugin_to_path(path)
        return path
