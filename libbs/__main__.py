import argparse
import sys
import logging
from pathlib import Path
import importlib
import importlib.resources

from libbs.plugin_installer import LibBSPluginInstaller

_l = logging.getLogger(__name__)


def run_ghidra_ui():
    libbs_path = Path(str(importlib.resources.files("libbs"))).absolute()
    decompilers_path = libbs_path / "decompilers"
    if not decompilers_path.exists():
        _l.error("Known plugins path does not exist, which means BinSync did not install correctly!")
        return False

    sys.path.insert(1, str(decompilers_path))
    plugin = importlib.import_module(f"ghidra.gui")
    _l.debug(f"Executing Ghidra UI...")
    return plugin.start_file_selector_ui()


def install():
    LibBSPluginInstaller().install()


def main():
    parser = argparse.ArgumentParser(
            description="""
            The LibBS Command Line Util. This is the script interface to LibBS that allows you to install and run 
            the Ghidra UI for running plugins. 
            """,
            epilog="""
            Examples:
            libbs --install
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install all the LibBS plugins to every decompiler. 
        """
    )
    parser.add_argument(
        "--single-decompiler-install", nargs=2, metavar=('decompiler', 'path'), help="Install DAILA into a single decompiler. Decompiler must be one of: ida, ghidra, binja, angr."
    )
    parser.add_argument(
        "--run-ghidra-ui", action="store_true", help="""
        Execute the Ghidra file selector UI for running LibBS scripts.
        """
    )
    args = parser.parse_args()

    if args.single_decompiler_install:
        decompiler, path = args.single_decompiler_install
        LibBSPluginInstaller().install(interactive=False, paths_by_target={decompiler: path})
    elif args.install:
        install()
    elif args.run_ghidra_ui:
        return run_ghidra_ui()


if __name__ == "__main__":
    main()
