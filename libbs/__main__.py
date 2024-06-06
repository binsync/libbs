import argparse
import sys
import logging
from pathlib import Path
import importlib
import importlib.resources

from libbs.plugin_installer import LibBSPluginInstaller

_l = logging.getLogger(__name__)


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
    args = parser.parse_args()

    if args.single_decompiler_install:
        decompiler, path = args.single_decompiler_install
        LibBSPluginInstaller().install(interactive=False, paths_by_target={decompiler: path})
    elif args.install:
        install()


if __name__ == "__main__":
    main()
