import argparse
import sys
import logging
from pathlib import Path
import importlib
import importlib.resources

from yodalib.installer import YODAInstaller

_l = logging.getLogger(__name__)


def run_ghidra_ui():
    yodalib_path = Path(str(importlib.resources.files("yodalib"))).absolute()
    decompilers_path = yodalib_path / "decompilers"
    if not decompilers_path.exists():
        _l.error("Known plugins path does not exist, which means BinSync did not install correctly!")
        return False

    sys.path.insert(1, str(decompilers_path))
    plugin = importlib.import_module(f"ghidra.file_selector")
    _l.debug(f"Executing Ghidra UI...")
    return plugin.start_ui()


def install():
    YODAInstaller().install()


def main():
    parser = argparse.ArgumentParser(
            description="""
            The YODA Command Line Util. This is the script interface to YODA that allows you to install and run 
            the Ghidra UI for running plugins. 
            """,
            epilog="""
            Examples:
            yodalib --install
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install all the YODA plugins to every decompiler. 
        """
    )
    parser.add_argument(
        "--run-ghidra-ui", action="store_true", help="""
        Execute the Ghidra file selector UI for running YODA scripts.
        """
    )
    args = parser.parse_args()

    if args.install:
        install()

    if args.run_ghidra_ui:
        return run_ghidra_ui()


if __name__ == "__main__":
    main()
