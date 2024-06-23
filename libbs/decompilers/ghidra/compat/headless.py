import logging
from pathlib import Path
from typing import Union

from pyhidra.core import _setup_project, _analyze_program
from jpype import JClass

_l = logging.getLogger(__name__)


def open_program(
    binary_path: Union[str, Path],
    project_location: Union[str, Path] = None,
    project_name: str = None,
    analyze=True,
    language: str = None,
    compiler: str = None,
    loader: Union[str, JClass] = None
):
    """
    Taken from Pyhidra, but updated to also return the project associated with the program:
    https://github.com/dod-cyber-crime-center/pyhidra/blob/c878e91b53498f65f2eb0255e22189a6d172917c/pyhidra/core.py#L178
    """
    from pyhidra.launcher import PyhidraLauncher, HeadlessPyhidraLauncher

    if not PyhidraLauncher.has_launched():
        HeadlessPyhidraLauncher().start()

    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI
    project, program = _setup_project(
        binary_path,
        project_location=project_location,
        project_name=project_name,
        language=language,
        compiler=compiler,
        loader=loader
    )
    GhidraScriptUtil.acquireBundleHostReference()
    flat_api = FlatProgramAPI(program)
    if analyze:
        _analyze_program(flat_api, program)

    return flat_api, project, program


def close_program(program, project) -> bool:
    """
    Returns true if closing was successful, false otherwise.

    """
    from ghidra.app.script import GhidraScriptUtil

    try:
        GhidraScriptUtil.releaseBundleHostReference()
        project.save(program)
        project.close()
        return True
    except Exception as e:
        _l.critical("Failed to close project: %s", e)

    return False
