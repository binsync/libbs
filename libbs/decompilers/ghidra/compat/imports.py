import logging
from typing import Tuple, Iterable

_l = logging.getLogger(__name__)

from ..interface import bridge
bridge = bridge or globals().get("binsync_ghidra_bridge", None)
HEADLESS = bridge is None


def get_private_class(path: str):
    from java.lang import ClassLoader
    from jpype import JClass

    gcl = ClassLoader.getSystemClassLoader()
    return JClass(path, loader=gcl)


def import_objs(path: str, objs: Iterable[str]):
    module = bridge.remote_import(path)
    new_objs = [getattr(module, obj) for obj in objs]
    return new_objs if len(new_objs) > 1 else new_objs[0]


if HEADLESS:
    from ghidra.framework.model import DomainObjectListener
    from ghidra.program.model.symbol import SourceType, SymbolType
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.data import (
        DataTypeConflictHandler, StructureDataType, ByteDataType, EnumDataType, CategoryPath,
    )
    from ghidra.program.util import ChangeManager, ProgramChangeRecord
    from ghidra.program.database.function import VariableDB, FunctionDB
    from ghidra.program.database.symbol import CodeSymbol, FunctionSymbol
    from ghidra.program.model.listing import CodeUnit
    from ghidra.app.cmd.comments import SetCommentCmd
    from ghidra.app.cmd.label import RenameLabelCmd
    from ghidra.app.context import ProgramLocationContextAction
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.util.cparser.C import CParserUtils
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.util.data import DataTypeParser
    from ghidra.util.exception import CancelledException
    from docking.action import MenuData

    EnumDB = get_private_class("ghidra.program.database.data.EnumDB")
    StructureDB = get_private_class("ghidra.program.database.data.StructureDB")
else:
    DomainObjectListener = import_objs("ghidra.framework.model", ("DomainObjectListener",))
    SourceType, SymbolType = import_objs("ghidra.program.model.symbol", ("SourceType", "SymbolType"))
    HighFunctionDBUtil = import_objs("ghidra.program.model.pcode", ("HighFunctionDBUtil",))
    DataTypeConflictHandler, StructureDataType, ByteDataType, EnumDataType, CategoryPath = import_objs(
        "ghidra.program.model.data",
        ("DataTypeConflictHandler", "StructureDataType", "ByteDataType", "EnumDataType", "CategoryPath")
    )
    ChangeManager, ProgramChangeRecord = import_objs("ghidra.program.util", ("ChangeManager", "ProgramChangeRecord"))
    VariableDB, FunctionDB = import_objs("ghidra.program.database.function", ("VariableDB", "FunctionDB"))
    CodeSymbol, FunctionSymbol = import_objs("ghidra.program.database.symbol", ("CodeSymbol", "FunctionSymbol"))
    CodeUnit = import_objs("ghidra.program.model.listing", ("CodeUnit",))
    SetCommentCmd = import_objs("ghidra.app.cmd.comments", ("SetCommentCmd",))
    RenameLabelCmd = import_objs("ghidra.app.cmd.label", ("RenameLabelCmd",))
    ProgramLocationContextAction = import_objs("ghidra.app.context", ("ProgramLocationContextAction",))
    DecompInterface = import_objs("ghidra.app.decompiler", ("DecompInterface",))
    AutoAnalysisManager = import_objs("ghidra.app.plugin.core.analysis", ("AutoAnalysisManager",))
    CParserUtils = import_objs("ghidra.app.util.cparser.C", ("CParserUtils",))
    ConsoleTaskMonitor = import_objs("ghidra.util.task", ("ConsoleTaskMonitor",))
    DataTypeParser = import_objs("ghidra.util.data", ("DataTypeParser",))
    CancelledException = import_objs("ghidra.util.exception", ("CancelledException",))
    MenuData = import_objs("docking.action", ("MenuData",))
    EnumDB = import_objs("ghidra.program.database.data", ("EnumDB",))
    StructureDB = import_objs("ghidra.program.database.data", ("StructureDB",))


__all__ = [
    # forcefully imported objects
    "DomainObjectListener",
    "SourceType",
    "ChangeManager",
    "ProgramChangeRecord",
    "VariableDB",
    "FunctionDB",
    "CodeSymbol",
    "FunctionSymbol",
    "ProgramLocationContextAction",
    "MenuData",
    "HighFunctionDBUtil",
    "DataTypeConflictHandler",
    "StructureDataType",
    "ByteDataType",
    "CodeUnit",
    "SetCommentCmd",
    "EnumDataType",
    "CategoryPath",
    "EnumDB",
    "RenameLabelCmd",
    "SymbolType",
    "StructureDB",
    "ConsoleTaskMonitor",
    "DecompInterface",
    "AutoAnalysisManager",
    "DataTypeParser",
    "CParserUtils",
    "CancelledException"
    "EnumDB",
    "StructureDB",
]
