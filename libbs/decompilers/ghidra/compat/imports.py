
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

from java.lang import ClassLoader
from jpype import JClass


def get_private_class(path: str):
    gcl = ClassLoader.getSystemClassLoader()
    return JClass(path, loader=gcl)


# private imports
EnumDB = get_private_class("ghidra.program.database.data.EnumDB")
StructureDB = get_private_class("ghidra.program.database.data.StructureDB")


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
