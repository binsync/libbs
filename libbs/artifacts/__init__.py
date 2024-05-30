from .formatting import TomlHexEncoder, ArtifactFormat
from .artifact import Artifact
from .comment import Comment
from .decompilation import Decompilation
from .enum import Enum
from .func import Function, FunctionHeader, FunctionArgument
from .global_variable import GlobalVariable
from .patch import Patch
from .stack_variable import StackVariable
from .struct import Struct, StructMember

ART_NAME_TO_CLS = {
    Function.__name__: Function,
    FunctionHeader.__name__: FunctionHeader,
    FunctionArgument.__name__: FunctionArgument,
    StackVariable.__name__: StackVariable,
    Comment.__name__: Comment,
    GlobalVariable.__name__: GlobalVariable,
    Enum.__name__: Enum,
    Struct.__name__: Struct,
    StructMember.__name__: StructMember,
    Patch.__name__: Patch,
    Decompilation.__name__: Decompilation,
}
