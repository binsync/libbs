from typing import Type
import logging

from libbs.data import (
    Artifact, Comment, Enum, FunctionHeader, Function, FunctionArgument,
    GlobalVariable, Patch, StackVariable, Struct, StructMember
)

_l = logging.getLogger(__name__)


class ArtifactDict(dict):
    def __init__(self, artifact_cls, decompiler_interface: "DecompilerInterface", error_on_duplicate=False):
        super().__init__()

        self._di = decompiler_interface
        self._error_on_duplicate = error_on_duplicate
        self._art_function = {
            # ArtifactType: (setter, getter, lister)
            Function: (self._di._set_function, self._di._get_function, self._di._functions),
            StackVariable: (self._di._set_stack_variable, self._di._get_stack_variable, self._di._stack_variables),
            GlobalVariable: (self._di._set_global_variable, self._di._get_global_var, self._di._global_vars),
            Struct: (self._di._set_struct, self._di._get_struct, self._di._structs),
            Enum: (self._di._set_enum, self._di._get_enum, self._di._enums),
            Comment: (self._di._set_comment, self._di._get_comment, self._di._comments),
            Patch: (self._di._set_patch, self._di._get_patch, self._di._patches)
        }

        functions = self._art_function.get(artifact_cls, None)
        if functions is None:
            raise ValueError(f"Attempting to create a dict for a Artifact class that is not supported: {artifact_cls}")

        self._artifact_class = artifact_cls
        self._artifact_setter, self._artifact_getter, self._artifact_lister = functions

    def __len__(self):
        return len(self._artifact_lister())

    def __getitem__(self, item):
        data = self._artifact_getter(item)
        if data is None:
            raise KeyError

        return data

    def __setitem__(self, key, value):
        if not self._artifact_setter(value) and self._error_on_duplicate:
            raise ValueError(f"Set value {value} is already present at key {key}")

    def __contains__(self, item):
        data = self._artifact_getter(item)
        return data is not None

    def __delitem__(self, key):
        # TODO: implement me
        pass

    def __iter__(self):
        return iter(self._artifact_lister())

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self._artifact_class.__name__} len={self.__len__()}>"

    def __str__(self):
        return f"{self._artifact_lister()}"

    def keys(self):
        return self._artifact_lister().keys()

    def values(self):
        return self._artifact_lister().values()

    def items(self):
        return self._artifact_lister().items()
