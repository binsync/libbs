import logging
import typing
import threading

from ...artifacts import FunctionHeader, Function, FunctionArgument, StackVariable, GlobalVariable, Struct, Enum

if typing.TYPE_CHECKING:
    from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface

_l = logging.getLogger(__name__)


def create_data_monitor(deci: "GhidraDecompilerInterface"):
    from .compat.imports import (
        DomainObjectListener, ChangeManager, ProgramChangeRecord, VariableDB, FunctionDB, CodeSymbol,
        FunctionSymbol
    )

    class DataMonitor(DomainObjectListener):
        def __init__(self, deci: "GhidraDecompilerInterface"):
            self._deci = deci
            # Init event lists
            self.funcEvents = [
                ChangeManager.DOCR_FUNCTION_CHANGED,
                ChangeManager.DOCR_FUNCTION_BODY_CHANGED,
                ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED,
                ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED
            ]

            self.symDelEvents = [ChangeManager.DOCR_SYMBOL_REMOVED]

            self.symChgEvents = [
                ChangeManager.DOCR_SYMBOL_ADDED,
                ChangeManager.DOCR_SYMBOL_RENAMED,
                ChangeManager.DOCR_SYMBOL_DATA_CHANGED
            ]

            self.typeEvents = [
                ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED,
                ChangeManager.DOCR_DATA_TYPE_CHANGED,
                ChangeManager.DOCR_DATA_TYPE_REPLACED,
                ChangeManager.DOCR_DATA_TYPE_RENAMED,
                ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED,
                ChangeManager.DOCR_DATA_TYPE_MOVED,
                ChangeManager.DOCR_DATA_TYPE_ADDED
            ]

        def domainObjectChanged(self, ev):
            try:
                self.do_change_handler(ev)
            except Exception as e:
                _l.exception("Error in domainObjectChanged: %s", e)

        def do_change_handler(self, ev):
            for record in ev:
                if not self._deci.isinstance(record, ProgramChangeRecord):
                    continue

                changeType = record.getEventType()
                newValue = record.getNewValue()
                obj = record.getObject()

                if changeType in self.funcEvents:
                    subType = record.getSubEventType()
                    if subType == ChangeManager.FUNCTION_CHANGED_RETURN:
                        # Function return type changed
                        header = FunctionHeader(
                            name=None, addr=obj.getEntryPoint().getOffset(), type_=str(obj.getReturnType())
                        )
                        self._deci.function_header_changed(header)

                elif changeType in self.typeEvents:
                    if changeType == ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                        # stack variables change address when retyped!
                        if self._deci.isinstance(obj, VariableDB):
                            parent_namespace = obj.getParentNamespace()
                            storage = obj.getVariableStorage()
                            if (
                                    (newValue is not None) and (storage is not None) and bool(storage.isStackStorage())
                                    and (parent_namespace is not None)
                            ):
                                sv = StackVariable(
                                    int(storage.stackOffset),
                                    None,
                                    str(obj.getDataType()),
                                    int(storage.size),
                                    int(obj.parentNamespace.entryPoint.offset)
                                )
                                self._deci.stack_variable_changed(
                                    sv
                                )

                    else:
                        try:
                            struct = self._deci.structs[newValue.name]
                            # TODO: access old name indicate deletion
                            # self._deci.struct_changed(Struct(None, None, None), deleted=True)
                            self._deci.struct_changed(struct)
                        except KeyError:
                            pass
                    if changeType == ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                        # stack variables change address when retyped!
                        if self._deci.isinstance(obj, VariableDB):
                            parent_namespace = obj.getParentNamespace()
                            storage = obj.getVariableStorage()
                            if (
                                    (newValue is not None) and (storage is not None) and bool(storage.isStackStorage())
                                    and (parent_namespace is not None)
                            ):
                                self._deci.stack_variable_changed(
                                    StackVariable(
                                        int(storage.stackOffset),
                                        None,
                                        str(obj.getDataType()),
                                        int(storage.size),
                                        int(obj.parentNamespace.entryPoint.offset)
                                    )
                                )

                    else:
                        try:
                            struct = self._deci.structs[newValue.name]
                            # TODO: access old name indicate deletion
                            # self._deci.struct_changed(Struct(None, None, None), deleted=True)
                            self._deci.struct_changed(struct)
                        except KeyError:
                            pass

                        try:
                            enum = self._deci.enums[newValue.name]
                            # self._deci.enum_changed(Enum(None, None), deleted=True)
                            self._deci.enum_changed(enum)
                        except KeyError:
                            pass

                elif changeType in self.symDelEvents:
                    # Globals are deleted first then recreated
                    if self._deci.isinstance(obj, CodeSymbol):
                        removed = GlobalVariable(obj.getAddress().getOffset(), obj.getName())
                        # deleted kwarg not yet handled by global_variable_changed
                        self._deci.global_variable_changed(removed, deleted=True)
                elif changeType in self.symChgEvents:
                    # For creation events, obj is stored in newValue
                    if obj is None and newValue is not None:
                        obj = newValue

                    if changeType == ChangeManager.DOCR_SYMBOL_ADDED:
                        if self._deci.isinstance(obj, CodeSymbol):
                            gvar = GlobalVariable(obj.getAddress().getOffset(), obj.getName())
                            self._deci.global_variable_changed(gvar)
                    elif changeType == ChangeManager.DOCR_SYMBOL_RENAMED:
                        if self._deci.isinstance(obj, CodeSymbol):
                            gvar = GlobalVariable(obj.getAddress().getOffset(), newValue)
                            self._deci.global_variable_changed(gvar)
                        if self._deci.isinstance(obj, FunctionSymbol):
                            header = FunctionHeader(name=newValue, addr=int(obj.getAddress().offset))
                            self._deci.function_header_changed(header)
                    elif self._deci.isinstance(obj, VariableDB):
                        parent_namespace = obj.getParentNamespace()
                        storage = obj.getVariableStorage()
                        if (
                                (newValue is not None) and (storage is not None) and bool(storage.isStackStorage())
                                and (parent_namespace is not None)
                        ):
                            self._deci.stack_variable_changed(
                                StackVariable(
                                    int(obj.variableStorage.stackOffset),
                                    newValue,
                                    None,
                                    None,
                                    int(obj.parentNamespace.entryPoint.offset)
                                )
                            )
                    elif self._deci.isinstance(obj, FunctionDB):
                        # TODO: Fix argument name support
                        # changed_arg = FunctionArgument(None, newValue, None, None)
                        # header = FunctionHeader(None, None, args={None: changed_arg})
                        # self._deci.function_header_changed(header)
                        pass
                    else:
                        continue

    data_monitor = DataMonitor(deci)
    return data_monitor


def create_context_action(name, action_string, callback_func, category=None):
    from .compat.imports import ProgramLocationContextAction, MenuData

    # XXX: you can't ever use super().__init__() due to some remote import issues
    class GenericDecompilerCtxAction(ProgramLocationContextAction):
        def actionPerformed(self, ctx):
            threading.Thread(target=callback_func, daemon=True).start()

    action = GenericDecompilerCtxAction(name, category)
    category_list = category.split("/") if category else []
    category_start = category_list[0] if category_list else category
    action.setPopupMenuData(MenuData(category_list + [action_string], None, category_start))

    return action
