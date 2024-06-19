import logging
import typing
import threading

from ...artifacts import FunctionHeader, Function, FunctionArgument, StackVariable, GlobalVariable, Struct, Enum
from .compat.imports import (
    DomainObjectListener, ChangeManager, ProgramChangeRecord, VariableDB, FunctionDB, CodeSymbol,
    FunctionSymbol, ProgramLocationContextAction, MenuData
)

from jpype import JImplements, JOverride

if typing.TYPE_CHECKING:
    from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface

_l = logging.getLogger(__name__)


@JImplements(DomainObjectListener, deferred=False)
class DataMonitor:
    @JOverride
    def __init__(self, interface: "GhidraDecompilerInterface"):
        self._interface = interface
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

    @JOverride
    def domainObjectChanged(self, ev):
        _l.debug("Event seen: %s", ev)
        for record in ev:
            if not isinstance(record, ProgramChangeRecord):
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
                    self._interface.function_header_changed(header)

            elif changeType in self.typeEvents:
                if changeType == ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                    # stack variables change address when retyped!
                    if isinstance(obj, VariableDB):
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
                            self._interface.stack_variable_changed(
                                sv
                            )

                else:
                    try:
                        struct = self._interface.structs[newValue.name]
                        # TODO: access old name indicate deletion
                        #self._interface.struct_changed(Struct(None, None, None), deleted=True)
                        self._interface.struct_changed(struct)
                    except KeyError:
                        pass
                if changeType == ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
                    # stack variables change address when retyped!
                    if isinstance(obj, VariableDB):
                        parent_namespace = obj.getParentNamespace()
                        storage = obj.getVariableStorage()
                        if (
                                (newValue is not None) and (storage is not None) and bool(storage.isStackStorage())
                                and (parent_namespace is not None)
                        ):
                            self._interface.stack_variable_changed(
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
                        struct = self._interface.structs[newValue.name]
                        # TODO: access old name indicate deletion
                        #self._interface.struct_changed(Struct(None, None, None), deleted=True)
                        self._interface.struct_changed(struct)
                    except KeyError:
                        pass

                    try:
                        enum = self._interface.enums[newValue.name]
                        #self._interface.enum_changed(Enum(None, None), deleted=True)
                        self._interface.enum_changed(enum)
                    except KeyError:
                        pass

            elif changeType in self.symDelEvents:
                # Globals are deleted first then recreated
                if isinstance(obj, CodeSymbol):
                    removed = GlobalVariable(obj.getAddress().getOffset(), obj.getName())
                    # deleted kwarg not yet handled by global_variable_changed
                    self._interface.global_variable_changed(removed, deleted=True)
            elif changeType in self.symChgEvents:
                # For creation events, obj is stored in newValue
                if obj is None and newValue is not None:
                    obj = newValue

                if changeType == ChangeManager.DOCR_SYMBOL_ADDED:
                    if isinstance(obj, CodeSymbol):
                        gvar = GlobalVariable(obj.getAddress().getOffset(), obj.getName())
                        self._interface.global_variable_changed(gvar)
                elif changeType == ChangeManager.DOCR_SYMBOL_RENAMED:
                    if isinstance(obj, CodeSymbol):
                        gvar = GlobalVariable(obj.getAddress().getOffset(), newValue)
                        self._interface.global_variable_changed(gvar)
                    if isinstance(obj, FunctionSymbol):
                        header = FunctionHeader(name=newValue, addr=int(obj.getAddress().offset))
                        self._interface.function_header_changed(header)
                elif isinstance(obj, VariableDB):
                    parent_namespace = obj.getParentNamespace()
                    storage = obj.getVariableStorage()
                    if (
                            (newValue is not None) and (storage is not None) and bool(storage.isStackStorage())
                            and (parent_namespace is not None)
                    ):
                        self._interface.stack_variable_changed(
                            StackVariable(
                                int(obj.variableStorage.stackOffset),
                                newValue,
                                None,
                                None,
                                int(obj.parentNamespace.entryPoint.offset)
                            )
                        )
                elif isinstance(obj, FunctionDB):
                    # TODO: Fix argument name support
                    # changed_arg = FunctionArgument(None, newValue, None, None)
                    # header = FunctionHeader(None, None, args={None: changed_arg})
                    # self._interface.function_header_changed(header)
                    pass
                else:
                    continue


def create_data_monitor(interface: "GhidraDecompilerInterface"):
    data_monitor = DataMonitor(interface)
    return data_monitor


def create_context_action(name, action_string, callback_func, category=None):
    # TODO: you cant subclass in JPype, what are we going to do?!?
    # TODO: verify this is still broken, if so, remove the todo. Else, move this class out.
    # XXX: you can't ever use super().__init__() due to some remote import issues
    class GenericDecompilerCtxAction(ProgramLocationContextAction):
        def actionPerformed(self, ctx):
            threading.Thread(target=callback_func, daemon=True).start()

    action = GenericDecompilerCtxAction(name, category)
    category_list = category.split("/") if category else []
    category_start = category_list[0] if category_list else category
    action.setPopupMenuData(MenuData(category_list + [action_string], None, category_start))

    return action
