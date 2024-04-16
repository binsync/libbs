import typing
import threading

from ...artifacts import FunctionHeader, Function, FunctionArgument, StackVariable, GlobalVariable, Struct, Enum

if typing.TYPE_CHECKING:
    from libbs.decompilers.ghidra.compat.ghidra_api import GhidraAPIWrapper
    from libbs.decompilers.ghidra.interface import GhidraDecompilerInterface

def create_data_monitor(ghidra: "GhidraAPIWrapper", interface: "GhidraDecompilerInterface"):
    model = ghidra.import_module("ghidra.framework.model")
    class DataMonitor(model.DomainObjectListener):
        def __init__(self, interface: "GhidraDecompilerInterface"):
            self._interface = interface
            self.changeManager = ghidra.import_module_object("ghidra.program.util", "ChangeManager")
            self.programChangeRecord = ghidra.import_module_object("ghidra.program.util", "ProgramChangeRecord")
            self.db = ghidra.import_module("ghidra.program.database")

            # Init event lists
            self.funcEvents = [
                self.changeManager.DOCR_FUNCTION_CHANGED,
                self.changeManager.DOCR_FUNCTION_BODY_CHANGED,
                self.changeManager.DOCR_VARIABLE_REFERENCE_ADDED,
                self.changeManager.DOCR_VARIABLE_REFERENCE_REMOVED
            ]

            self.symDelEvents = [self.changeManager.DOCR_SYMBOL_REMOVED]

            self.symChgEvents = [
                self.changeManager.DOCR_SYMBOL_ADDED,
                self.changeManager.DOCR_SYMBOL_RENAMED,
                self.changeManager.DOCR_SYMBOL_DATA_CHANGED
            ]

            self.typeEvents = [
                self.changeManager.DOCR_DATA_TYPE_CHANGED,
                self.changeManager.DOCR_DATA_TYPE_REPLACED,
                self.changeManager.DOCR_DATA_TYPE_RENAMED,
                self.changeManager.DOCR_DATA_TYPE_SETTING_CHANGED,
                self.changeManager.DOCR_DATA_TYPE_MOVED,
                self.changeManager.DOCR_DATA_TYPE_ADDED
            ]
        def domainObjectChanged(self, ev):
            for record in ev:
                # NOTE: This excludes type changes anything as they are DomainObjectChangeRecord
                # print(f"Event type {record.getEventType()} caught:")
                # print(f"\tNewValue: {record.getNewValue()}")
                # print(f"\tOldValue: {record.getOldValue()}")
                # print(f"\tObjectType: {type(record.getObject())}")
                if record.getEventType() == 5:
                    print(record)
                if not self._interface.ghidra.isinstance(record, self.programChangeRecord):
                    continue

                changeType = record.getEventType()
                newValue = record.getNewValue()
                obj = record.getObject()

                if changeType in self.funcEvents:
                    pass
                elif changeType in self.typeEvents:
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
                    # Currently unused and unsupported
                    pass
                elif changeType in self.symChgEvents:
                    #if changeType == 52:
                        #print(f"Record:\n{record}")
                    if obj is None and newValue is not None:
                        obj = newValue
                    if self._interface.ghidra.isinstance(obj, self.db.function.VariableDB):
                        parent_namespace = obj.getParentNamespace()
                        storage = obj.getVariableStorage()
                        if (
                            (newValue is not None) and (storage is not None) and bool(storage.isStackStorage())
                            and (parent_namespace is not None)
                        ):
                            self._interface.stack_variable_changed(
                                self._interface.art_lifter.lift(
                                    StackVariable(
                                        int(obj.variableStorage.stackOffset),
                                        newValue,
                                        None,
                                        None,
                                        int(obj.parentNamespace.entryPoint.offset)
                                    )
                                )
                            )
                        else:
                            # TODO: figure out how to differentiate type changes
                            # print(f"VariableSymbolDB caught: {obj}")
                            # print(f"Obj type: {type(obj)}")
                            # print(f"Old value: {oldValue}")
                            # print(f"New value: {newValue}")
                            # typ = obj.getDataType()
                            # stackVar = StackVariable(None, None, typ, None, None)
                            # self._interface.stack_variable_changed(stackVar)
                            pass
                        continue
                    elif self._interface.ghidra.isinstance(obj, self.db.symbol.CodeSymbol):
                        # TODO: Find trigger for global var changes
                        # gVar = GlobalVariable(None, newValue)
                        # self._interface.global_variable_changed(gVar)
                        continue
                    elif self._interface.ghidra.isinstance(obj, self.db.symbol.FunctionSymbol):
                        header = FunctionHeader(newValue, int(obj.getAddress().offset))
                        self._interface.function_header_changed(
                            self._interface.art_lifter.lift(header)
                        )
                    elif self._interface.ghidra.isinstance(obj, self.db.function.FunctionDB):
                        # TODO: Fix argument name support
                        #changed_arg = FunctionArgument(None, newValue, None, None)
                        #header = FunctionHeader(None, None, args={None: changed_arg})
                        #self._interface.function_header_changed(header)
                        pass
                    else:
                        continue

    data_monitor = DataMonitor(interface)
    return data_monitor

def create_context_action(ghidra: "GhidraAPIWrapper", name, action_string, callback_func, category=None):
    ProgramLocationContextAction = ghidra.import_module_object("ghidra.app.context", "ProgramLocationContextAction")
    MenuData = ghidra.import_module_object("docking.action", "MenuData")

    # XXX: you can't ever use super().__init__() due to some remote import issues
    class GenericDecompilerCtxAction(ProgramLocationContextAction):
        def actionPerformed(self, ctx):
            threading.Thread(target=callback_func, daemon=True).start()

    action = GenericDecompilerCtxAction(name, category)
    category_list = category.split("/") if category else []
    category_start = category_list[0] if category_list else category
    action.setPopupMenuData(MenuData(category_list + [action_string], None, category_start))

    return action
