import typing
import threading

from ...artifacts import FunctionHeader, Function, FunctionArgument, StackVariable, GlobalVariable, Struct

if typing.TYPE_CHECKING:
    from libbs.decompilers.ghidra.compat.ghidra_api import GhidraAPIWrapper

def create_data_monitor(ghidra: "GhidraAPIWrapper", interface):
    model = ghidra.import_module("ghidra.framework.model")
    class DataMonitor(model.DomainObjectListener):
        def __init__(self, interface):
            self._interface = interface
            self.changeManager = ghidra.import_module_object("ghidra.program.util", "ChangeManager")
            self.programChangeRecord = ghidra.import_module_object("ghidra.program.util", "ProgramChangeRecord")
            self.db = ghidra.import_module("ghidra.program.database")
        def domainObjectChanged(self, ev):
            funcEvents = [
                self.changeManager.DOCR_FUNCTION_CHANGED,
                self.changeManager.DOCR_FUNCTION_BODY_CHANGED,
                self.changeManager.DOCR_VARIABLE_REFERENCE_ADDED,
                self.changeManager.DOCR_VARIABLE_REFERENCE_REMOVED
            ]

            symDelEvents = [self.changeManager.DOCR_SYMBOL_REMOVED]

            symChgEvents = [
                self.changeManager.DOCR_SYMBOL_ADDED,
                self.changeManager.DOCR_SYMBOL_RENAMED,
                self.changeManager.DOCR_SYMBOL_DATA_CHANGED
            ]

            typeEvents = [
                self.changeManager.DOCR_DATA_TYPE_CHANGED,
                self.changeManager.DOCR_DATA_TYPE_REPLACED,
                self.changeManager.DOCR_DATA_TYPE_RENAMED,
                self.changeManager.DOCR_DATA_TYPE_SETTING_CHANGED,
                self.changeManager.DOCR_DATA_TYPE_MOVED,
                self.changeManager.DOCR_DATA_TYPE_ADDED
            ]

            # TODO: enum changes?

            for record in ev:
                # Note: This excludes type changes anything as they are DomainObjectChangeRecord
                if not "ProgramChangeRecord" in str(type(record)):
                    continue

                changeType = record.getEventType()
                newValue = record.getNewValue()
                oldValue = record.getOldValue()
                obj = record.getObject()

                if changeType in funcEvents:
                    funcAddr = record.getStart().getOffset()
                    pass
                elif changeType in typeEvents:
                    # TODO: find how to seperate struct and enum
                    gstruct = self._interface._get_struct_by_name(newValue)
                    members = self._interface._struct_members_from_gstruct(newValue)
                    struct = Struct(newValue, gstruct.getLength(), members=members)
                    self._interface.struct_changed(struct)
                elif changeType in symDelEvents:
                    # Currently unused and unsupported
                    pass
                elif changeType in symChgEvents:
                    if obj == None and newValue != None:
                        obj = newValue

                    if "VariableSymbolDB" in str(type(obj)):
                        if oldValue and newValue:
                            stackVar = StackVariable(None, newValue, None, None, None)
                            self._interface.stack_variable_changed(stackVar)
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
                    elif "CodeSymbol" in str(type(obj)):
                        # NOTE: GlobalVariables do not trigger this
                        gVar = GlobalVariable(None, newValue)
                        self._interface.global_variable_changed(gVar)
                        continue
                    elif "FunctionSymbol" in str(type(obj)):
                        header = FunctionHeader(newValue, None)
                        self._interface.function_header_changed(header)
                    elif "FunctionDB" in str(type(obj)):
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
