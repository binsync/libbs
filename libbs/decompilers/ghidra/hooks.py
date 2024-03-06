import typing
import threading

if typing.TYPE_CHECKING:
    from libbs.decompilers.ghidra.compat.ghidra_api import GhidraAPIWrapper

def create_data_monitor(ghidra: "GhidraAPIWrapper"):
    model = ghidra.import_module("ghidra.framework.model")
    class DataMonitor(model.DomainObjectListener):
        def __init__(self, interface):
            self.changeManager = ghidra.import_module_object("ghidra.program.util", "ChangeManager")
            self.programChangeRecord = ghidra.import_module_object("ghidra.program.util", "ProgramChangeRecord")
            self.symbol = ghidra.import_module("ghidra.program.database.symbol")
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
                if not isinstance(record, self.programChangeRecord):
                    continue

                changeType = record.getEventType()
                newValue = record.getNewValue()
                obj = record.getObject()

                if changeType in funcEvents:
                    # TODO: func stuff
                    pass
                elif changeType in typeEvents:
                    # TODO: type stuff
                    pass
                elif changeType in symDelEvents:
                    # TODO: symbol del stuff
                    pass
                elif changeType in symChgEvents:
                    if obj == None and newValue != None:
                        obj = newValue

                    if isinstance(obj, self.symbol.VariableSymbolDB):
                        # TODO: stack var stuff
                        continue
                    elif isinstance(obj, self.symbol.CodeSymbol):
                        # TODO: global and label stuff
                        continue
                    elif isinstance(obj, self.symbol.FunctionSymbol):
                        # TODO: func name stuff
                        continue
                    else:
                        continue
            print(ev)

    data_monitor = DataMonitor(ghidra)
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
