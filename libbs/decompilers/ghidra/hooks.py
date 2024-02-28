import typing
import threading

from .interface import GhidraDecompilerInterface

if typing.TYPE_CHECKING:
    from libbs.decompilers.ghidra.compat.ghidra_api import GhidraAPIWrapper

model = GhidraAPIWrapper.import_module("ghidra.framework.model")
class DataMonitor(model.DomainObjectListener):
    # TODO: Design and inplement
    def __init__(self, interface):
        self._interface: GhidraDecompilerInterface = interface

    def domainObjectChanged(self, ev):
        print(ev)

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
