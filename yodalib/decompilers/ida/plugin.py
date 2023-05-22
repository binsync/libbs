# ----------------------------------------------------------------------------
# This file is simply the entrypoint from the initial call in ida_yodalib,
# which will setup all the hooks for both the UI and IDB changes, and will
# also create the config window.
#
# ----------------------------------------------------------------------------
import logging
import os

from PyQt5.QtCore import QObject

import idaapi
import ida_kernwin
import idc
import idautils
import ida_hexrays

from yodalib import __version__ as VERSION
from .hooks import MasterHook, IdaHotkeyHook
from .interface import IDAInterface
from . import compat

l = logging.getLogger(__name__)
interface = IDAInterface()

# disable the annoying "Running Python script" wait box that freezes IDA at times
idaapi.set_script_timeout(0)


#
#   UI Hook, placed here for convenience of reading UI implementation
#

class ScreenHook(ida_kernwin.View_Hooks):
    def __init__(self):
        super(ScreenHook, self).__init__()
        self.hooked = False

    def view_click(self, view, event):
        form_type = idaapi.get_widget_type(view)
        decomp_view = idaapi.get_widget_vdui(view)
        if not form_type:
            return

        # check if view is decomp or disassembly before doing expensive ea lookup
        if not decomp_view and not form_type == idaapi.BWN_DISASM:
            return

        ea = idc.get_screen_ea()
        if not ea:
            return

        interface.update_active_context(ea)

#
#  Base Plugin
#


class YODALibPlugin(QObject, idaapi.plugin_t):
    """Plugin entry point. Does most of the skinning magic."""

    flags = idaapi.PLUGIN_FIX
    comment = "Syncing dbs between users"
    wanted_name = "yodalib"

    def __init__(self, *args, **kwargs):
        print("[yodalib] {} loaded!".format(VERSION))

        QObject.__init__(self, *args, **kwargs)
        idaapi.plugin_t.__init__(self)
        self.hooks_started = False

    def _init_hooks(self):
        # init later
        self.view_hook = ScreenHook()
        # Hook IDB & Decomp Actions in IDA
        self.action_hooks = MasterHook(interface)

    def _get_or_create_deocmpilation_view(self):
        # casually open a pseudocode window, this prevents magic sync from spawning pseudocode windows
        # in weird locations upon an initial run
        func_addr = next(idautils.Functions())
        if interface.decompiler_available:
            ida_hexrays.open_pseudocode(func_addr, ida_hexrays.OPF_NO_WAIT | ida_hexrays.OPF_REUSE)

        # then attempt to flip back to IDA View-A
        twidget = idaapi.find_widget("IDA View-A")
        if twidget is not None:
            ida_kernwin.activate_widget(twidget, True)

    def init(self):
        self._init_hooks()
        #self._get_or_create_deocmpilation_view()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass

#
#   Utils
#


def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    plugin_path = os.path.abspath(os.path.dirname(__file__))

    return os.path.join(
        plugin_path,
        resource_name
    )




