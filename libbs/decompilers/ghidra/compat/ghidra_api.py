import time
import logging

import ghidra_bridge
from jfx_bridge.bridge import BridgedObject

_l = logging.getLogger(__name__)


class GhidraAPIWrapper:
    def __init__(self, controller, connection_timeout=10):
        self._controller = controller
        self._connection_timeout = connection_timeout

        self.bridge = None
        self._ghidra_bridge_attrs = {}
        self._imports = {}

        self.connected = self._connect_ghidra_bridge()
        if not self.connected:
            return

    def __getattr__(self, item):
        if item in self._ghidra_bridge_attrs:
            return self._ghidra_bridge_attrs[item]
        else:
            return self.__getattribute__(item)

    def import_module_object(self, module_name: str, obj_name: str):
        module = self.import_module(module_name)
        try:
            module_obj = getattr(module, obj_name)
        except AttributeError:
            _l.critical(f"Failed to import {module}.{obj_name}")
            module_obj = None

        return module_obj

    def import_module(self, module_name: str):
        if module_name not in self._imports:
            self._imports[module_name] = self.bridge.remote_import(module_name)

        return self._imports[module_name]

    def _connect_ghidra_bridge(self):
        start_time = time.time()
        successful = False
        while time.time() - start_time < self._connection_timeout:
            try:
                self.bridge = ghidra_bridge.GhidraBridge(namespace=self._ghidra_bridge_attrs, interactive_mode=True)
                successful = True
            except ConnectionError:
                time.sleep(1)

            if successful:
                break

        return successful

    def print(self, string, print_local=True):
        """
        A proxy printer to print both in the local terminal and on the remote if a bridge is available.
        """
        if print_local:
            print(string)

        if self.bridge:
            self.bridge.remote_exec(f'print("{string}")')

    def ping(self):
        connected = False
        if self.bridge is not None:
            try:
                self.bridge.remote_eval("True")
                connected = True
            except Exception:
                pass

        return connected

    @staticmethod
    def isinstance(obj, cls):
        """
        A proxy isinstance function that can handle BridgedObjects. This is necessary because the `isinstance` function
        in the remote namespace will not recognize BridgedObjects as instances of classes in the local namespace.
        """
        return obj._bridge_isinstance(cls) if isinstance(obj, BridgedObject) else isinstance(obj, cls)
