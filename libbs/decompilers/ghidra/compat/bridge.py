import importlib
import inspect
import logging
import re
import time
from functools import wraps
import typing
from typing import Optional

import ghidra_bridge

if typing.TYPE_CHECKING:
    from ..interface import GhidraDecompilerInterface

_l = logging.getLogger(name=__name__)


def connect_to_bridge(connection_timeout=20) -> Optional[ghidra_bridge.GhidraBridge]:
    start_time = time.time()
    bridge = None
    while time.time() - start_time < connection_timeout:
        try:
            bridge = ghidra_bridge.GhidraBridge(
                namespace=globals(), interactive_mode=True
            )
        except ConnectionError as e:
            _l.info(f"Failed to connect to GhidraBridge: {e}")
            time.sleep(1)

        if bridge is not None:
            break

    return bridge


def shutdown_bridge(bridge: ghidra_bridge.GhidraBridge):
    if bridge is None:
        return False

    return bool(bridge.remote_shutdown())


def _ping_bridge(bridge: ghidra_bridge.GhidraBridge) -> bool:
    connected = False
    if bridge is not None:
        try:
            bridge.remote_eval("True")
            connected = True
        except Exception:
            pass

    return connected


def run_until_bridge_closed(bridge: ghidra_bridge.GhidraBridge, sleep_interval=30):
    while True:
        if not _ping_bridge(bridge):
            break

        time.sleep(sleep_interval)


class FlatAPIWrapper:
    def __getattr__(self, name):
        g = globals()
        if name in g:
            return g[name]
        else:
            raise AttributeError(f"No global import named {name}")


def ui_remote_eval(f):
    @wraps(f)
    def _ui_remote_eval(self: "GhidraDecompilerInterface", *args, **kwargs):
        # exit early, no analysis needed
        if self.headless:
            return f(self, *args, **kwargs)

        # extract every argument name from the function signature
        code_args = list(inspect.getfullargspec(f).args)[1:len(args)+1]
        args_by_name = {
            arg: val for arg, val in zip(code_args, args)
        }
        args_by_name["_self"] = self
        args_by_name.update(kwargs)

        # update the code that uses self to use the _self variable
        f_code = inspect.getsource(f)
        f_code = f_code.replace("self.", "_self.")

        # extract all (from * imports) with a regex, and import them
        import_pairs = re.findall("from (.*?) import (.*?)\n", f_code)
        imported_objs = {}
        for module, objs in import_pairs:
            module_obj = importlib.import_module(
                module, package="libbs.decompilers.ghidra" if module.startswith(".") else None
            )
            for obj in objs.split(","):
                obj_name = obj.strip()
                imported_objs[obj_name] = getattr(module_obj, obj_name)

        namespace = args_by_name
        namespace.update(imported_objs)

        # extract the remote code
        remote_codes = re.findall(r"return (\[.*])", f_code.replace("\n", " "))
        if len(remote_codes) != 1:
            raise ValueError(f"Failed to extract remote code from function {f}! This must be a bug in writing.")

        remote_code = remote_codes[0]
        try:
            val = self._bridge.remote_eval(remote_code, **namespace)
        except Exception as e:
            self.error(f"Failed to evaluate remote code: {remote_code}")
            val = []

        return val

    return _ui_remote_eval


