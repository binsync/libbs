import logging

_l = logging.getLogger(__name__)


def _get_python_plugin(flat_api=None):
    if flat_api is not None:
        state = flat_api.getState()
    else:
        _l.warning("Using internal ghidra functions without a distinct FlatAPI is likely dangerous!")
        # assume it must be either in the globals or __this__ object, but this will likley crash if we are here
        gvs = dict(globals())
        state = gvs.get("getState", None) or gvs.get("__this__", None).getState

    for plugin in state.getTool().getManagedPlugins():
        if plugin.name == "PythonPlugin":
            break
    else:
        raise RuntimeError("PythonPlugin not found")

    return plugin


def get_current_program(flat_api=None):
    return _get_python_plugin(flat_api=flat_api).getCurrentProgram()


def get_current_address(flat_api=None):
    addr = _get_python_plugin(flat_api=flat_api).getProgramLocation().getAddress().offset
    if addr is not None:
        addr = int(addr)

    return addr

