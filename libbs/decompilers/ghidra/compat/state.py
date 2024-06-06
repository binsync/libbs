from .imports import getState


def _get_python_plugin():
    for plugin in getState().getTool().getManagedPlugins():
        if plugin.name == "PythonPlugin":
            break
    else:
        raise RuntimeError("PythonPlugin not found")

    return plugin


def get_current_program():
    return _get_python_plugin().getCurrentProgram()


def get_current_address():
    addr = _get_python_plugin().getProgramLocation().getAddress().offset
    if addr is not None:
        addr = int(addr)

    return addr

