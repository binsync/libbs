# Shutdown the LibBS backend server.
# @author LibBS
# @category LibBS
# @menupath Tools.LibBS.Shutdown LibBS Backend

from libbs_vendored.jfx_bridge import bridge
from libbs_vendored.ghidra_bridge_port import DEFAULT_SERVER_PORT

if __name__ == "__main__":
    print("Requesting server shutdown...")
    b = bridge.BridgeClient(
        connect_to_host="127.0.0.1", connect_to_port=DEFAULT_SERVER_PORT
    )

    print(b.remote_shutdown())
