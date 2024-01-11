# Starts the LibBS backend for Ghidra scripts.
# @author LibBS
# @category LibBS

from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer

if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=False)
