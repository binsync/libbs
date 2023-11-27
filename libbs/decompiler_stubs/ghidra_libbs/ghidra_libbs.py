# Starts the LibBS backend for Ghidra scripts.
# @author libbs
# @category libbs
# @menupath Tools.libbs.Start LibBS Backend

import subprocess
from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer


def start_libbs_selector():
    subprocess.Popen("libbs --run-ghidra-ui".split(" "))


if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
    # TODO: put the selector back
    #start_libbs_selector()
