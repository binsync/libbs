# Starts the YODA backend for Ghidra scripts.
# @author YODALib
# @category YODALib
# @menupath Tools.YODALib.Start YODA Backend

import subprocess
from yodalib_vendored.ghidra_bridge_server import GhidraBridgeServer


def start_yoda_selector():
    subprocess.Popen("yodalib --run-ghidra-ui".split(" "))


if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
    # TODO: put the selector back
    #start_yoda_selector()
