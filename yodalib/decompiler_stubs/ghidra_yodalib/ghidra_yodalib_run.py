# Starts the YODA backend and selects a generic YODA Python script to run
# @author YODALib
# @category YODALib
# @menupath Tools.YODALib.Run YODA Backend

import subprocess
from yodalib_vendored.ghidra_bridge_server import GhidraBridgeServer


def start_bs_ui():
    subprocess.Popen("yodalib --run-ghidra-ui".split(" "))


if __name__ == "__main__":
    GhidraBridgeServer.run_server(background=True)
    start_bs_ui()
