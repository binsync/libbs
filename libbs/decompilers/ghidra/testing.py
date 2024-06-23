import os
import subprocess
import tempfile
import time
from pathlib import Path

from libbs.plugin_installer import PluginInstaller


class HeadlessGhidraDecompiler:
    def __init__(
        self,
        binary_path: Path,
        headless_dec_path: Path = None,
        headless_script_path: Path = None,
    ):
        self._binary_path = Path(binary_path)
        if not self._binary_path.exists():
            raise FileNotFoundError(f"Failed to find binary at {self._binary_path}")

        if headless_dec_path is None:
            env_val = os.getenv("GHIDRA_HEADLESS_PATH", None)
            if env_val is None:
                raise ValueError("Must provide headless_dec_path or set GHIDRA_HEADLESS_PATH")

            headless_dec_path = Path(env_val)
        if not headless_dec_path.exists():
            raise FileNotFoundError(f"Failed to find ghidra headless at {headless_dec_path}")
        self._headless_dec_path = headless_dec_path

        self._headless_script_path = headless_script_path or PluginInstaller.find_pkg_files("libbs") / "decompiler_stubs" / "ghidra_libbs" / "ghidra_libbs_mainthread_server.py"
        if not self._headless_script_path.exists():
            raise FileNotFoundError(f"Failed to find headless script at {self._headless_script_path}")

        self._proc = None

    def __enter__(self):
        self._headless_g_project = tempfile.TemporaryDirectory()
        self._proc = subprocess.Popen([
            str(self._headless_dec_path),
            self._headless_g_project.name,
            "headless",
            "-import",
            str(self._binary_path),
            "-scriptPath",
            str(self._headless_script_path.parent),
            "-postScript",
            str(self._headless_script_path.name),
        ])
        time.sleep(1)

    def __exit__(self, exc_type, exc_val, exc_tb):
        time.sleep(2)
        # Wait until headless binary gets shutdown
        try:
            self._proc.kill()
        except Exception:
            pass
        self._headless_g_project.cleanup()
