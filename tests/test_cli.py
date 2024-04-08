import sys
import subprocess

import unittest


class TestCommandline(unittest.TestCase):
    def test_change_watcher_plugin_cli(self):
        # assumes you've pip installed ./examples/change_watcher_plugin
        import bs_change_watcher

        # run the CLI version check
        output = subprocess.run(["bs_change_watcher", "--version"], capture_output=True)
        version = output.stdout.decode().strip()
        assert version == bs_change_watcher.__version__


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
