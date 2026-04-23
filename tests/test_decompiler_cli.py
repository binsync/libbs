"""
Tests for the `decompiler` CLI and the new libbs core features it exposes
(list_strings, get_callers, disassemble).

These tests use the angr backend so they work without external installs (IDA,
Ghidra, Binary Ninja). They run the CLI by spawning subprocesses so that the
real entry point and server-registry flow are exercised.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from libbs.api import server_registry
from libbs.api.decompiler_client import DecompilerClient
from libbs.api.decompiler_interface import DecompilerInterface
from libbs.api.decompiler_server import DecompilerServer


TEST_BINARIES_DIR = Path(
    os.getenv("TEST_BINARIES_DIR", Path(__file__).parent.parent.parent / "bs-artifacts" / "binaries")
)
FAUXWARE_PATH = TEST_BINARIES_DIR / "fauxware"
POSIX_SYSCALL_PATH = TEST_BINARIES_DIR / "posix_syscall"


def _cli_env():
    env = os.environ.copy()
    # Isolate registry per-test so concurrent test runs don't collide and stale
    # servers from previous runs don't leak in.
    env["LIBBS_SERVER_REGISTRY"] = _REGISTRY_DIR
    return env


def _run_cli(*args, check=True, timeout=600) -> subprocess.CompletedProcess:
    """Run the `decompiler` CLI and return the result."""
    cmd = [sys.executable, "-m", "libbs.cli.decompiler_cli", *args]
    env = _cli_env()
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout, env=env)


# Shared registry directory for this module's tests
_REGISTRY_DIR = tempfile.mkdtemp(prefix="libbs_cli_registry_")


def _stop_all_servers():
    """Best-effort teardown: kill every server present in the registry."""
    os.environ["LIBBS_SERVER_REGISTRY"] = _REGISTRY_DIR
    try:
        records = server_registry.list_servers(prune_stale=False)
    except Exception:
        records = []
    for record in records:
        try:
            client = DecompilerClient(socket_path=record["socket_path"])
            try:
                client._send_request({"type": "shutdown_deci"})
            except Exception:
                pass
            client.shutdown()
        except Exception:
            pass
        finally:
            server_registry.unregister_server(record.get("id"))
            # Also try to SIGKILL the PID as a fallback
            pid = record.get("pid")
            if pid:
                try:
                    os.kill(int(pid), 9)
                except Exception:
                    pass


@unittest.skipUnless(FAUXWARE_PATH.exists(), f"Missing test binary: {FAUXWARE_PATH}")
class TestDecompilerCLI(unittest.TestCase):
    """End-to-end tests for the decompiler CLI using angr backend."""

    @classmethod
    def setUpClass(cls):
        os.environ["LIBBS_SERVER_REGISTRY"] = _REGISTRY_DIR
        _stop_all_servers()

    @classmethod
    def tearDownClass(cls):
        _stop_all_servers()
        try:
            shutil.rmtree(_REGISTRY_DIR, ignore_errors=True)
        except Exception:
            pass

    def tearDown(self):
        _stop_all_servers()

    def _load_fauxware(self):
        result = _run_cli("load", str(FAUXWARE_PATH), "--backend", "angr", "--json")
        payload = json.loads(result.stdout)
        self.assertIn(payload["status"], ("started", "already_loaded"))
        self.assertEqual(payload["backend"], "angr")
        return payload

    def test_load_and_list(self):
        loaded = self._load_fauxware()
        server_id = loaded["id"]

        list_result = _run_cli("list", "--json")
        payload = json.loads(list_result.stdout)
        # Feedback P3.13: list --json should expose the registry path.
        self.assertIn("registry_dir", payload)
        self.assertTrue(payload["registry_dir"])
        ids = {s["id"] for s in payload["servers"]}
        self.assertIn(server_id, ids)

    def test_list_show_registry(self):
        result = _run_cli("list", "--show-registry")
        self.assertTrue(result.stdout.strip())

    def test_load_idempotent(self):
        first = self._load_fauxware()
        second = self._load_fauxware()
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["status"], "already_loaded")

    def test_multi_instance_same_binary_with_force(self):
        first = self._load_fauxware()
        forced = _run_cli(
            "load", str(FAUXWARE_PATH), "--backend", "angr", "--force", "--json"
        )
        second = json.loads(forced.stdout)
        self.assertNotEqual(first["id"], second["id"])

        # Ambiguous selection should fail helpfully.
        result = _run_cli("decompile", "main", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Specify --id", result.stdout + result.stderr)

        # Selecting a specific id disambiguates.
        ok = _run_cli("decompile", "main", "--id", first["id"])
        self.assertIn("main", ok.stdout)

    def test_load_replace_stops_old_server(self):
        """`load --replace` should tear the existing server down, not leave two."""
        first = self._load_fauxware()
        replaced_result = _run_cli(
            "load", str(FAUXWARE_PATH), "--backend", "angr", "--replace", "--json"
        )
        replaced = json.loads(replaced_result.stdout)
        self.assertEqual(replaced["status"], "started")
        self.assertNotEqual(replaced["id"], first["id"])

        # Only one server should remain.
        listing = _run_cli("list", "--json")
        servers = json.loads(listing.stdout)["servers"]
        fauxware_servers = [s for s in servers if s["binary_path"] == str(FAUXWARE_PATH)]
        self.assertEqual(len(fauxware_servers), 1)
        self.assertEqual(fauxware_servers[0]["id"], replaced["id"])

    def test_decompile(self):
        self._load_fauxware()
        result = _run_cli("decompile", "main", "--json")
        payload = json.loads(result.stdout)
        self.assertIn("text", payload)
        self.assertIn("main", payload["text"])
        # Feedback P1.4: JSON should include addr_hex alongside addr.
        self.assertIn("addr_hex", payload)
        self.assertTrue(payload["addr_hex"].startswith("0x"))

        # By address (lifted)
        addr_dec = _run_cli("decompile", "0x71d", "--json")
        self.assertIn("text", json.loads(addr_dec.stdout))

    def test_decompile_raw(self):
        """Feedback P1.7: --raw should print text directly, not JSON-wrapped."""
        self._load_fauxware()
        raw = _run_cli("decompile", "main", "--raw")
        # Raw output: no literal '\\n' escape or JSON quoting.
        self.assertNotIn('\\n', raw.stdout)
        self.assertNotIn('{"addr"', raw.stdout)
        self.assertIn("main", raw.stdout)

    def test_decompile_not_a_function_start(self):
        """Feedback P1.6: clear error distinguishing 'not a start' from engine failure."""
        self._load_fauxware()
        # 0x71e is inside main (main starts at 0x71d).
        result = _run_cli("decompile", "0x71e", check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("No function starts at", result.stdout + result.stderr)

    def test_disassemble(self):
        self._load_fauxware()
        result = _run_cli("disassemble", "main", "--json")
        payload = json.loads(result.stdout)
        self.assertIn("text", payload)
        self.assertIn("addr_hex", payload)
        # sanity: some assembly
        self.assertTrue(any(op in payload["text"] for op in ("push", "mov", "call")))

    def test_disassemble_raw(self):
        self._load_fauxware()
        raw = _run_cli("disassemble", "main", "--raw")
        self.assertNotIn('\\n', raw.stdout)
        self.assertNotIn('{"addr"', raw.stdout)

    def test_list_functions(self):
        """Feedback P0.1: `list_functions` subcommand."""
        self._load_fauxware()
        result = _run_cli("list_functions", "--filter", "main", "--json")
        entries = json.loads(result.stdout)
        names = {e["name"] for e in entries}
        self.assertIn("main", names)
        # Each entry must carry addr, addr_hex, size, name.
        for e in entries:
            self.assertIn("addr", e)
            self.assertIn("addr_hex", e)
            self.assertIn("size", e)
            self.assertIn("name", e)
        # Text output is tabular.
        text = _run_cli("list_functions", "--filter", "main").stdout
        self.assertIn("ADDR", text)
        self.assertIn("main", text)

    def test_xref_to(self):
        self._load_fauxware()
        result = _run_cli("xref_to", "authenticate", "--json")
        payload = json.loads(result.stdout)
        names = {x.get("name") for x in payload["xrefs"]}
        self.assertIn("main", names)
        # Feedback P1.3: rows should be kind-tagged.
        kinds = {x.get("kind") for x in payload["xrefs"]}
        self.assertIn("Function", kinds)
        # addr_hex present for each xref
        for x in payload["xrefs"]:
            self.assertIn("addr_hex", x)

    def test_xref_from(self):
        self._load_fauxware()
        result = _run_cli("xref_from", "main", "--json")
        payload = json.loads(result.stdout)
        # main should call at least `authenticate`; address is always populated.
        addrs = {x.get("addr") for x in payload["xrefs"]}
        self.assertGreaterEqual(len(addrs), 1)
        names = {x.get("name") for x in payload["xrefs"] if x.get("name")}
        # At least one named callee (puts/read/authenticate/accepted/rejected)
        self.assertTrue(names & {"authenticate", "puts", "read", "accepted", "rejected"})

    def test_rename_func(self):
        self._load_fauxware()
        result = _run_cli("rename", "func", "authenticate", "my_auth", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["success"])

    def test_rename_func_missing_exits_1(self):
        """Feedback P1.5: non-existent rename should exit 1, not 2."""
        self._load_fauxware()
        result = _run_cli(
            "rename", "func", "nonexistent_fn_xyz", "whatever", check=False
        )
        self.assertEqual(result.returncode, 1)

    def test_rename_var_missing_exits_1(self):
        """Feedback P1.5: var rename with missing old name should exit 1, not 2."""
        self._load_fauxware()
        result = _run_cli(
            "rename", "var", "no_such_var_xyz", "whatever",
            "--function", "main", check=False,
        )
        self.assertEqual(result.returncode, 1)

    def test_rename_var(self):
        self._load_fauxware()
        # Fetch an existing local variable name dynamically via the client API
        # so this doesn't depend on angr's specific naming.
        record = server_registry.find_servers(binary_path=str(FAUXWARE_PATH))[0]
        client = DecompilerClient(socket_path=record["socket_path"])
        try:
            addrs = [a for a, f in client.functions.items() if f.name == "main"]
            main_addr = addrs[0]
            main_func = client.functions[main_addr]
            names = client.local_variable_names(main_func)
            target = next((n for n in names if n not in ("a0", "a1")), names[0])
        finally:
            client.shutdown()

        result = _run_cli(
            "rename", "var", target, "renamed_var",
            "--function", "main", "--json",
        )
        payload = json.loads(result.stdout)
        self.assertTrue(payload["success"])

    def test_list_strings(self):
        self._load_fauxware()
        result = _run_cli("list_strings", "--filter", "Welcome", "--json")
        payload = json.loads(result.stdout)
        # Each entry has addr, addr_hex, string, source.
        hit = next((s for s in payload if "Welcome" in s["string"]), None)
        self.assertIsNotNone(hit)
        self.assertIn("addr_hex", hit)
        self.assertIn("source", hit)

    def test_list_strings_rescan_picks_up_more(self):
        """Feedback P0/P1.2: fallback scan should surface more entries than the thin angr detector."""
        self._load_fauxware()
        backend_only = _run_cli("list_strings", "--no-rescan", "--json")
        with_rescan = _run_cli("list_strings", "--rescan", "--json")
        self.assertGreater(len(json.loads(with_rescan.stdout)),
                           len(json.loads(backend_only.stdout)))
        # rescan entries should include section info for ELF binaries.
        rescan_entries = [s for s in json.loads(with_rescan.stdout)
                          if s.get("source") == "rescan"]
        self.assertTrue(rescan_entries)
        self.assertTrue(any("section" in e for e in rescan_entries))

    def test_list_strings_min_length(self):
        self._load_fauxware()
        result = _run_cli("list_strings", "--min-length", "20", "--json")
        entries = json.loads(result.stdout)
        # Every entry must meet the threshold.
        for e in entries:
            self.assertGreaterEqual(len(e["string"]), 20)

    def test_get_callers(self):
        self._load_fauxware()
        by_name = _run_cli("get_callers", "authenticate", "--json")
        payload = json.loads(by_name.stdout)
        names = {c.get("name") for c in payload["callers"]}
        self.assertIn("main", names)
        # Every *_addr field should have a hex sibling (target_addr -> target_addr_hex, etc.)
        self.assertIn("target_addr_hex", payload)
        for c in payload["callers"]:
            self.assertIn("addr_hex", c)

    def test_stop(self):
        loaded = self._load_fauxware()
        stop = _run_cli("stop", "--id", loaded["id"], "--json")
        payload = json.loads(stop.stdout)
        self.assertTrue(payload["stopped"][0]["stopped"])
        listing = _run_cli("list", "--json")
        servers = json.loads(listing.stdout)["servers"]
        ids = {s["id"] for s in servers}
        self.assertNotIn(loaded["id"], ids)

    @unittest.skipUnless(POSIX_SYSCALL_PATH.exists(), f"Missing: {POSIX_SYSCALL_PATH}")
    def test_two_binaries_concurrent(self):
        first = self._load_fauxware()
        second_result = _run_cli(
            "load", str(POSIX_SYSCALL_PATH), "--backend", "angr", "--json"
        )
        second = json.loads(second_result.stdout)
        self.assertNotEqual(first["id"], second["id"])

        # Each CLI call with --id should return results from its binary.
        fauxware_strings = _run_cli("list_strings", "--id", first["id"], "--json")
        self.assertTrue(any("Welcome" in s["string"] for s in json.loads(fauxware_strings.stdout)))


class TestSkillInstaller(unittest.TestCase):
    """The bundled `decompiler` skill should ship with the package and install cleanly."""

    def test_bundled_skill_present(self):
        from libbs import skills

        names = skills.available_skills()
        self.assertIn("decompiler", names)
        skill = skills.skill_path("decompiler") / "SKILL.md"
        content = skill.read_text()
        self.assertIn("name: decompiler", content)
        self.assertIn("decompiler load", content)

    def test_install_skill_via_cli(self):
        with tempfile.TemporaryDirectory() as dest:
            result = _run_cli("install-skill", "--dest", dest, "--json")
            # Feedback P3.12: --json must emit parseable JSON (not Python repr).
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["installed"]), 1)
            installed_path = Path(payload["installed"][0]["path"])
            self.assertTrue((installed_path / "SKILL.md").is_file())

            # Re-install without --force should fail helpfully.
            again = _run_cli("install-skill", "--dest", dest, "--json", check=False)
            self.assertNotEqual(again.returncode, 0)

            # --force overwrites.
            forced = _run_cli("install-skill", "--dest", dest, "--json", "--force")
            self.assertEqual(len(json.loads(forced.stdout)["installed"]), 1)

    def test_install_skill_text_output_is_parsable(self):
        """Text output should be readable (not single-quoted Python repr)."""
        with tempfile.TemporaryDirectory() as dest:
            result = _run_cli("install-skill", "--dest", dest)
            # No Python-style single quotes around the payload.
            self.assertNotIn("[{'name'", result.stdout)
            self.assertIn("decompiler", result.stdout)


@unittest.skipUnless(FAUXWARE_PATH.exists(), f"Missing test binary: {FAUXWARE_PATH}")
class TestNewLibbsFeatures(unittest.TestCase):
    """Direct tests (not via CLI) for the new list_strings/get_callers/disassemble APIs."""

    @classmethod
    def setUpClass(cls):
        cls.deci = DecompilerInterface.discover(
            force_decompiler="angr",
            headless=True,
            binary_path=str(FAUXWARE_PATH),
        )

    def test_list_strings_no_filter(self):
        strings = self.deci.list_strings()
        self.assertGreater(len(strings), 0)
        for addr, s in strings:
            self.assertIsInstance(addr, int)
            self.assertIsInstance(s, str)

    def test_list_strings_filter(self):
        welcome = self.deci.list_strings(filter=r"Welcome")
        self.assertEqual(len(welcome), 1)
        self.assertIn("Welcome", welcome[0][1])
        # Ensure non-matching regex yields nothing.
        self.assertEqual(self.deci.list_strings(filter=r"zzz_no_match_zzz"), [])

    def test_disassemble(self):
        addrs = [a for a, f in self.deci.functions.items() if f.name == "main"]
        self.assertEqual(len(addrs), 1)
        main_addr = addrs[0]
        text = self.deci.disassemble(main_addr)
        self.assertIsNotNone(text)
        self.assertTrue(any(mnem in text for mnem in ("push", "mov", "call")))

    def test_get_callers_by_addr_name_and_function(self):
        addrs_by_name = {f.name: a for a, f in self.deci.functions.items()}
        auth_addr = addrs_by_name["authenticate"]

        by_addr = self.deci.get_callers(auth_addr)
        by_name = self.deci.get_callers("authenticate")
        self.assertGreater(len(by_addr), 0)
        self.assertGreater(len(by_name), 0)
        self.assertEqual({f.addr for f in by_addr}, {f.addr for f in by_name})

        # A made-up name raises.
        with self.assertRaises(ValueError):
            self.deci.get_callers("no_such_function_xyz")


if __name__ == "__main__":
    unittest.main()
