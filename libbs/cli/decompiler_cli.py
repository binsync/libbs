"""
The `decompiler` CLI: a simplified, LLM-friendly interface to libbs.

The CLI is a client that connects to a DecompilerServer. The first `load` of
a binary auto-starts a headless server in the background; subsequent CLI
invocations (including `load`s of other binaries) connect to the right server
via the shared server registry (see libbs.api.server_registry).

Subcommands implemented:
- load            start a server on a binary
- list            list running servers
- stop            stop one or all servers
- list_functions  list functions in the binary, optionally filtered by regex
- decompile       decompile a function by name or address
- disassemble     disassemble a function by name or address
- xref_to         data + code references to a target
- xref_from       things a function calls (callees)
- rename          rename a function or local variable
- list_strings    list strings in the binary, optionally filtered by regex
- get_callers     functions (call sites only) that call a target
- install-skill   install the bundled Agent Skill so LLMs learn the CLI
"""
import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Standardized exit codes — keep these consistent across subcommands so that
# `&&` chaining and scripts have predictable behavior.
EXIT_OK = 0
EXIT_USER_ERROR = 1        # user asked for something that didn't happen
EXIT_NOT_FOUND = 1         # missing function/name/binary
EXIT_RUNTIME_ERROR = 1     # unhandled/unknown failure

from libbs.api import server_registry
from libbs.decompilers import SUPPORTED_DECOMPILERS
from libbs import skills

_l = logging.getLogger("libbs.cli.decompiler")

_SERVER_START_TIMEOUT = 300.0  # seconds; Ghidra initial analysis can be slow
_SERVER_POLL_INTERVAL = 0.25


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # Keep libbs chatter quiet unless --verbose; otherwise INFO logs clobber the CLI output.
    if not verbose:
        logging.getLogger("libbs").setLevel(logging.WARNING)


def _parse_target(target: str) -> Tuple[Optional[int], Optional[str]]:
    """Parse a user-supplied target into (addr, name).

    Accepts hex (0x...), decimal, or a symbol name. Returns (addr, None) if numeric,
    otherwise (None, target).
    """
    if target is None:
        return None, None
    t = target.strip()
    if t.lower().startswith("0x"):
        try:
            return int(t, 16), None
        except ValueError:
            pass
    if t.isdigit():
        try:
            return int(t, 10), None
        except ValueError:
            pass
    return None, t


def _resolve_function_addr(client, target: str) -> Optional[int]:
    """Resolve a function reference to its address using a client.

    Names are resolved by scanning light artifacts. Addresses may be given in either
    lifted (relative to base) or lowered (absolute/loaded) form; we match whichever
    the server's artifact dict uses.
    """
    addr, name = _parse_target(target)
    if name is not None:
        for _addr, func in client.functions.items():
            if func.name == name:
                return _addr
        return None
    if addr is None:
        return None

    # Addresses may be given as absolute; the server exposes lifted addresses.
    known = set(client.functions.keys())
    if addr in known:
        return addr
    try:
        base = client.binary_base_addr
    except Exception:
        base = 0
    if base and addr >= base and (addr - base) in known:
        return addr - base
    if base and (addr + base) in known:
        return addr + base
    return addr  # let the caller raise if it's truly invalid


def _select_server(
    server_id: Optional[str],
    binary_path: Optional[str],
    backend: Optional[str],
) -> Dict:
    """Pick a server record from the registry, or error out with a helpful message."""
    records = server_registry.find_servers(
        binary_path=binary_path,
        backend=backend,
    )
    if server_id:
        records = [r for r in records if r.get("id") == server_id]

    if not records:
        filters = {"id": server_id, "binary_path": binary_path, "backend": backend}
        active = {k: v for k, v in filters.items() if v}
        raise SystemExit(
            "No running decompiler server matches "
            f"{active or '(no filters)'}. Start one with `decompiler load <binary>`."
        )
    if len(records) > 1 and not server_id:
        lines = [
            f"{r['id']}  backend={r.get('backend')}  binary={r.get('binary_path')}"
            for r in records
        ]
        raise SystemExit(
            "Multiple servers match. Specify --id to disambiguate:\n  "
            + "\n  ".join(lines)
        )
    return records[0]


def _connect_client(record: Dict):
    from libbs.api.decompiler_client import DecompilerClient

    return DecompilerClient(socket_path=record["socket_path"])


def _with_client(args):
    """Resolve & connect to the selected server, returning the client."""
    record = _select_server(
        server_id=getattr(args, "id", None),
        binary_path=getattr(args, "binary", None),
        backend=getattr(args, "backend", None),
    )
    return _connect_client(record)


# ---------------------------------------------------------------------------
# load
# ---------------------------------------------------------------------------

def _spawn_server(binary_path: Path, backend: str, server_id: str) -> subprocess.Popen:
    """Start a detached headless server process for the given binary."""
    cmd = [
        sys.executable, "-m", "libbs",
        "--server",
        "--decompiler", backend,
        "--headless",
        "--binary-path", str(binary_path),
        "--server-id", server_id,
    ]
    env = os.environ.copy()
    # Inherit env so things like GHIDRA_INSTALL_DIR flow through.

    # Fully detach: new session so Ctrl-C in the CLI won't kill the server.
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
        "env": env,
        "close_fds": True,
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    return subprocess.Popen(cmd, **kwargs)


def _wait_for_server(server_id: str, timeout: float = _SERVER_START_TIMEOUT) -> Dict:
    """Block until a server with `server_id` appears in the registry or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = server_registry.find_server(server_id=server_id)
        if record and record.get("socket_path") and os.path.exists(record["socket_path"]):
            return record
        time.sleep(_SERVER_POLL_INTERVAL)
    raise SystemExit(
        f"Timed out waiting {timeout:.0f}s for server {server_id} to start. "
        "Check backend dependencies (e.g. GHIDRA_INSTALL_DIR) and retry."
    )


def cmd_load(args) -> int:
    binary_path = Path(args.binary).expanduser().resolve()
    if not binary_path.exists():
        raise SystemExit(f"Binary not found: {binary_path}")

    backend = args.backend
    if backend not in SUPPORTED_DECOMPILERS:
        raise SystemExit(
            f"Unsupported backend {backend!r}; pick one of: {sorted(SUPPORTED_DECOMPILERS)}"
        )

    # Existing server(s) for this binary+backend.
    existing = server_registry.find_servers(binary_path=str(binary_path), backend=backend)
    if existing and args.replace:
        # --replace: tear the old one(s) down first, then start fresh.
        for record in existing:
            _stop_server_by_record(record)
        existing = []
    if existing and not args.force:
        record = existing[0]
        _emit(args, {
            "status": "already_loaded",
            "id": record["id"],
            "binary_path": record.get("binary_path"),
            "backend": record.get("backend"),
            "socket_path": record.get("socket_path"),
        })
        return 0

    server_id = args.id or server_registry.new_server_id()
    _spawn_server(binary_path, backend, server_id)
    record = _wait_for_server(server_id)
    _emit(args, {
        "status": "started",
        "id": record["id"],
        "binary_path": record.get("binary_path"),
        "backend": record.get("backend"),
        "socket_path": record.get("socket_path"),
    })
    return 0


# ---------------------------------------------------------------------------
# list / stop
# ---------------------------------------------------------------------------

def cmd_list(args) -> int:
    records = server_registry.list_servers()
    registry_dir = str(server_registry._registry_dir())  # type: ignore[attr-defined]
    if args.show_registry and not args.json:
        print(registry_dir)
        return 0
    if args.json:
        print(json.dumps({"registry_dir": registry_dir, "servers": records}, indent=2, default=str))
        return 0
    if not records:
        print(f"No running decompiler servers.  (registry: {registry_dir})")
        return 0
    print(f"{'ID':<12} {'BACKEND':<8} {'PID':<8} BINARY")
    for r in records:
        print(f"{r.get('id',''):<12} {str(r.get('backend','')):<8} {str(r.get('pid','')):<8} {r.get('binary_path','')}")
    print(f"\n(registry: {registry_dir})")
    return 0


def _stop_server_by_record(record: Dict) -> bool:
    """Shut down the server process backing `record`.

    Asks the server to shut itself down gracefully, falling back to SIGTERM/SIGKILL
    on the PID if the request fails. Returns True if we believe the process is
    gone (or never existed) by the time we return.
    """
    from libbs.api.decompiler_client import DecompilerClient

    server_id = record.get("id")
    pid = record.get("pid")
    socket_path = record.get("socket_path")
    graceful = False
    try:
        client = DecompilerClient(socket_path=socket_path)
    except Exception as exc:
        _l.warning("Could not connect to server %s: %s", server_id, exc)
        client = None
    if client is not None:
        try:
            client._send_request({"type": "shutdown_server"})
            graceful = True
        except Exception as exc:
            _l.debug("shutdown_server rejected by %s: %s", server_id, exc)
        # Close the socket directly instead of calling client.shutdown(); the
        # latter also fires `shutdown_deci`, which noisily fails once the server
        # has stopped listening.
        try:
            if client._socket is not None:
                client._socket.close()
        except Exception:
            pass
        client._connected = False

    if not _wait_for_process_exit(pid, timeout=3.0):
        # Graceful request didn't land or server is stuck — escalate.
        _signal_process(pid, signal.SIGTERM)
        if not _wait_for_process_exit(pid, timeout=2.0):
            _signal_process(pid, signal.SIGKILL)
            _wait_for_process_exit(pid, timeout=1.0)

    server_registry.unregister_server(server_id)
    return graceful or not _process_alive(pid)


def _process_alive(pid) -> bool:
    if not pid:
        return False
    try:
        import psutil

        return psutil.pid_exists(int(pid))
    except Exception:
        return False


def _signal_process(pid, sig) -> None:
    if not pid:
        return
    try:
        os.kill(int(pid), sig)
    except ProcessLookupError:
        return
    except Exception as exc:
        _l.debug("Signal %s to pid %s failed: %s", sig, pid, exc)


def _wait_for_process_exit(pid, timeout: float) -> bool:
    if not pid:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _process_alive(pid):
            return True
        time.sleep(0.05)
    return not _process_alive(pid)


def cmd_stop(args) -> int:
    records = server_registry.list_servers()
    if args.all:
        targets = records
    elif args.id:
        targets = [r for r in records if r.get("id") == args.id]
    elif args.binary:
        targets = server_registry.find_servers(binary_path=args.binary)
    else:
        raise SystemExit("decompiler stop needs --id, --binary, or --all")

    if not targets:
        raise SystemExit("No matching server to stop")

    results = []
    for record in targets:
        ok = _stop_server_by_record(record)
        results.append({"id": record.get("id"), "stopped": bool(ok)})
    _emit(args, {"stopped": results})
    return 0


# ---------------------------------------------------------------------------
# decompile / disassemble
# ---------------------------------------------------------------------------

def _known_function_addrs(client) -> set:
    try:
        return set(client.functions.keys())
    except Exception:
        return set()


def cmd_decompile(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        known = _known_function_addrs(client)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        if known and addr not in known:
            raise SystemExit(
                f"No function starts at 0x{addr:x}. "
                f"Try `decompiler list_functions --filter '{args.target}'` or "
                "pick a function-start address."
            )
        dec = client.decompile(addr)
        if dec is None:
            raise SystemExit(
                f"Decompiler engine returned no result for 0x{addr:x}. "
                "The address is a known function start, but decompilation "
                "failed — this usually means the backend can't handle this "
                "function (unreachable code, ARM/x86 mode mismatch, etc.)."
            )
        text = dec.text if hasattr(dec, "text") else str(dec)
        if getattr(args, "raw", False):
            # --raw: dump just the text body to stdout, regardless of --json.
            print(text)
            return 0
        out = {
            "addr": addr,
            "decompiler": dec.decompiler if hasattr(dec, "decompiler") else None,
            "text": text,
        }
        _emit(args, out, text_field="text")
    return 0


def cmd_disassemble(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        known = _known_function_addrs(client)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        if known and addr not in known:
            raise SystemExit(
                f"No function starts at 0x{addr:x}. "
                f"Try `decompiler list_functions --filter '{args.target}'` or "
                "pick a function-start address."
            )
        text = client.disassemble(addr)
        if text is None:
            raise SystemExit(
                f"Disassembler returned no instructions for 0x{addr:x} "
                "(likely a function too small to disassemble or a backend bug)."
            )
        if getattr(args, "raw", False):
            print(text)
            return 0
        _emit(args, {"addr": addr, "text": text}, text_field="text")
    return 0


def cmd_list_functions(args) -> int:
    with _with_client(args) as client:
        pattern = re.compile(args.filter) if args.filter else None
        entries: List[Dict] = []
        for addr, func in sorted(client.functions.items(), key=lambda kv: kv[0]):
            name = getattr(func, "name", None) or ""
            if pattern and not pattern.search(name):
                continue
            size = getattr(func, "size", 0) or 0
            entries.append({"addr": addr, "size": int(size), "name": name})

        if args.json:
            _emit_list(args, entries)
        else:
            if not entries:
                print("No functions matched.")
                return 0
            print(f"{'ADDR':<12} {'SIZE':<8} NAME")
            for e in entries:
                print(f"0x{e['addr']:<10x} {e['size']:<8} {e['name']}")
    return 0


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------

def _format_xref(artifact) -> Dict:
    """Render any artifact (Function, GlobalVariable, etc.) as a uniform dict.

    Unlike `_format_function`, this keeps the artifact kind so callers can
    tell code refs apart from data refs.
    """
    return {
        "kind": type(artifact).__name__,
        "addr": getattr(artifact, "addr", None),
        "name": getattr(artifact, "name", None),
    }


def cmd_xref_to(args) -> int:
    """All references — code and data — to the target.

    Note: distinct from `get_callers`, which is call-sites only. `xref_to`
    here asks the backend for *every* artifact that points at the target,
    including globals, strings, and non-call code references.
    """
    from libbs.artifacts import Function

    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        # Build a Function stub to hand to xrefs_to so backends that *do*
        # surface non-function refs (Ghidra via `decompile=True`) can add them.
        func_stub = Function(addr, 0)
        try:
            xrefs = client.xrefs_to(func_stub, decompile=bool(args.decompile))
        except Exception as exc:
            _l.debug("xrefs_to raised %s; falling back to get_callers", exc)
            xrefs = client.get_callers(addr)

        # Enrich Function entries with names from the light artifact cache,
        # since some backends only return (addr, 0) stubs from xrefs_to.
        light_funcs = dict(client.functions.items())
        data: List[Dict] = []
        for x in xrefs:
            entry = _format_xref(x)
            if entry["kind"] == "Function" and not entry.get("name"):
                func = light_funcs.get(entry.get("addr"))
                if func is not None:
                    entry["name"] = getattr(func, "name", None)
            data.append(entry)
        _emit_xrefs(args, addr, data, direction="to")
    return 0


def cmd_xref_from(args) -> int:
    """Return the callees of a function (what the function calls).

    Implementation: decompile the function then scan the callgraph for edges leaving
    this function. Falls back to parsing `call` instructions in disassembly.
    """
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")

        callees: List[Dict] = []
        seen = set()
        try:
            cg = client.get_callgraph(only_names=False)
            for caller, callee in cg.out_edges(nbunch=None):  # type: ignore[attr-defined]
                caller_addr = getattr(caller, "addr", None)
                if caller_addr == addr:
                    callee_addr = getattr(callee, "addr", None)
                    if callee_addr in seen:
                        continue
                    seen.add(callee_addr)
                    callees.append(_format_xref(callee))
        except Exception as exc:
            _l.debug("Callgraph-based xref_from failed (%s); falling back to disasm scan.", exc)

        if not callees:
            # Fallback: parse `call 0x...` from disassembly.
            disasm = client.disassemble(addr) or ""
            call_re = re.compile(r"\bcall\b[^0-9]*0x([0-9a-fA-F]+)")
            functions_by_addr = dict(client.functions.items())
            for match in call_re.finditer(disasm):
                try:
                    callee_addr = int(match.group(1), 16)
                except ValueError:
                    continue
                if callee_addr in seen:
                    continue
                seen.add(callee_addr)
                func = functions_by_addr.get(callee_addr)
                callees.append({
                    "kind": "Function",
                    "addr": callee_addr,
                    "name": func.name if func else None,
                })

        _emit_xrefs(args, addr, callees, direction="from")
    return 0


def _emit_xrefs(args, addr: int, xrefs: List[Dict], *, direction: str) -> None:
    payload = {"addr": addr, "direction": direction, "xrefs": xrefs}
    if args.json:
        print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
        return
    if not xrefs:
        print(f"No xrefs {direction} 0x{addr:x}")
        return
    for x in xrefs:
        a = x.get("addr")
        n = x.get("name") or ""
        kind = x.get("kind") or ""
        if a is not None:
            print(f"0x{a:x}\t{kind}\t{n}" if kind else f"0x{a:x}\t{n}")
        else:
            print(f"?\t{kind}\t{n}" if kind else f"?\t{n}")


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------

def cmd_rename(args) -> int:
    kind = args.kind
    with _with_client(args) as client:
        if kind == "func":
            addr = _resolve_function_addr(client, args.target)
            if addr is None:
                raise SystemExit(f"Function not found: {args.target!r}")
            func = client.functions[addr]
            if not func:
                raise SystemExit(f"Could not load function at 0x{addr:x}")
            func.name = args.new_name
            if func.header is not None:
                func.header.name = args.new_name
            ok = bool(client.set_artifact(func))
            _emit(args, {"kind": "func", "addr": addr, "new_name": args.new_name, "success": ok})
            return EXIT_OK if ok else EXIT_USER_ERROR
        elif kind == "var":
            if not args.function:
                raise SystemExit("--function is required when renaming a variable")
            func_addr = _resolve_function_addr(client, args.function)
            if func_addr is None:
                raise SystemExit(f"Function not found: {args.function!r}")
            func = client.functions[func_addr]
            if not func:
                raise SystemExit(f"Could not load function at 0x{func_addr:x}")
            name_map = {args.target: args.new_name}
            ok = bool(client.rename_local_variables_by_names(func, name_map))
            _emit(args, {"kind": "var", "function_addr": func_addr,
                         "old_name": args.target, "new_name": args.new_name,
                         "success": ok})
            return EXIT_OK if ok else EXIT_USER_ERROR
        raise SystemExit(f"Unknown rename kind: {kind}")


# ---------------------------------------------------------------------------
# list_strings / get_callers (new core APIs)
# ---------------------------------------------------------------------------

def cmd_list_strings(args) -> int:
    """List strings. Two data sources:

    1. The backend's native string detector (default). Fast but fidelity
       varies — angr's detector is thin and will miss most of `.rodata`.
    2. A raw-bytes scan of the binary file (`--rescan`). Equivalent to
       `strings -n <min_length>` plus ELF section labeling. Always enabled
       automatically if the native detector returns fewer than `_RESCAN_FLOOR`
       entries; pass `--no-rescan` to disable.
    """
    _RESCAN_FLOOR = 32

    with _with_client(args) as client:
        filter_pat = re.compile(args.filter) if args.filter else None
        native = client.list_strings(filter=args.filter) or []

        results: List[Dict] = []
        seen = set()
        for addr, s in native:
            if len(s) < args.min_length:
                continue
            seen.add((addr, s))
            results.append({"addr": addr, "string": s, "source": "backend"})

        should_rescan = args.rescan or (
            not args.no_rescan and len(results) < _RESCAN_FLOOR
        )
        if should_rescan:
            # Find the binary path via the registry record.
            record = _select_server(
                server_id=getattr(args, "id", None),
                binary_path=getattr(args, "binary", None),
                backend=getattr(args, "backend", None),
            )
            binary_path = record.get("binary_path")
            if binary_path and os.path.exists(binary_path):
                data = _read_binary_bytes(binary_path)
                if data is not None:
                    sections = _elf_sections_from_file(binary_path)
                    for offset, text in _scan_ascii_strings(data, min_length=args.min_length):
                        if filter_pat and not filter_pat.search(text):
                            continue
                        key = (offset, text)
                        if key in seen:
                            continue
                        seen.add(key)
                        record_entry: Dict = {
                            "addr": offset,
                            "string": text,
                            "source": "rescan",
                        }
                        sec = _section_for_offset(sections, offset)
                        if sec:
                            record_entry["section"] = sec
                        results.append(record_entry)

        # Sort by addr.
        results.sort(key=lambda e: e.get("addr", 0))

        if args.json:
            _emit_list(args, results)
        else:
            for entry in results:
                sec = entry.get("section") or entry.get("source") or ""
                sec_col = f"[{sec}]\t" if sec else ""
                print(f"0x{entry['addr']:x}\t{sec_col}{entry['string']}")
    return 0


def cmd_get_callers(args) -> int:
    """Functions that contain a call to the target (call-sites only).

    Distinct from `xref_to`, which returns every reference (code *or* data).
    If you want the full reference set, use `xref_to` instead.
    """
    with _with_client(args) as client:
        # Reuse the resolver so absolute addresses get normalized to the lifted
        # form the server expects.
        resolved = _resolve_function_addr(client, args.target)
        if resolved is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        try:
            callers = client.get_callers(resolved)
        except ValueError as exc:
            raise SystemExit(str(exc))
        data = [_format_xref(c) for c in callers]
        if args.json:
            _emit(args, {"target": args.target, "target_addr": resolved, "callers": data})
        else:
            if not data:
                print(f"No callers found for {args.target!r}")
            else:
                for entry in data:
                    a = entry.get("addr")
                    n = entry.get("name") or ""
                    print(f"0x{a:x}\t{n}" if a is not None else f"?\t{n}")
    return 0


# ---------------------------------------------------------------------------
# install-skill
# ---------------------------------------------------------------------------

def _default_skill_dest() -> Path:
    return Path(os.path.expanduser("~/.claude/skills"))


def cmd_install_skill(args) -> int:
    dest_root = Path(args.dest).expanduser().resolve() if args.dest else _default_skill_dest()
    names = args.names or skills.available_skills()
    if not names:
        raise SystemExit("No bundled skills to install")

    dest_root.mkdir(parents=True, exist_ok=True)
    installed: List[Dict] = []
    for name in names:
        src = skills.skill_path(name)
        dest = dest_root / name
        if dest.exists() and not args.force:
            raise SystemExit(
                f"Skill already exists at {dest}. Pass --force to overwrite."
            )
        if dest.exists() and args.force:
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        installed.append({"name": name, "path": str(dest)})

    if args.json:
        print(json.dumps({"installed": installed}, indent=2, default=str))
    else:
        for entry in installed:
            print(f"installed {entry['name']} → {entry['path']}")
    return 0


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _annotate_addrs(payload):
    """Recursively add `*_hex` siblings for every `*addr` integer field.

    JSON historically emitted addresses as decimals; feedback was that this
    is awkward when copying from one command to another. Instead of breaking
    existing int fields, we add a sibling hex-string field so both forms
    are available. A key named `addr` gets `addr_hex`, `target_addr` gets
    `target_addr_hex`, `function_addr` gets `function_addr_hex`, etc.
    """
    if isinstance(payload, dict):
        for key in list(payload.keys()):
            value = payload[key]
            if (
                (key == "addr" or key.endswith("_addr"))
                and isinstance(value, int)
                and f"{key}_hex" not in payload
            ):
                payload[f"{key}_hex"] = f"0x{value:x}"
        for v in payload.values():
            _annotate_addrs(v)
    elif isinstance(payload, list):
        for item in payload:
            _annotate_addrs(item)
    return payload


def _emit(args, payload: Dict, *, text_field: Optional[str] = None) -> None:
    """Emit a response either as JSON or as a human-readable block."""
    if args.json:
        print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
        return
    if text_field and text_field in payload:
        print(payload[text_field])
        return
    # Default: key: value lines
    for k, v in payload.items():
        print(f"{k}: {v}")


def _emit_list(args, payload):
    """Same as _emit but for a top-level list payload (JSON arrays)."""
    if args.json:
        print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
        return
    # Fallback: print each item on its own line as "key: value" pairs if
    # it's a dict; otherwise str(item).
    for item in payload:
        if isinstance(item, dict):
            print(" ".join(f"{k}={v}" for k, v in item.items()))
        else:
            print(item)


def _format_function(func) -> Dict:
    return {
        "addr": getattr(func, "addr", None),
        "name": getattr(func, "name", None),
    }


def _read_binary_bytes(binary_path: str, max_bytes: int = 32 * 1024 * 1024) -> Optional[bytes]:
    """Read up to `max_bytes` from `binary_path`. Returns None on failure."""
    try:
        with open(binary_path, "rb") as f:
            return f.read(max_bytes)
    except OSError as exc:
        _l.debug("Could not read binary %s: %s", binary_path, exc)
        return None


def _scan_ascii_strings(data: bytes, min_length: int = 4) -> List[Tuple[int, str]]:
    """strings(1)-equivalent scan over a raw byte buffer.

    Returns `(offset_in_buffer, decoded_ascii)` tuples. The caller is
    responsible for relocating `offset_in_buffer` into whatever address
    space makes sense (e.g. file offset vs mapped vaddr).
    """
    results: List[Tuple[int, str]] = []
    start = -1
    for i, b in enumerate(data):
        # Printable ASCII (space..tilde) plus tab as an allowed interior byte.
        if 0x20 <= b < 0x7f or b == 0x09:
            if start < 0:
                start = i
        else:
            if start >= 0 and (i - start) >= min_length:
                try:
                    text = data[start:i].decode("ascii", errors="strict")
                except UnicodeDecodeError:
                    pass
                else:
                    results.append((start, text))
            start = -1
    if start >= 0 and (len(data) - start) >= min_length:
        try:
            text = data[start:].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            pass
        else:
            results.append((start, text))
    return results


def _section_for_offset(elf_sections: Iterable, offset: int) -> Optional[str]:
    """Return the name of the ELF section a file offset lives in, or None."""
    for name, start, size in elf_sections:
        if start <= offset < start + size:
            return name
    return None


def _elf_sections_from_file(binary_path: str):
    """Return [(name, file_offset, size), ...] for an ELF, or [] if not ELF."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
    except ImportError:
        return []
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            return [(sec.name, sec["sh_offset"], sec["sh_size"]) for sec in elf.iter_sections()]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# argparse plumbing
# ---------------------------------------------------------------------------

def _add_server_filter_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--id", dest="id", help="Server ID to target (see `decompiler list`).")
    p.add_argument("--binary", dest="binary", help="Match server by binary path.")
    p.add_argument("--backend", dest="backend", choices=sorted(SUPPORTED_DECOMPILERS), help="Match server by backend.")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="Emit JSON output instead of text.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decompiler",
        description=(
            "LLM-friendly decompiler CLI powered by LibBS. "
            "Load a binary once, then run decompile/disassemble/xref/rename "
            "commands. Multiple binaries/backends can run concurrently."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # load
    p_load = sub.add_parser("load", help="Load a binary, starting a server if needed.")
    p_load.add_argument("binary", help="Path to the binary to analyze.")
    p_load.add_argument("--backend", default="angr", choices=sorted(SUPPORTED_DECOMPILERS),
                        help="Backend decompiler to use (default: angr).")
    p_load.add_argument("--id", dest="id", help="Explicit server ID (otherwise auto-generated).")
    p_load.add_argument("--force", action="store_true",
                        help="Start a new server even if one already exists for this binary.")
    p_load.add_argument("--replace", action="store_true",
                        help="Stop the existing server for this binary+backend (if any) before starting.")
    _add_output_args(p_load)
    p_load.set_defaults(func=cmd_load)

    # list
    p_list = sub.add_parser("list", help="List running decompiler servers.")
    p_list.add_argument("--show-registry", action="store_true",
                        help="Print just the registry directory path and exit.")
    _add_output_args(p_list)
    p_list.set_defaults(func=cmd_list)

    # list_functions
    p_lf = sub.add_parser("list_functions", help="List functions in the binary.")
    p_lf.add_argument("--filter", dest="filter", help="Regex to filter function names.")
    _add_server_filter_args(p_lf)
    _add_output_args(p_lf)
    p_lf.set_defaults(func=cmd_list_functions)

    # stop
    p_stop = sub.add_parser("stop", help="Stop a running server.")
    p_stop.add_argument("--id", dest="id", help="Server ID to stop.")
    p_stop.add_argument("--binary", dest="binary", help="Stop servers for this binary.")
    p_stop.add_argument("--all", action="store_true", help="Stop every running server.")
    _add_output_args(p_stop)
    p_stop.set_defaults(func=cmd_stop)

    # decompile
    p_dec = sub.add_parser("decompile", help="Decompile a function by name or address.")
    p_dec.add_argument("target", help="Function name or address (hex/decimal).")
    p_dec.add_argument("--raw", action="store_true",
                       help="Print the decompilation text directly (no JSON or header wrapping).")
    _add_server_filter_args(p_dec)
    _add_output_args(p_dec)
    p_dec.set_defaults(func=cmd_decompile)

    # disassemble
    p_dis = sub.add_parser("disassemble", help="Disassemble a function by name or address.")
    p_dis.add_argument("target", help="Function name or address (hex/decimal).")
    p_dis.add_argument("--raw", action="store_true",
                       help="Print the disassembly text directly (no JSON or header wrapping).")
    _add_server_filter_args(p_dis)
    _add_output_args(p_dis)
    p_dis.set_defaults(func=cmd_disassemble)

    # xref_to
    p_xto = sub.add_parser(
        "xref_to",
        help=(
            "Every reference (code AND data) to a target. "
            "For call-sites only, see `get_callers`."
        ),
    )
    p_xto.add_argument("target", help="Function name or address (hex/decimal).")
    p_xto.add_argument("--decompile", action="store_true",
                       help="Ask the backend to decompile first (picks up more refs on Ghidra).")
    _add_server_filter_args(p_xto)
    _add_output_args(p_xto)
    p_xto.set_defaults(func=cmd_xref_to)

    # xref_from
    p_xfrom = sub.add_parser("xref_from", help="Things a function calls (callees).")
    p_xfrom.add_argument("target", help="Function name or address (hex/decimal).")
    _add_server_filter_args(p_xfrom)
    _add_output_args(p_xfrom)
    p_xfrom.set_defaults(func=cmd_xref_from)

    # rename
    p_ren = sub.add_parser("rename", help="Rename a function or a local variable.")
    p_ren.add_argument("kind", choices=["func", "var"], help="What to rename.")
    p_ren.add_argument("target", help="Function name/address (for `func`) or variable name (for `var`).")
    p_ren.add_argument("new_name", help="New name.")
    p_ren.add_argument("--function", help="When renaming a variable, the containing function.")
    _add_server_filter_args(p_ren)
    _add_output_args(p_ren)
    p_ren.set_defaults(func=cmd_rename)

    # list_strings
    p_ls = sub.add_parser(
        "list_strings",
        help=(
            "List strings in the binary. Backend detectors vary in fidelity "
            "(angr < ghidra < ida); --rescan does a raw strings(1)-like scan "
            "of the file as a fallback."
        ),
    )
    p_ls.add_argument("--filter", dest="filter", help="Regex to filter strings.")
    p_ls.add_argument("--min-length", dest="min_length", type=int, default=4,
                      help="Minimum string length to keep (default: 4).")
    p_ls.add_argument("--rescan", action="store_true",
                      help="Force a raw-bytes scan of the binary file on top of the backend result.")
    p_ls.add_argument("--no-rescan", action="store_true",
                      help="Never fall back to the raw scan, even if the backend returns few results.")
    _add_server_filter_args(p_ls)
    _add_output_args(p_ls)
    p_ls.set_defaults(func=cmd_list_strings)

    # get_callers
    p_gc = sub.add_parser(
        "get_callers",
        help=(
            "Functions that call a target (call-sites only). "
            "For every reference (code AND data), see `xref_to`."
        ),
    )
    p_gc.add_argument("target", help="Function name or address (hex/decimal).")
    _add_server_filter_args(p_gc)
    _add_output_args(p_gc)
    p_gc.set_defaults(func=cmd_get_callers)

    # install-skill
    p_sk = sub.add_parser(
        "install-skill",
        help="Install the bundled Agent Skill (SKILL.md) into ~/.claude/skills/.",
    )
    p_sk.add_argument("names", nargs="*",
                      help="Specific skill names to install (default: all bundled).")
    p_sk.add_argument("--dest", help="Install destination (default: ~/.claude/skills).")
    p_sk.add_argument("--force", action="store_true",
                      help="Overwrite an existing skill directory.")
    _add_output_args(p_sk)
    p_sk.set_defaults(func=cmd_install_skill)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", False))
    try:
        return args.func(args) or EXIT_OK
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        _l.exception("Unhandled error: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
