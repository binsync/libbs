"""
The `decompiler` CLI: a simplified, LLM-friendly interface to libbs.

The CLI is a client that connects to a DecompilerServer. The first `load` of
a binary auto-starts a headless server in the background; subsequent CLI
invocations (including `load`s of other binaries) connect to the right server
via the shared server registry (see libbs.api.server_registry).

Subcommands implemented:
- load          start a server on a binary
- list          list running servers
- stop          stop one or all servers
- decompile     decompile a function by name or address
- disassemble   disassemble a function by name or address
- xref_to       list callers/references to a name or address
- xref_from     list callees of a function (things it calls)
- rename        rename a function or local variable
- list_strings  list strings in the binary, optionally filtered by regex
- get_callers   list callers of a function
- install-skill install the bundled Agent Skill so LLMs learn the CLI
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
from typing import Dict, List, Optional, Tuple

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

    # If there's already a matching server for this exact binary+backend, prefer that.
    existing = server_registry.find_servers(binary_path=str(binary_path), backend=backend)
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
    if args.json:
        print(json.dumps(records, indent=2, default=str))
        return 0
    if not records:
        print("No running decompiler servers.")
        return 0
    print(f"{'ID':<12} {'BACKEND':<8} {'PID':<8} BINARY")
    for r in records:
        print(f"{r.get('id',''):<12} {str(r.get('backend','')):<8} {str(r.get('pid','')):<8} {r.get('binary_path','')}")
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

def cmd_decompile(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        dec = client.decompile(addr)
        if dec is None:
            raise SystemExit(f"Failed to decompile function at 0x{addr:x}")
        out = {
            "addr": addr,
            "decompiler": dec.decompiler if hasattr(dec, "decompiler") else None,
            "text": dec.text if hasattr(dec, "text") else str(dec),
        }
        _emit(args, out, text_field="text")
    return 0


def cmd_disassemble(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        text = client.disassemble(addr)
        if text is None:
            raise SystemExit(f"Failed to disassemble function at 0x{addr:x}")
        _emit(args, {"addr": addr, "text": text}, text_field="text")
    return 0


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------

def _format_function(func) -> Dict:
    out = {
        "addr": getattr(func, "addr", None),
        "name": getattr(func, "name", None),
    }
    return out


def cmd_xref_to(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        callers = client.get_callers(addr)
        data = [_format_function(c) for c in callers]
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
                    callees.append(_format_function(callee))
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
                    "addr": callee_addr,
                    "name": func.name if func else None,
                })

        _emit_xrefs(args, addr, callees, direction="from")
    return 0


def _emit_xrefs(args, addr: int, xrefs: List[Dict], *, direction: str) -> None:
    payload = {"addr": addr, "direction": direction, "xrefs": xrefs}
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return
    if not xrefs:
        print(f"No xrefs {direction} 0x{addr:x}")
        return
    for x in xrefs:
        a = x.get("addr")
        n = x.get("name") or ""
        print(f"0x{a:x}\t{n}" if a is not None else f"?\t{n}")


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
            return 0 if ok else 2
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
            return 0 if ok else 2
        raise SystemExit(f"Unknown rename kind: {kind}")


# ---------------------------------------------------------------------------
# list_strings / get_callers (new core APIs)
# ---------------------------------------------------------------------------

def cmd_list_strings(args) -> int:
    with _with_client(args) as client:
        strings = client.list_strings(filter=args.filter)
        if args.json:
            print(json.dumps(
                [{"addr": a, "string": s} for a, s in strings],
                indent=2, default=str,
            ))
        else:
            for addr, s in strings:
                print(f"0x{addr:x}\t{s}")
    return 0


def cmd_get_callers(args) -> int:
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
        data = [_format_function(c) for c in callers]
        if args.json:
            print(json.dumps({"target": args.target, "callers": data}, indent=2, default=str))
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

    _emit(args, {"installed": installed})
    return 0


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _emit(args, payload: Dict, *, text_field: Optional[str] = None) -> None:
    """Emit a response either as JSON or as a human-readable block."""
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return
    if text_field and text_field in payload:
        print(payload[text_field])
        return
    # Default: key: value lines
    for k, v in payload.items():
        print(f"{k}: {v}")


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
    _add_output_args(p_load)
    p_load.set_defaults(func=cmd_load)

    # list
    p_list = sub.add_parser("list", help="List running decompiler servers.")
    _add_output_args(p_list)
    p_list.set_defaults(func=cmd_list)

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
    _add_server_filter_args(p_dec)
    _add_output_args(p_dec)
    p_dec.set_defaults(func=cmd_decompile)

    # disassemble
    p_dis = sub.add_parser("disassemble", help="Disassemble a function by name or address.")
    p_dis.add_argument("target", help="Function name or address (hex/decimal).")
    _add_server_filter_args(p_dis)
    _add_output_args(p_dis)
    p_dis.set_defaults(func=cmd_disassemble)

    # xref_to
    p_xto = sub.add_parser("xref_to", help="Functions/code that call or reference a target.")
    p_xto.add_argument("target", help="Function name or address (hex/decimal).")
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
    p_ls = sub.add_parser("list_strings", help="List strings in the binary.")
    p_ls.add_argument("--filter", dest="filter", help="Regex to filter strings.")
    _add_server_filter_args(p_ls)
    _add_output_args(p_ls)
    p_ls.set_defaults(func=cmd_list_strings)

    # get_callers
    p_gc = sub.add_parser("get_callers", help="List callers of a function (Function|addr|name).")
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
        return args.func(args) or 0
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        _l.exception("Unhandled error: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
