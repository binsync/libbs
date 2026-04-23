---
name: decompiler
description: Reverse-engineer and modify binaries with a single `decompiler` CLI that drives IDA Pro, Ghidra, Binary Ninja, or angr via LibBS. Use whenever the user asks to decompile, disassemble, look up cross references, rename functions or variables, search strings or functions, or otherwise inspect a binary file. Also use for multi-binary workflows (load several binaries at once and switch between them with --id).
---

# `decompiler` — LibBS CLI for LLMs

The `decompiler` command is a thin client that talks to a long-running
`DecompilerServer` (IDA / Ghidra / Binary Ninja / angr). The first `load` of a
binary spawns a server in the background; every subsequent call reuses that
server, so repeated `decompile`/`disassemble`/`xref_*` calls are fast.

## Setup (once per environment)

```bash
pip install libbs          # installs the `decompiler` and `libbs` entry points
libbs --install            # registers LibBS plugins into detected decompilers
```

If you only want one backend (for example, Binary Ninja), use:
```bash
libbs --single-decompiler-install binja /Applications/Binary\ Ninja.app
```

`angr` needs no host install — it's a Python dependency and the fastest way
to verify the pipeline end-to-end.

## Mental model

| Concept | Description |
|---|---|
| **Server** | A headless `libbs --server` process holding a single binary open. Identified by a short ID. |
| **Client** | Every `decompiler <subcommand>` call is a short-lived client that picks a server, does one thing, and exits. |
| **Registry** | `decompiler list` / the shared registry under the libbs state dir. Each record has `id`, `backend`, `binary_path`, `socket_path`, `pid`. Use `decompiler list --show-registry` to print just the path. |
| **Address form** | Servers expose **lifted** addresses (relative to the binary base). The CLI accepts either lifted (`0x71d`) or absolute (`0x40071d`) and does the conversion. JSON output always includes both `addr` (int) and `addr_hex` (hex string). |

## First moves on a new binary

```bash
decompiler load ./target                      # start a server (angr by default)
decompiler list_functions                     # enumerate every function
decompiler list_functions --filter 'main|auth' # or narrow by regex
decompiler list_strings --filter 'flag|pass' # find useful string constants
```

For stripped binaries `decompile main` often fails — use `list_functions`
first to discover the real entry (`sub_XXXX`, `entry`, etc.) and start from
there.

## Core workflow

```bash
decompiler load ./fauxware                    # start a server
decompiler list_functions                     # enumerate functions
decompiler decompile main                     # by name
decompiler disassemble 0x40071d               # by absolute address
decompiler xref_to authenticate               # every code+data reference
decompiler get_callers authenticate           # call-sites only (subset of xref_to)
decompiler xref_from main                     # what does main call?
decompiler list_strings --filter 'pass|key'   # backend detector + raw fallback
decompiler rename func sub_400662 trampoline  # rename a function
decompiler rename var v2 auth_result --function main  # rename a local
decompiler stop --all
```

## Running multiple binaries concurrently

Each binary gets its own server ID:

```bash
decompiler load ./my-binary            # id=abc1234
decompiler load ./my-binary-2          # id=def5678
decompiler list
# ID           BACKEND  PID      BINARY
# abc1234...   angr     4213     .../my-binary
# def5678...   angr     4217     .../my-binary-2
decompiler decompile main --id abc1234
decompiler decompile main --binary ./my-binary-2   # or target by path
```

When more than one server matches, the CLI refuses and prints a
disambiguation list. Narrow with `--id`, `--binary`, or `--backend`. If you
want to restart the server for a binary cleanly, use `load ... --replace`
which stops the old server and starts a new one (vs `--force` which adds a
second server alongside the existing one).

## Choosing a backend

```bash
decompiler load ./my-binary --backend ghidra   # needs GHIDRA_INSTALL_DIR
decompiler load ./my-binary --backend angr     # pure-Python, always available
decompiler load ./my-binary --backend binja    # Binary Ninja, needs license
decompiler load ./my-binary --backend ida      # IDA Pro, needs install
```

`--backend` is also accepted on the inspection/mutation subcommands to
narrow which server to target when multiple backends are loaded for the
same binary.

## Full subcommand reference

| Subcommand | Purpose | Key flags |
|---|---|---|
| `load <bin>` | Start a server on the binary. Idempotent: returns existing unless `--force`/`--replace`. | `--backend`, `--id`, `--force`, `--replace`, `--json` |
| `list` | Show all running servers and the registry path. | `--show-registry`, `--json` |
| `stop` | Shut down one or all servers. | `--id`, `--binary`, `--all`, `--json` |
| `list_functions` | Enumerate every function (ADDR, SIZE, NAME). | `--filter REGEX`, `--json` |
| `decompile <target>` | Pseudocode for a function (name or address). | `--raw`, `--id`, `--binary`, `--backend`, `--json` |
| `disassemble <target>` | Assembly for a function. | `--raw`, same |
| `xref_to <target>` | Every reference (code + data) to the target. | `--decompile`, same |
| `xref_from <target>` | Functions that `target` calls. | same |
| `rename func <target> <new>` | Rename a function. | same + `--json` |
| `rename var <old> <new> --function <f>` | Rename a local variable inside a function. | same |
| `list_strings` | Strings (backend + raw rescan fallback). | `--filter`, `--min-length N`, `--rescan`, `--no-rescan`, same |
| `get_callers <target>` | Call-sites only — subset of `xref_to`. | same |
| `install-skill` | Install this file into `~/.claude/skills/`. | `--dest`, `--force`, `--json` |

### `xref_to` vs `get_callers`

- `xref_to` asks the backend for **every reference** — code *and* data. On
  Ghidra with `--decompile` this includes global variables and string
  references. Rows include a `kind` field (`Function`, `GlobalVariable`,
  ...).
- `get_callers` is the narrower call-sites-only view: only functions that
  contain a `call` to the target. When you want "who calls this?" reach
  for `get_callers`; when you want "who touches this in any way?" reach
  for `xref_to`.

### `list_strings` fidelity

String detection quality varies by backend: `angr < ghidra < ida`. The CLI
hides this: if the backend returns few results (threshold: 32), we auto-run
a raw `strings(1)`-like scan of the binary file and label those entries
with their ELF section (`.rodata`, `.dynstr`, `.text`, etc.). Use
`--rescan` to force the scan, or `--no-rescan` to skip it and see only the
backend result. `--min-length` defaults to 4.

## Machine-readable output

Pass `--json` on any subcommand to get a structured payload suitable for
downstream parsing — ideal when an LLM wants to chain commands. Every
JSON payload that mentions an address provides both `addr` (int, lifted)
and `addr_hex` (hex string, also lifted):

```bash
decompiler list_functions --filter '^main$' --json
# [{"addr": 1821, "size": 184, "name": "main", "addr_hex": "0x71d"}]

decompiler list_strings --filter 'flag' --json
# [{"addr": 4197168, "string": "flag{...}", "source": "backend", "addr_hex": "0x4008e0"},
#  {"addr": 4197232, "string": "flag_check_ok", "source": "rescan",
#   "section": ".rodata", "addr_hex": "0x400900"}]

decompiler decompile main --json
# {"addr": 1821, "decompiler": "angr", "text": "void main(...){...}", "addr_hex": "0x71d"}

# Terminal-friendly form of decompile: skip JSON wrapping entirely.
decompiler decompile main --raw
```

## Gotchas and tips

- **First `load` is slow** (backend analysis pass). Subsequent calls on the
  same server are fast.
- **`rename` exit codes**: every CLI command exits `0` on success and `1`
  on any failure (including "rename didn't find the old name"). Use
  `&&` safely.
- **Stripped binaries**: use `list_functions` before `decompile` to find
  the real entry. `main` may not exist; look for `sub_XXXX` with plausible
  sizes and xrefs.
- **Invalid addresses** fail with a clear message distinguishing "no
  function starts here" from "decompiler engine failed". The CLI does not
  auto-round-trip invalid addresses.
- **Address formats**: `0x71d`, `0x40071d`, and `1821` all resolve the
  same function in fauxware. Names are also accepted wherever an address
  is.
- **Servers persist** until explicitly stopped (`decompiler stop --all`)
  or the host reboots; `decompiler list` always reflects live processes.
- **Registry path**: `decompiler list --show-registry` prints just the
  directory so you can clean up manually if you ever need to (e.g. after
  a `kill -9`).

## Library-level API (for Python scripts)

Everything the CLI does is also available as a library:

```python
from libbs.api.decompiler_client import DecompilerClient

client = DecompilerClient.discover_from_registry(binary_path="./fauxware")
for addr, func in client.functions.items():
    if func.name == "main":
        print(client.decompile(addr).text)
```

The new core APIs (`list_strings(filter=...)`, `get_callers(target)`,
`disassemble(addr)`) are on both the local `DecompilerInterface` and the
`DecompilerClient` proxy.
