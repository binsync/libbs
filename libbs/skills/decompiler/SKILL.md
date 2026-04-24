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

**Always start with `list_functions` and `list_strings`** — the same binary
can have the entry named `main` (angr), `FUN_00101c5c` (Ghidra), or
`sub_101c5c` (IDA). Don't assume `main` exists.

```bash
decompiler load ./target                       # start a server (angr by default)
decompiler list_functions                      # enumerate every function — pick a real entry
decompiler list_functions --filter 'main|auth' # or narrow by regex
decompiler list_strings --filter 'flag|pass'   # find interesting string constants
```

Typical first-hour workflow on a stripped binary:

1. `decompiler load ./bin --backend ghidra` (or `angr` if no Ghidra install)
2. `decompiler list_functions` → note non-stub function names + sizes
3. `decompiler list_strings` → look for error messages, user prompts,
   format strings — they often point at the interesting code
4. `decompiler xref_to "Welcome"` → jump from a string to its users
5. `decompiler decompile <addr>` on whichever function came out of steps 3–4

## Core workflow

```bash
decompiler load ./fauxware                    # start a server
decompiler list_functions                     # enumerate functions (do this first)
decompiler list_strings --filter 'pass|key'   # strings the decompiler identified
decompiler xref_to SOSNEAKY                   # who references this string?
decompiler decompile authenticate             # by name (from list_functions)
decompiler disassemble 0x40071d               # by absolute address
decompiler xref_to authenticate               # every code+data reference
decompiler get_callers authenticate           # call-sites only (subset of xref_to)
decompiler xref_from main                     # what does main call?
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
| `load <bin>` | Start a server on the binary. Idempotent: returns existing unless `--force`/`--replace`. | `--backend`, `--id`, `--force`, `--replace`, `--project-dir`, `--json` |
| `list` | Show all running servers and the registry path. | `--show-registry`, `--json` |
| `stop` | Shut down one or all servers. | `--id`, `--binary`, `--all`, `--json` |
| `list_functions` | Enumerate every function (ADDR, SIZE, NAME). | `--filter REGEX`, `--json` |
| `decompile <target>` | Pseudocode for a function (name or address). | `--raw`, `--id`, `--binary`, `--backend`, `--json` |
| `disassemble <target>` | Assembly for a function. | `--raw`, same |
| `xref_to <target>` | Every reference (code + data) to the target. | `--decompile`, same |
| `xref_from <target>` | Functions that `target` calls. | same |
| `rename func <target> <new>` | Rename a function. | same + `--json` |
| `rename var <old> <new> --function <f>` | Rename a local variable inside a function. | same |
| `list_strings` | Strings the decompiler found (may be incomplete — see below). | `--filter`, `--min-length N`, same |
| `get_callers <target>` | Call-sites only — subset of `xref_to`. | same |
| `install-skill` | Install this file for Claude Code or Codex. | `--agent`, `--dest`, `--force`, `--json` |

### `xref_to` vs `get_callers`

- `xref_to` asks the backend for **every reference** — code *and* data. On
  Ghidra with `--decompile` this includes global variables and string
  references. Rows include a `kind` field (`Function`, `GlobalVariable`,
  ...). `xref_to` also accepts **strings and raw addresses**: if the
  target isn't a function, it's looked up in `list_strings` first, then
  queried as a raw-address xref — so you can go straight from
  `list_strings --filter "admin"` to `xref_to admin` to find who reads
  that constant.
- `get_callers` is the narrower call-sites-only view: only functions that
  contain a `call` to the target. When you want "who calls this?" reach
  for `get_callers`; when you want "who touches this in any way?" reach
  for `xref_to`.

### `list_strings` may be incomplete

`list_strings` returns exactly what the backend's own string detector
surfaced — the CLI does not second-guess the decompiler. Fidelity varies
(`angr < ghidra < ida`); angr in particular misses most of `.rodata`. If
the output looks thin, check the binary file directly with an external
scanner:

```bash
strings -a -n 4 ./target          # classic strings(1)
rabin2 -z ./target                # radare2: ASCII data-section scan
readelf -p .rodata ./target       # ELF-specific, per section
```

Use those to confirm a specific constant exists, then come back and
`decompile` / `xref_to` its address inside the CLI. `--min-length`
defaults to 4.

## Machine-readable output

Pass `--json` on any subcommand to get a structured payload suitable for
downstream parsing — ideal when an LLM wants to chain commands. Every
JSON payload that mentions an address provides both `addr` (int, lifted)
and `addr_hex` (hex string, also lifted):

```bash
decompiler list_functions --filter '^main$' --json
# [{"addr": 1821, "size": 184, "name": "main", "addr_hex": "0x71d"}]

decompiler list_strings --filter 'flag' --json
# [{"addr": 4197168, "string": "flag{...}", "addr_hex": "0x4008e0"}]

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
  the real entry. `main` may not exist; look for non-default names
  (`sub_XXXX`, `FUN_...`, `entry`, etc.) with plausible sizes and xrefs.
- **Backend main-naming varies**: angr promotes the entry to `main`,
  Ghidra leaves `FUN_00101c5c`, IDA emits `sub_101c5c`. Always resolve via
  `list_functions` or a known entry address, not by assuming `main`.
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
- **Project/database files**: by default they live in
  `<user-cache>/libbs/projects/<binary>-<hash>/`, not next to the binary.
  Pass `--project-dir <path>` to `load` to override, or `--project-dir ""`
  to restore the legacy "write next to the binary" behavior.

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
