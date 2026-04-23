---
name: decompiler
description: Reverse-engineer and modify binaries with a single `decompiler` CLI that drives IDA Pro, Ghidra, Binary Ninja, or angr via LibBS. Use whenever the user asks to decompile, disassemble, look up cross references, rename functions or variables, search strings, or otherwise inspect a binary file. Also use for multi-binary workflows (load several binaries at once and switch between them with --id).
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
| **Registry** | `decompiler list` / the shared registry under the libbs state dir. Each record has `id`, `backend`, `binary_path`, `socket_path`, `pid`. |
| **Address form** | Servers expose **lifted** addresses (relative to the binary base). The CLI accepts either lifted (`0x71d`) or absolute (`0x40071d`) and does the conversion. |

## Core workflow

```bash
# 1. Load a binary (auto-starts a server; default backend = angr).
decompiler load ./fauxware
# 2. Poke around.
decompiler decompile main
decompiler disassemble authenticate
decompiler xref_to authenticate        # who calls this?
decompiler xref_from main              # what does main call?
decompiler list_strings --filter 'pass|key'
decompiler get_callers 0x71d
# 3. Mutate the database.
decompiler rename func sub_400662 trampoline
decompiler rename var v2 auth_result --function main
# 4. Tidy up when done.
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
disambiguation list. Narrow with `--id`, `--binary`, or `--backend`.

## Choosing a backend

```bash
decompiler load ./my-binary --backend ghidra   # needs GHIDRA_INSTALL_DIR
decompiler load ./my-binary --backend angr     # pure-Python, always available
decompiler load ./my-binary --backend binja    # Binary Ninja, needs license
decompiler load ./my-binary --backend ida      # IDA Pro, needs install
```

`--backend` is also accepted on `decompile`/`disassemble`/`xref_*`/`rename`/
`list_strings`/`get_callers` to narrow which server to target when multiple
backends are loaded for the same binary.

## Full subcommand reference

| Subcommand | Purpose | Key flags |
|---|---|---|
| `load <bin>` | Start a server on the binary. Idempotent: returns existing server unless `--force`. | `--backend`, `--id`, `--force`, `--json` |
| `list` | Show all running servers. | `--json` |
| `stop` | Shut down one or all servers. | `--id`, `--binary`, `--all`, `--json` |
| `decompile <target>` | Pseudocode for a function (name or address). | `--id`, `--binary`, `--backend`, `--json` |
| `disassemble <target>` | Assembly for a function. | same |
| `xref_to <target>` | Functions that call `target`. | same |
| `xref_from <target>` | Functions that `target` calls. | same |
| `rename func <target> <new>` | Rename a function. | same + `--json` |
| `rename var <old> <new> --function <f>` | Rename a local variable inside a function. | same |
| `list_strings [--filter REGEX]` | Strings in the binary, regex-filterable. | same |
| `get_callers <target>` | Functions that call `target` (by addr, lifted addr, or name). | same |

## Machine-readable output

Pass `--json` on any subcommand to get a structured payload suitable for
downstream parsing — ideal when an LLM wants to chain commands:

```bash
decompiler list_strings --filter 'flag' --json
# [{"addr": 4197168, "string": "flag{...}"}]
decompiler decompile main --json
# {"addr": 1821, "decompiler": "angr", "text": "void main(...){...}"}
```

## Gotchas and tips

- **First `load` is slow** (analysis pass). Subsequent calls on the same
  server are fast.
- **Rename's "success" is authoritative**: if the old name is missing the
  command exits non-zero and reports `success: false`.
- **Servers persist until explicitly stopped** (`decompiler stop --all`) or
  the host reboots; `decompiler list` always reflects live processes.
- **Address formats**: `0x71d`, `0x40071d`, and `1821` all resolve the same
  function in fauxware. Names are also accepted anywhere an address is.
- **Binary Ninja / IDA / Ghidra backends**: the CLI still works the same; only
  the server process differs. `--backend` on `load` is what matters.

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
