# `decompiler` CLI

The `decompiler` command is a thin, LLM-friendly client over LibBS. You load a
binary once (which spawns a headless decompiler server in the background) and
then run quick inspection or mutation commands against it. Multiple binaries
and backends can be loaded at the same time; each server is identified by a
short ID.

This document is for humans; the short reference version used by LLM agents
lives at [`libbs/skills/decompiler/SKILL.md`](../libbs/skills/decompiler/SKILL.md)
and can be installed with `decompiler install-skill`.

---

## Table of contents

- [Install & setup](#install--setup)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Subcommand reference](#subcommand-reference)
  - [`load`](#load)
  - [`list`](#list)
  - [`stop`](#stop)
  - [`decompile`](#decompile)
  - [`disassemble`](#disassemble)
  - [`xref_to`](#xref_to)
  - [`xref_from`](#xref_from)
  - [`rename`](#rename)
  - [`list_strings`](#list_strings)
  - [`get_callers`](#get_callers)
  - [`install-skill`](#install-skill)
- [Server selection (`--id`, `--binary`, `--backend`)](#server-selection)
- [JSON output (`--json`)](#json-output)
- [Running multiple binaries at once](#running-multiple-binaries-at-once)
- [Address formats](#address-formats)
- [Library-level API](#library-level-api)
- [Troubleshooting](#troubleshooting)

---

## Install & setup

```bash
pip install libbs
# Register LibBS plugins into every detected decompiler.
libbs --install
# Or point the installer at one specific decompiler:
libbs --single-decompiler-install binja "/Applications/Binary Ninja.app"
```

After `pip install libbs`, two entry points are available:

- `libbs` — the existing management CLI (install plugins, run the server,
  etc.)
- `decompiler` — the new LLM-facing CLI documented here.

Pick a backend you have available:

- **angr** — pure Python, always available. Good for end-to-end testing and
  small/medium binaries.
- **ghidra** — requires `GHIDRA_INSTALL_DIR` and uses PyGhidra.
- **binja** — requires a Binary Ninja license.
- **ida** — requires IDA Pro.

---

## Quick start

```bash
# 1. Load a binary. The first call spawns a detached headless server.
decompiler load ./fauxware --backend angr
# id: 3308b81cf8 …

# 2. Poke around.
decompiler decompile main                    # by name
decompiler disassemble 0x40071d              # by absolute address
decompiler xref_to authenticate              # callers of a function
decompiler xref_from main                    # what main calls
decompiler list_strings --filter 'pass|key'  # regex-filtered strings
decompiler get_callers 0x71d                 # lifted address works too

# 3. Mutate the database.
decompiler rename func sub_400662 trampoline
decompiler rename var v2 auth_result --function main

# 4. Tear it down when you're done.
decompiler stop --all
```

---

## How it works

```
┌─────────────┐      spawns       ┌─────────────────────────┐
│  decompiler │ ────────────────▶ │ libbs --server (headless│
│     CLI     │   (first load)    │ decompiler + AF_UNIX    │
│             │                   │ socket)                 │
│             │ ◀─────────────────│                         │
└─────────────┘   every command   └─────────────────────────┘
        │
        ▼
~/.local/state/libbs/servers/<id>.json  ← the shared registry
```

Each running server writes a small JSON descriptor (`id`, `socket_path`,
`binary_path`, `binary_hash`, `backend`, `pid`, `started_at`) into a shared
registry directory. The CLI reads the registry to figure out which server to
talk to. Stale records (server exited, socket missing) are pruned on read.

Every subcommand except `load`, `list`, and `install-skill` accepts
`--id`, `--binary`, and `--backend` to pick which server to target when you
have more than one running.

---

## Subcommand reference

### `load`

Load a binary, starting a headless server if one isn't already running for
it.

```bash
decompiler load <binary> [--backend {angr,ghidra,binja,ida}]
                         [--id SERVER_ID]
                         [--force]
                         [--json]
```

- **`--backend`** (default: `angr`) — which decompiler to use.
- **`--id`** — explicit server ID; otherwise one is auto-generated.
- **`--force`** — start a fresh server even if an existing one matches this
  `(binary, backend)`.

Outputs `id`, `socket_path`, `binary_path`, `backend`, and `status` (either
`started` or `already_loaded`).

### `list`

Show all running decompiler servers.

```bash
decompiler list [--json]
```

Text output:

```
ID           BACKEND  PID      BINARY
3308b81cf8   angr     57613    /…/fauxware
9d77ab8fd4   angr     57786    /…/posix_syscall
```

### `stop`

Stop one or all servers.

```bash
decompiler stop [--id SERVER_ID] [--binary PATH] [--all] [--json]
```

You must pass one of `--id`, `--binary`, or `--all`.

### `decompile`

Decompile a function to pseudocode.

```bash
decompiler decompile <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

`<target>` is a function name or address (hex/decimal, lifted or absolute —
see [Address formats](#address-formats)).

Text output is the decompilation. JSON output includes `addr`, `decompiler`,
and `text`.

### `disassemble`

Disassemble a function to text assembly.

```bash
decompiler disassemble <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

### `xref_to`

Functions that reference/call `target`.

```bash
decompiler xref_to <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

### `xref_from`

Functions that `target` calls (its callees).

```bash
decompiler xref_from <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Implementation note: this prefers the backend's call-graph. If the call-graph
is unavailable it falls back to scanning the function's disassembly for
`call 0x…` instructions.

### `rename`

Rename a function or a local variable.

```bash
# Rename a function.
decompiler rename func <old_name_or_addr> <new_name> [--id ID] [--json]

# Rename a local variable inside a function.
decompiler rename var <old_var_name> <new_var_name> --function <func_name_or_addr> [--id ID] [--json]
```

The CLI exits non-zero if the rename didn't actually change anything (the
response's `success` field is authoritative).

### `list_strings`

List strings in the binary, optionally filtered by regex.

```bash
decompiler list_strings [--filter REGEX] [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Text output is `0x<addr>\t<string>` per line. JSON output is a list of
`{"addr": int, "string": str}`.

### `get_callers`

List callers of a function (by address or symbol name). Equivalent to
`xref_to`, but accepts a `Function`, `int` (address), or `str` (name) and is
exposed as a first-class core API.

```bash
decompiler get_callers <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

### `install-skill`

Copy the bundled Agent Skill into `~/.claude/skills/` so Claude Code (or any
agent that picks up skills from that path) learns how to drive the CLI.

```bash
decompiler install-skill [names ...] [--dest DIR] [--force] [--json]
```

With no `names`, every bundled skill is installed. Use `--dest` to copy the
skill somewhere else, and `--force` to overwrite an existing directory.

---

## Server selection

When more than one server is running, the inspection/mutation commands need
to know which one to talk to. Narrow with any combination of:

- **`--id <SERVER_ID>`** — exact match.
- **`--binary <PATH>`** — match by binary path (resolved to an absolute
  path).
- **`--backend <angr|ghidra|binja|ida>`** — match by backend.

If zero servers match, the CLI errors out and tells you to run
`decompiler load`. If multiple match, it prints a disambiguation list:

```
Multiple servers match. Specify --id to disambiguate:
  3308b81cf8  backend=angr  binary=/…/fauxware
  9d77ab8fd4  backend=angr  binary=/…/posix_syscall
```

---

## JSON output

Pass `--json` on any subcommand to get a structured payload suitable for
downstream parsing. This is the recommended mode for scripts and LLM
callers:

```bash
decompiler decompile main --json
# {"addr": 1821, "decompiler": "angr", "text": "void main(...){...}"}

decompiler list_strings --filter 'flag' --json
# [{"addr": 4197168, "string": "flag{...}"}]

decompiler xref_to authenticate --json
# {"addr": 1636, "direction": "to", "xrefs": [{"addr": 1821, "name": "main"}, ...]}
```

---

## Running multiple binaries at once

```bash
decompiler load ./my-binary                # id=abc1234
decompiler load ./my-binary-2              # id=def5678

decompiler list
# ID           BACKEND  PID      BINARY
# abc1234...   angr     4213     .../my-binary
# def5678...   angr     4217     .../my-binary-2

# Target by ID …
decompiler decompile main --id abc1234

# … or by binary path.
decompiler decompile main --binary ./my-binary-2

# Tear them both down.
decompiler stop --all
```

You can even mix backends on the same binary — add `--force` to `load` to
launch a second server for the same file:

```bash
decompiler load ./bin --backend ghidra
decompiler load ./bin --backend angr --force
decompiler decompile main --binary ./bin --backend ghidra
decompiler decompile main --binary ./bin --backend angr
```

---

## Address formats

LibBS normalizes addresses to a **lifted** form (relative to the binary's
base address), so artifacts stay stable across decompilers. The CLI, though,
accepts whatever is natural for the user:

- `0x71d`, `1821` — lifted
- `0x40071d` — absolute (base + lifted)
- `main` — symbol name

The CLI converts on the fly. The returned `addr` fields in JSON output are
**always lifted**, which matches what the server's artifact dictionaries
use.

---

## Library-level API

Everything the CLI does is also available as a library — useful when you
want to chain operations or integrate LibBS into a larger tool:

```python
from libbs.api.decompiler_client import DecompilerClient

# Pick a running server out of the shared registry.
client = DecompilerClient.discover_from_registry(binary_path="./fauxware")

for addr, func in client.functions.items():
    if func.name == "main":
        print(client.decompile(addr).text)
        print(client.disassemble(addr))
        for caller in client.get_callers(addr):
            print(caller.addr, caller.name)
```

The three APIs added to power the CLI are also usable directly through
`DecompilerInterface` (headless/embedded) and `DecompilerClient` (remote):

- `list_strings(filter: str | None = None) -> list[tuple[int, str]]`
- `get_callers(target: Function | int | str) -> list[Function]`
- `disassemble(addr: int) -> str | None`

Backends currently implementing them: angr and Ghidra. IDA and Binary Ninja
fall back to the default implementations.

---

## Troubleshooting

**`No running decompiler server matches …`**
You haven't loaded the binary yet. Run
`decompiler load <binary> --backend <backend>` first, or use
`decompiler list` to see what's already running.

**`Multiple servers match. Specify --id to disambiguate`**
Two servers match your filters. Either pass `--id` with one of the printed
IDs, or narrow with `--binary`/`--backend`.

**`Timed out waiting … for server … to start.`**
The detached server process didn't come up in time (default 5 minutes).
Check backend prerequisites:
- Ghidra: `GHIDRA_INSTALL_DIR` must be set.
- IDA/Binary Ninja: their Python bindings must be importable.
- angr: should just work.

**Rename reports `success: False`**
The old name was not found in the function (e.g. it was already renamed, or
you targeted the wrong function). The exit code will be non-zero so it's
easy to detect from a script.

**Server-side logs**
Spawned servers have their stdout/stderr sent to `/dev/null`. If you're
debugging server startup, start one by hand in a foreground terminal:

```bash
libbs --server --headless --decompiler angr --binary-path ./bin --server-id my-srv
```

That will print log output to the terminal, and the CLI in another terminal
can still drive it via `decompiler decompile main --id my-srv`.
