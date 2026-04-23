# `decompiler` CLI + Skill — field report from solving `rpc.out`

Context: used the new `decompiler` CLI (angr backend) end-to-end to reverse
`challenge/rpc.out` and construct a solve script. Everything below is a
concrete friction point hit during that session, in rough priority order.

## P0 — missing capability that hurt the workflow

### 1. No way to *list functions*
There is no `decompiler list_functions` / `decompiler functions` command. For
a stripped binary the only entry point from the CLI is `decompile main`, and
from there you discover the call graph one `decompile sub_XXXX` at a time.
For a CTF workflow (or any exploratory reverse), this is painful — I'd expect
something like:

```
decompiler list_functions [--filter REGEX] [--json]
# ADDR       SIZE  NAME
# 0x401b53   240   serve_forever
# 0x401ad3   112   handle_client
# ...
```

The data is clearly available server-side (`client.functions.items()` is
mentioned in `SKILL.md`), it just isn't exposed as a subcommand. This was the
single biggest gap.

### 2. `list_strings` under-reports drastically
On this binary:

```
$ decompiler list_strings | wc -l
18
```

Only 18 strings, and most are PLT/data-table fillers (`0x4f38`, `" "`, `"("`,
`"0"`, ...). `admin`, `private`, `r` were caught. Running `strings -n 4` on
the same binary yields the same "real" strings, so angr isn't *missing* the
ASCII runs in this case — but the output is clearly not a full `.rodata`
walk. For larger binaries it will miss data.

Would be nice if `list_strings`:
- had a `--min-length N` flag (default 4 would cut the noise above),
- distinguished source section (.rodata vs .data vs inline),
- optionally fell back to a raw-bytes scan when the backend's string
  detector is thin (angr is).

## P1 — correctness / UX

### 3. `get_callers` and `xref_to` look redundant
Both commands return the same thing for the same target:

```
$ decompiler xref_to check_auth
0x1690  run_vm
$ decompiler get_callers check_auth
0x1690  run_vm
```

`SKILL.md` lists them as separate subcommands with slightly different
descriptions but no concrete difference in output. Either unify them, or
document precisely when you'd reach for one over the other (e.g. `xref_to`
is data *and* code refs, `get_callers` is call-site only?). As shipped I
never had a reason to use both.

### 4. Mixed hex / decimal addresses in output
Text output prints addresses as hex (`0x3004`), `--json` output prints them
as decimals (`"addr": 12298`). Same data, different radix. Mildly annoying
when piping between commands or copying from a prior output.

Suggestion: JSON should emit `"addr": "0x3004"` (or ship `addr` as int and
`addr_hex` as string), and be consistent across `list_strings`, `xref_to`,
`decompile`, `rename`.

### 5. `rename var` on a nonexistent name exits 2, not 1
```
$ decompiler rename var not_there missing --function run_vm ; echo $?
success: False
2
```

Everywhere else (`decompile nonexistent`, `rename func nonexistent`) exits
`1`. Exit-code inconsistency breaks simple `&&` chaining in shell scripts.

### 6. Decompile failure message doesn't distinguish failure modes
```
$ decompiler decompile 0x999999
Failed to decompile function at 0x999999
```
Was the address invalid? Not a function start? Decompiler bug? Same message
for all three. At minimum, split "no function at address" from "decompilation
engine failed".

### 7. `decompile --json` stuffs the whole pseudocode into one string
```
{"addr": 6995, "decompiler": "angr", "text": "typedef struct ...\n ..."}
```
For LLM consumption this is fine, but when debugging from a terminal the
embedded `\n`s are unreadable. A `--no-escape` or `--raw` flag to print the
`text` body directly (with a JSON header on stderr) would be nice.

## P2 — skill / docs

### 8. `SKILL.md` promises a richer `list_strings` than the angr backend ships
The skill example shows:
```
decompiler list_strings --filter 'flag' --json
# [{"addr": 4197168, "string": "flag{...}"}]
```
On angr this detector is thin (see #2). The skill should either warn
"`list_strings` fidelity varies by backend (angr < ghidra < ida)" or include
a fallback pattern ("if nothing comes back, fall through to `strings(1)` on
the binary directly").

### 9. `SKILL.md` says "Address forms: 0x71d, 0x40071d, and 1821 all resolve the same function"
This worked correctly in my session (both lifted `0x1b53` and absolute
`0x401b53` decompiled `serve_forever`), but the skill doesn't mention that
`decompile` will happily accept an *invalid* address and print
"Failed to decompile function at 0x999999" rather than validating the input.
A note that "address form doesn't round-trip — the CLI canonicalises to
lifted internally" would help downstream agents reason about output.

### 10. Skill lacks a "functions" example
Since `list_functions` doesn't exist (see #1), the skill also can't show
"first step in a new binary: see all functions." A seasoned reverser opens a
new binary and immediately wants the function list. The skill currently
pushes toward `decompile main` as the entry, which only helps if `main` is a
known name — and on stripped binaries where main is `sub_XXXX`, that fails
silently.

## P3 — nits

### 11. Stale server records pile up after `--force`
Running `load ... --force` leaves the old server running (good) and starts a
new one. `decompiler list` shows both, but there's no visual cue that the
two are for the same binary (apart from the path). A column marking
`ORIGINAL`/`FORCED` or a `--kill-existing` flag would be clearer.

### 12. `install-skill` success output is a Python repr, not JSON
```
installed: [{'name': 'decompiler', 'path': '...'}]
```
Single-quoted dict. Either make it valid JSON (so `decompiler install-skill
--json | jq` works) or print a human-friendly line. Currently it's neither.

### 13. Registry state-dir path isn't obvious
`decompiler list` doesn't say *where* the registry lives. When a stale
record survives a reboot or a kill -9, a user has no obvious breadcrumb to
go clean it up. Add the path to `list --json` output or a `--show-registry`
flag.

## What worked well

- `load` + automatic server spawn: zero ceremony, fast on small binaries.
- `--id` / `--binary` disambiguation refusal is exactly right.
- `rename func` / `rename var` worked first try, renames stuck across
  subsequent `decompile` calls, and the JSON surface (`{kind, addr,
  new_name, success}`) is clean.
- `xref_from` on the VM dispatcher gave me the five opcode handlers
  instantly — this is the CLI's sweet spot.
- `install-skill --force` behaved correctly, exit codes correct.
- Multi-server support works; `stop --id` targets cleanly.

## Summary
The CLI handled the solve well enough that I never dropped to `objdump` or
`strings(1)` for *analysis* — only for cross-checking. The two biggest gaps
are **no `list_functions`** (P0) and **under-reporting `list_strings`** (P1).
Everything else is polish.
