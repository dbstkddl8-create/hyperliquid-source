# foundation-string-move-assign-94: what does the 0x514b4f0 window do?

- Component: `foundation`, a string-primitive window in the node #94
  function map (RE-001).
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503`.
- Claim: observations about one target function, its single callee
  arm, and its 20 direct call sites; its source-level name remains
  an inference, not an established fact.
- Included: the 216-byte FDE function with its 8 padding bytes, the
  complete move-assign rule (steal arm, copy arm, self-move arm, and
  the null-old-pointer arm), the memcpy PLT arm, and the full
  direct-e8 caller census with enclosing functions.
- Excluded: which source-level function or component owns this
  window, what the callers' strings mean, and any claim about
  strings beyond the two object arguments.

## Why this packet

The function map needs bounded, digest-bound entries for small
primitives that larger components call. This window is a complete
behavior, not a fragment: an entry function plus the callee that
decides one of its arms (memcpy) plus all 20 consumers that call it.
It is the string move-assign primitive: it transfers a buffer from
source to destination and leaves the source empty, with the
small-string (SSO) and heap cases taking observably different paths
through the same function.

This window was checked for overlap before building: no work-item,
tool, or test in the tree claims `0x514b4f0` (the single grep hit is
a call-site line inside another packet's caller disassembly,
`foundation-nine-eight-gate-94/caller.objdump.txt`, which claims
that packet's own window, not this function), no open WalkCrypto PR
title mentions it or string move-assign, and it is deliberately
distinguished from its neighbours: `0x514b490` (#1320, object-keyed
map::at with a throw arm, a different protocol), `0x514b390` (a
larger string-replace function calling `0x54307c0` and using
snprintf/strlen/replace), and `0x514b5d0` (the following FDE, not
examined beyond its start).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra, Java, or
REA provider was used: `make doctor` reports Rust and Ghidra
unavailable (expected on this VM, exit 1), and `make rea-doctor`
reports the pinned REA package absent. No target binary, captured
service, networked node, or chain operation was executed. All
analysis below is static byte evidence from the digest-verified
work copy `work/hl-node-94.bin`.

```sh
python3 tools/foundation_string_move_assign.py --check research/work-items/foundation-string-move-assign-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_string_move_assign -v
```

Raw exports were generated with:

```sh
objdump -d --start-address=0x514b4f0 --stop-address=0x514b5d0 work/hl-node-94.bin
objdump -d --start-address=<enclosing FDE start> --stop-address=<enclosing FDE end> work/hl-node-94.bin   # once per distinct caller function (13)
objdump --dwarf=frames work/hl-node-94.bin
```

The `window.objdump.txt` file retains complete disassembly of the
function including its 8 padding `int3` bytes. The
`callers.objdump.txt` file retains complete disassembly of each of
the 13 distinct enclosing caller functions (concatenated objdump
output). The `frames.txt` file retains the function FDE line and
the 13 caller FDE lines. `evidence.json` was generated
programmatically from the objdump output and the binary bytes, and
the checker re-derives every claim from the binary.
`MANIFEST.sha256` covers `window.objdump.txt`,
`callers.objdump.txt`, `frames.txt`, `evidence.json`, and this
README, and the checker verifies those hashes.

## Verbatim-evidence note, stated head-on

Every mnemonic, operand, and instruction byte in `evidence.json`
is copied exactly as GNU objdump emitted it, and the checker
verifies each recorded mnemonic against its own line in
`window.objdump.txt` and each recorded instruction byte against
the binary. This function has **no `endbr64`**: its entry
instruction at `0x514b4f0` is `push %rbp`, not a landing pad. The
`nopw`/`nopl` instructions at `0x514b54a`, `0x514b56d`,
`0x514b59a`, `0x514b5a5`, and `0x514b5b7` are genuine compiler
alignment NOPs present in the target binary, not placeholders, and
the 8 `int3` bytes after `0x514b5c8` are padding to the next FDE
at `0x514b5d0`, not code.

## Observations

All addresses below are ELF VAs. The ELF section table maps
`.text` with file offset = VA - `0x1000`.

### Entry, FDE extent, and padding

- `.eh_frame+0x0029a588` describes `[0x514b4f0, 0x514b5c8)`,
  216 bytes. Complete linear decoding from that start gives the
  65 instructions in `evidence.json`, ending exactly at the FDE
  endpoint (the last body instruction is the `jmp 0x514b538` at
  `0x514b5c3` on the self-move path).
- Eight `int3` bytes follow: the next FDE starts exactly at
  `0x514b5d0` (record at `.eh_frame+0x0029a5b4`).
- The function returns void, preserves `rbp`/`rbx`, and balances
  the stack (`sub $0x8,%rsp` at entry, `add $0x8,%rsp` on the
  return path). No stack canary is present.
- The objdump nearest-symbol label is stripped-binary arithmetic,
  not an identity, and no source-level function is claimed from it.

### Object layout (observed, then used consistently)

- Destination object in `rdi` (saved to `rbp`), source object in
  `rsi` (saved to `rbx`).
- Pointer at object+0x0, length at object+0x8, and a union at
  object+0x10: heap capacity when the object is heap-allocated,
  the 16-byte SSO character buffer when it is not. An object is
  SSO exactly when its pointer equals its own +0x10 address:
  the entry compares the destination pointer against
  destination+0x10 (`0x514b50a`) and the source pointer against
  source+0x10 (`0x514b513`).
- This layout reading is what makes the two steal-path stores
  cohere: after a heap-to-heap steal the source's +0x10 slot
  receives the old destination capacity, while after an
  SSO-destination steal the source's +0x10 slot is its new SSO
  character buffer (first byte written 0 by the shared tail).

### Steal arm: source heap, destination not SSO, source not SSO

Taken when both comparisons above are not-equal (`0x514b518`):

- Destination pointer = source pointer, destination length =
  source length, destination capacity = source capacity
  (`0x514b518`–`0x514b528`).
- If the destination's old pointer is null (`0x514b52c`–
  `0x514b52f` je to `0x514b5a0`), the source pointer becomes the
  source's own +0x10 address (its internal buffer) and the shared
  tail empties it — the source becomes an empty SSO string.
- Otherwise the source pointer = old destination pointer, the
  source capacity = old destination capacity, and the shared tail
  (`0x514b538`) sets the source length to 0 and writes 0 to the
  first byte of the old destination buffer. The source ends empty
  but retains the old destination buffer and capacity.

### SSO-destination steal arm: destination SSO, source heap

Taken via `0x514b550` when the destination pointer equals
destination+0x10 but the source pointer does not equal
source+0x10:

- Destination pointer/length/capacity = source
  pointer/length/capacity (`0x514b555`–`0x514b564`).
- Source pointer = the destination's +0x10 address (the
  destination's old SSO buffer, `0x514b568`), then the shared tail
  sets the source length to 0 and writes 0 to that buffer. The
  source ends as an empty SSO string whose buffer is the
  destination's former internal buffer. The source's +0x10 slot is
  not separately written on this path: it *is* that buffer.

### Copy arm: source SSO (memcpy arm)

Taken via `0x514b570` when the source pointer equals source+0x10,
regardless of whether the destination is SSO or heap:

- If destination == source (self-move, `0x514b570`–`0x514b573`
  je to `0x514b5c0`), the shared tail empties the object: length
  0, first byte 0. Self move-assign therefore clears the string
  (a valid-but-unspecified state, recorded as observed, not as a
  claim about what any caller intends).
- If the source length is 0 (`0x514b575`–`0x514b578`), no copy
  runs; the destination length is set to 0 and a terminator is
  written at destination[0].
- If the source length is 1 (`0x514b57a`–`0x514b57e`), a single
  `movzbl`/`mov` pair at `0x514b5a8` copies the one byte; memcpy
  is not called.
- Otherwise `memcpy` is called at `0x514b580` (PLT stub
  `0x5660100`, the function's only call) with the destination
  pointer, source pointer, and source length, then the
  destination length is reloaded from the source object
  (`0x514b585`) and a terminator is written at
  destination[length] (`0x514b591`).
- The tail (`0x514b595`–`0x514b59b` into `0x514b538`) then sets
  the source length to 0 and writes 0 to the first byte of the
  source pointer. The destination pointer and, for a heap
  destination, its capacity are unchanged on this arm.

### Caller census

A full `.text` direct-`e8` scan for calls targeting `0x514b4f0`
finds exactly 20 sites in 13 distinct enclosing FDE functions
(call bytes and targets re-derived by the checker; enclosing
ranges in `evidence.json`):

| call site | enclosing function |
| --- | --- |
| 0x514be33 | 0x514bdf0..0x514be75 |
| 0x514ccaa | 0x514cc10..0x514ccf9 |
| 0x514ddab | 0x514dce0..0x514ddf1 |
| 0x514eaf6 | 0x514e9f0..0x514eb3a |
| 0x514ecc4 | 0x514eb90..0x514ed1b |
| 0x514edc1, 0x514efa9 | 0x514ed50..0x514f223 |
| 0x514ff33 | 0x514fd60..0x514ffd8 |
| 0x51546d6 | 0x5154460..0x51547cd |
| 0x51549b2 | 0x5154830..0x5154ad6 |
| 0x51559a6, 0x5155a3c, 0x5155a73, 0x5155ab4, 0x5155af5 | 0x5155710..0x5155bed |
| 0x5155e30 | 0x5155c50..0x5155fae |
| 0x5157ddf, 0x5157e4e, 0x5157eaa | 0x5157d30..0x5158ebe |
| 0x515963d | 0x5159180..0x515994f |

Two sites were spot-checked as genuine calls with the argument
registers set immediately beforehand (the remaining 18 are
census-only: call bytes and target verified, per-site argument
setup not individually claimed): at `0x514be33` the caller moves
`rbx` to `rdi` and `rbp` to `rsi`; at `0x51546d6` it moves `rax`
to `rdi` and `r13` to `rsi`.

## Inferences, kept separate from observations

- The name "string move-assign" is an inference from the observed
  layout (pointer/length/union), the buffer-transfer semantics,
  and the empty-source postcondition. It is not an established
  source-level name.
- The +0x10 union reading (capacity vs SSO buffer) is an
  inference that explains both steal-path stores; the bytes
  alone show the slot being read and written as a qword.
- The `0x514b390` neighbour is a different, larger string
  operation (it calls `0x54307c0` and uses snprintf/strlen/
  replace); no part of its behavior is claimed here.

## Unknowns

- Which source-level function or component owns this window, and
  what the 20 callers' strings represent.
- Whether a null-pointer destination combined with an SSO source
  is a reachable valid state: the steal arm handles a null old
  destination pointer, but the copy arm would dereference it
  (memcpy destination, or the terminator store). The model
  therefore raises for that combination rather than inventing a
  result.
- Whether any caller relies on the self-move clearing behavior
  or on the source retaining the old destination buffer/capacity
  after a steal; both are recorded as observed postconditions.

## Environment limits, stated honestly

- `make doctor` exits 1 on this VM (Rust toolchains and Ghidra
  unavailable); `make rea-doctor` reports the pinned REA package
  absent. Analysis is GNU objdump static evidence only.
- Repo-wide `make catalogue-check` was not re-run this cycle;
  earlier cycles report its pre-existing LFS-pointer identity
  failure ("Byte coverage target identity differs"), which is
  unrelated to this PR's files and is not claimed as a regression.
- The checker and tests run offline against the digest-verified
  work copy; where the checkout path `artifacts/node/94/hl-node`
  is still an LFS pointer, pass `--binary work/hl-node-94.bin`
  (the tests try the artifact path first, then the work copy).
