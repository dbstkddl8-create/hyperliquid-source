# RE-001: chain-walk dispatch at 0x514ba10 (node #94)

Bounded question: what does function 0x514ba10 do with its two arguments,
and how do its helper 0x52f5290 and its default-handler twin 0x4f8da10
decide the result?

## Target

Node #94 work binary `work/hl-node-94.bin`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
(the digest-pinned copy; `artifacts/node/94/hl-node` is still an LFS
pointer on this checkout). All records in `records.json` are bound to
that digest; `verify.py` re-checks them against the binary.

## The behavior

`0x514ba10` walks a chain of nodes and dispatches on a key string:

```
node = next(input)            # vtable slot +0x88 of the input object
while node is not null:
    handler = node vtable slot +0x38
    if handler != DEFAULT:    # DEFAULT = runtime value of GOT 0x5777b10
        return handler(node, key)     # tail call, same arguments
    hit = table_lookup(node, key)     # 0x52f5290
    if hit != 0: return hit
    node = next(node)
return 0
```

`DEFAULT` is the default handler `0x4f8da10` itself: it tries the
helper first, and on a miss steps exactly one node and tail-calls that
node's handler slot (or returns 0 when the next node is null). The
walker is the looping form of the same dispatch; the caller at
`0x514e7bb` (enclosing function `0x514e550..0x514e7d6`, which inlines
the same pattern) delegates the rest of its walk to this function with
rdi = current node, rsi = the carried key, which confirms the
two-argument protocol.

The walker's first three iterations are unrolled in the bytes: after
the first helper miss it steps to a second node, after the second miss
to a third, and after the third miss it jumps back to the loop head
(`0x514ba1d`) with the current node restored, so the walk is
unbounded, not three steps. The second and third slot compares are
against the previous node's slot, which provably equals the sentinel
on those paths (each is reachable only when the previous slot equalled
it), so they are equivalent to sentinel compares.

`table_lookup` (`0x52f5290`) scans 48-byte records from `[node+0x8]`
to `[node+0x10]`. Each record's key string (pointer at +0x0, length
at +0x8, union at +0x10) is materialized into a stack string — one
byte copied on the length-1 fast path, bytes copied for lengths 2..15,
heap buffer via `_M_create` with old capacity 0 for lengths over 15 —
and compared to the argument string (pointer at +0x0, length at +0x8)
by length then bytes; a zero length matches by length alone. On a
match it returns the record's +0x20 first qword; when no record
matches it returns 0. An empty range returns 0 immediately. The heap
stack string is freed with sized operator delete (capacity + 1) after
the compare on both the match and mismatch paths; the function is
stack-canary protected.

## Files

- `window.objdump.txt` — whole walker function plus int3 padding, verbatim.
- `helper.objdump.txt` — whole helper function plus int3 padding, verbatim.
- `sentinel.objdump.txt` — whole default handler plus int3 padding, verbatim.
- `caller.objdump.txt` — whole enclosing caller function plus padding, verbatim.
- `plt.objdump.txt` — the five PLT stubs the helper calls, verbatim.
- `frames.txt` — the four FDE records, verbatim from readelf.
- `records.json` — semantic records only (carve ranges and SHAs,
  branch site-to-target pairs, call site-to-target pairs, GOT/PLT
  records, censuses, the composed rule). No per-instruction list:
  instruction-level detail lives only in the raw excerpts above.
- `verify.py` — checks every record against the binary (digest,
  carve SHAs, padding, branch/call targets re-derived from raw
  encodings, GOT relocation, PLT slots, FDE lines, censuses, manifest).
- `export_excerpts.py` — regenerates the five excerpts byte-identically
  from the digest-pinned binary.
- `MANIFEST.sha256` — hashes of every packet file.

## Notes on the excerpts

- The walker entry is `push %r13`, not `endbr64`; the helper and the
  sentinel do start with `endbr64`. `endbr64` is a genuine x86-64
  instruction present in the target binary, not a placeholder, and
  every excerpt line is verified byte-for-byte against the binary by
  `tools/foundation_chain_walk_dispatch.py`.
- Objdump's nearest-symbol annotations (e.g. a `ctype` symbol name)
  are NOT claimed as symbol names for these addresses; the packet
  claims only the behavior decoded above.
- The record's trailing 16-byte field at +0x20 is not typed: only its
  first qword is ever returned, so no type is claimed for it.
- The enclosing caller function's own dispatch iterations are
  census-only here, not modelled; only its delegation call to the
  walker is claimed.

## Reproduce

```
python3 research/work-items/RE-001-chain-walk-dispatch-94/verify.py \
    --binary work/hl-node-94.bin
python3 -m pytest tests/test_foundation_chain_walk_dispatch.py -q
```

Excerpt regeneration (from the repository root):

```
python3 research/work-items/RE-001-chain-walk-dispatch-94/export_excerpts.py \
    --binary work/hl-node-94.bin
```

## Environment limits (stated honestly)

This checkout has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make doctor` reports those tools unavailable (expected) and the
repo-wide `make catalogue-check` still fails on its pre-existing
LFS-pointer identity mismatch; neither is a regression from this
change. The packet verifier and the model tests below are the checks
that were actually run for this item.
