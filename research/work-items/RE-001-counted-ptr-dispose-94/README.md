# RE-001: counted-pointer dispose at 0x514bb10 (node #94)

Bounded question: what does function 0x514bb10 do with its counted
object, and how does its default-dispose guard 0x4f9ea60 continue
the walk?

## Target

Node #94 work binary `work/hl-node-94.bin`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
(the digest-pinned copy; `artifacts/node/94/hl-node` is still an LFS
pointer on this checkout). All records in `records.json` are bound to
that digest; `verify.py` re-checks them against the binary.

## The behavior

`0x514bb10` is vtable slot 2 (dispose) of the
`_Sp_counted_ptr_inplace` family whose other slots were bound by
#1322 (slot 0 complete destructor, slot 1 deleting destructor, slot
3 destroy, slot 4 `_M_get_deleter`). It takes a counted object:

```
value = [object + 0x18]
if value == 0: return              # head node never read
node = [object + 0x10]
fn = node vtable slot +0x38
if fn != GUARD:                     # GUARD = runtime value of GOT
    call fn(node, value, 0)         # 0x5777960, RELATIVE to 0x4f9ea60
    return
while stepping node = [node + 0x38]:
    if node slot +0x38 != previous node's slot:
        tail-call it with (node, value, 0)
    if five nodes examined: tail-call the fifth node's slot
        unconditionally (if it is the guard, the guard continues)
```

The guard `0x4f9ea60` is the default dispose. It takes a node, a
second argument it never touches, and a flag byte in dl (widened by
movzbl, passed through unchanged). It walks from `[node + 0x38]`
onward with the same rule over nine nodes: the first node's dispose
is compared against the guard itself, later nodes against the
previous node's dispose, and the ninth node's dispose is tail-called
unconditionally. A guard tail-call therefore recurses, so the walk
is unbounded, not five or nine steps.

The guard is shared: 97 sites across `.text` compare a slot
function against this same GOT slot (full disassembly count). This
packet decodes only the dispose and guard sites; the other uses are
other functions' dispatches on the same default and are not claimed
here.

Two equivalences used by the model, both provable from the bytes:
the previous-slot compares are equivalent to guard compares on
every reachable path, because a node is only reached when the
previous node's dispose equalled the guard (or, for the first node,
the guard itself); and dispose's first-node invocation is a real
call (stack adjusted, returns) while every later invocation is a
tail jump, so dispose returns only on the null arm and the
first-node call path.

Mnemonics such as `endbr64` in the raw excerpts are genuine
instructions present in the target binary, not placeholders: the
excerpts are verbatim objdump output, and the tools checker
re-verifies every excerpt byte against the binary. The bytes at
`0x514bb95` are a separate landing-pad FDE, not part of dispose,
which has zero int3 padding; the guard has six int3 bytes to its
next FDE at `0x4f9eb10`.

## What is NOT claimed

The node type, the meaning of `[object + 0x18]` beyond "the second
dispose argument", and what a non-guard dispose does with its
arguments are not pinned here — only the dispatch rule. Objdump's
nearest-symbol annotations are explicitly not claimed as symbol
names. The sibling vtable slots are cited from #1322, not
re-claimed; only the slot-2 dispose behavior and its guard are new.

## Files

- `records.json` — semantic records only (carve ranges + SHAs,
  branch/call site→target pairs, GOT/vtable relocations, FDE
  records, censuses, rule). No per-instruction mnemonic list.
- `window.objdump.txt` — whole dispose function, verbatim.
- `guard.objdump.txt` — whole guard function plus its int3
  padding, verbatim.
- `frames.txt` — the two FDE lines.
- `relocations.txt` — the vtable and GOT relocation lines.
- `verify.py` — packet verifier (run it; see its header).
- `export_excerpts.py` — regenerates both excerpts byte-identically.
- `MANIFEST.sha256` — hashes of every packet file.

## Verification

Run from the repository root:

```
python3 research/work-items/RE-001-counted-ptr-dispose-94/verify.py \
    --binary work/hl-node-94.bin
python3 -m pytest tests/test_foundation_counted_ptr_dispose.py -q
```

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs and no Ghidra/Java, so `make doctor` fails (expected)
and the repo-wide `make catalogue-check` still fails on its
pre-existing LFS-pointer identity baseline; neither is a regression
from this change, and neither blocks this digest-bound packet.
