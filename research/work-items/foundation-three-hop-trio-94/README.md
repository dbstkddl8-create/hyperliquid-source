# RE-001: what do the three three-hop windows at 0x514acc0, 0x514acf0 and 0x514ad20 compute?

- Component ID: `foundation`, three adjacent small windows; their source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for all three windows' rules; inference for the
  shared-container reading; unresolved for source names, types, and callers.
- Scope included and excluded: included are exactly the three FDE windows
  `0x514acc0..0x514ace2`, `0x514acf0..0x514ad12` and `0x514ad20..0x514ad42`,
  their int3 padding, their FDE records, and a direct-caller census for
  each. Excluded are the preceding windows (`0x514ac90` stub,
  `0x514aca0` sized-delete thunk, `0x514acb0` one-hop reader — different
  protocols, not claimed here), the following window at `0x514ad50` (a
  two-hop chain through `0x928`, not the `0x8e8` chain bound here), all
  #115 addresses, target execution, and Rust reconstruction.

## Why this packet

The three windows are adjacent FDE entries sharing one three-hop chain
and one store/return protocol, so they are bound together as one family
item rather than as three one-window submissions: each takes a container
in `rdi` and an out pointer in `rsi`, loads `base = [rdi + 0x788]`, then
`inner = [base + 0x8e8]`, then projects one field of `inner` into `[rsi]`
and returns 1. The trio differs only in the final projection:
`0x514acc0` copies a qword at `inner + 0xcd0`, `0x514acf0` copies a qword
at `inner + 0xa70`, and `0x514ad20` copies a qword at `inner + 0xa78`.
The last two fields are consecutive qwords, so the `0xa70`/`0xa78`
windows are not interchangeable — the tests pin that distinction.
Neither window calls, branches, or checks anything, so no rule depends on
another's correctness beyond the shared chain shape, which each window's
own bytes establish independently.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514acc0 --stop-address=0x514acf0 work/hl-node-94.bin
objdump -d --start-address=0x514acf0 --stop-address=0x514ad20 work/hl-node-94.bin
objdump -d --start-address=0x514ad20 --stop-address=0x514ad50 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so it
cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was verified
to equal the provenance digest for node #94 (`3b7179cd…c0459f`,
91,774,280 bytes) before any byte was read from it. The checker
therefore takes an optional `--binary` argument: without it, it
verifies the packet files against each other (retained disassembly
bytes, FDE records, padding, rule edges); with it, it additionally
verifies the target digest, the window bytes, the padding, the FDE
pc ranges, and the direct-caller scan against that binary. On a
checkout where the LFS artifact is materialized, run the binary form
with `--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_three_hop_trio.py \
    --check research/work-items/foundation-three-hop-trio-94/evidence.json
python3 tools/foundation_three_hop_trio.py \
    --check research/work-items/foundation-three-hop-trio-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_three_hop_trio -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; `.text` VA `0x1343c80` maps to file offset `0x1342c80` in this
binary, and the checker resolves every VA through the ELF section
headers rather than assuming VA equals file offset. Boundaries are the
FDE pc ranges, validated below against the `.eh_frame` records.

Window `0x514acc0` (34 bytes, FDE `.eh_frame+0x0029a1a8`, range
`0x514acc0..0x514ace2`, SHA-256
`b620d9476f72bb3589095cc5f3ab5004d696bc0ba2061e56a15fdc0821869628`,
14 int3 padding bytes to the next FDE at `0x514acf0`):
`endbr64; mov 0x788(%rdi),%rax; mov 0x8e8(%rax),%rax;
mov 0xcd0(%rax),%rax; mov %rax,(%rsi); mov $0x1,%eax; ret`.
Rule: out = qword at `[[[container + 0x788] + 0x8e8] + 0xcd0]`, return 1.
Direct e8 callers in `.text`: 0.

Window `0x514acf0` (34 bytes, FDE `.eh_frame+0x0029a1bc`, range
`0x514acf0..0x514ad12`, SHA-256
`07966b35f6537dc251e2424859708aa0725596c728b79de5eb199d59b4c098f0`,
14 int3 padding bytes to the next FDE at `0x514ad20`):
same chain, final field `0xa70` instead of `0xcd0`.
Rule: out = qword at `[[[container + 0x788] + 0x8e8] + 0xa70]`, return 1.
Direct e8 callers in `.text`: 0.

Window `0x514ad20` (34 bytes, FDE `.eh_frame+0x0029a1d0`, range
`0x514ad20..0x514ad42`, SHA-256
`77ef72de2bac3f0a630e97e15f4520fe418fb1cd5a7b078c0173a0e70307c8b3`,
14 int3 padding bytes to the next FDE at `0x514ad50`):
same chain, final field `0xa78` instead of `0xa70`.
Rule: out = qword at `[[[container + 0x788] + 0x8e8] + 0xa78]`, return 1.
Direct e8 callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container, the inner object, and
  the three projected fields are not established by these bytes.
- Why these three fields are exposed through identical accessor windows
  (and whether they share a caller through a vtable or indirect call)
  is not established: the direct-caller census finds 0 e8 sites for
  each window, so any caller must reach them indirectly.
- The `0x514ad50` window (two-hop chain through `0x928`) is a separate
  item and is deliberately not folded into this trio.
