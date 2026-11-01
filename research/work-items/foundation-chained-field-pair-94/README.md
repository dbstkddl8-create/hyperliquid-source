# RE-001: what do the two chained-field windows at 0x514ac20 and 0x514ac40 compute?

- Component ID: `foundation`, two adjacent small windows; their source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for both windows' rules; inference for the
  shared-container reading; unresolved for source names, types, and callers.
- Scope included and excluded: included are exactly the two FDE windows
  `0x514ac20..0x514ac3f` and `0x514ac40..0x514ac5f`, their int3 padding,
  their FDE records, and a direct-caller census for each. Excluded are
  the preceding windows (`0x514ab90`, `0x514abb0`, `0x514abf0`, already
  bound in #1283/#1282), the following window at `0x514ac60` (a different
  register protocol: r8/rcx inputs, not claimed here), all #115
  addresses, target execution, and Rust reconstruction.

## Why this packet

The two windows are adjacent FDE entries sharing one two-hop chain and
one store/return protocol, so they are bound together as one family item
rather than as two one-window submissions: each takes a container in
`rdi` and an out pointer in `rsi`, loads `base = [rdi + 0x788]`, then
`inner = [base + 0x30]`, then projects one field of `inner` into
`[rsi]` and returns 1. The pair differs only in the final projection:
`0x514ac20` sign-extends a 32-bit field at `inner + 0xb30` (movslq),
while `0x514ac40` copies a full qword at `inner + 0x1008`. Neither
window calls, branches, or checks anything, so neither rule depends on
the other's correctness beyond the shared chain shape, which each
window's own bytes establish independently.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ac20 --stop-address=0x514ac40 work/hl-node-94.bin
objdump -d --start-address=0x514ac40 --stop-address=0x514ac60 work/hl-node-94.bin
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
python3 tools/foundation_chained_field_pair.py \
    --check research/work-items/foundation-chained-field-pair-94/evidence.json
python3 tools/foundation_chained_field_pair.py \
    --check research/work-items/foundation-chained-field-pair-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_chained_field_pair -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; `.text` VA `0x1343c80` maps to file offset `0x1342c80` in this
binary, and the checker resolves every VA through the ELF section
headers rather than assuming VA equals file offset. Boundaries are the
FDE pc ranges, validated below against the `.eh_frame` records.

Window `0x514ac20` (31 bytes, FDE `.eh_frame+0x0029a130`, range
`0x514ac20..0x514ac3f`, SHA-256
`f9b13fa74f01e307c5c2963df4cf30235de6a258385f7a2eb599e039c5cb604f`):

```text
514ac20: endbr64
514ac24: mov 0x788(%rdi),%rax
514ac2b: mov 0x30(%rax),%rax
514ac2f: movslq 0xb30(%rax),%rax
514ac36: mov %rax,(%rsi)
514ac39: mov $0x1,%eax
514ac3e: ret
514ac3f: int3 (1 byte padding; next FDE starts at 0x514ac40)
```

Rule: `out = sign_extend32([[[rdi + 0x788] + 0x30] + 0xb30])`,
return 1 on all inputs. The movslq opcode (`48 63 80` plus disp32
`0xb30`) is what makes the extension a sign extension rather than a
zero extension; a 32-bit field value of `0x80000000` therefore yields
`0xFFFFFFFF80000000`, not `0x80000000`.

Window `0x514ac40` (31 bytes, FDE `.eh_frame+0x0029a144`, range
`0x514ac40..0x514ac5f`, SHA-256
`94921d64cad302b4c5aed3707b69b392f120e5224a50f3e02182317e3b0d415a`):

```text
514ac40: endbr64
514ac44: mov 0x788(%rdi),%rax
514ac4b: mov 0x30(%rax),%rax
514ac4f: mov 0x1008(%rax),%rax
514ac56: mov %rax,(%rsi)
514ac59: mov $0x1,%eax
514ac5e: ret
514ac5f: int3 (1 byte padding; next FDE starts at 0x514ac60)
```

Rule: `out = qword at [[[rdi + 0x788] + 0x30] + 0x1008]`, return 1
on all inputs.

Callers/callees: neither window contains a call, and a scan of `.text`
for direct `e8` calls landing exactly on either window start finds 0
sites each. That census covers direct calls only; it is not a complete
xref analysis, and indirect or tail-call callers are not excluded.
Analysis was limited to these two windows plus the padding and FDE
records beside them; no broader decompilation was attempted.

## Implementation and comparison

Independent Rust path: not yet implemented/measured. No Rust
reconstruction is claimed for these windows, and no build comparison
exists. The Python model in `tools/foundation_chained_field_pair.py`
simulates only the two stated rules (including the sign-extension edge
for the `0x514ac20` window) and is checked against the packet bytes
and, in binary mode, against the digest-bound target. Boundary and
corruption controls: the test suite flips one window byte, one padding
byte, and one FDE range byte in a digest-verified binary copy and
requires the checker to fail; it also corrupts the packet digest,
window hash, field offset, and caller count and requires failure.

## Results and limitations

- Checker passes in packet mode and in binary mode against the
  digest-verified work binary; all tests pass (pure simulation plus
  binary reproduction plus corruption controls; see the test run in
  the PR description).
- No progress gate is requested: this packet binds two windows only
  and does not claim a component mapped, a catalogue denominator, or
  any gate scope.
- Unknowns, kept separate from observations: the source-level names
  and types of the container, the intermediate object, and both fields;
  what calls these windows (no direct caller found); and whether the
  two projections belong to one source struct or two views of it.
- Concrete next question: what does the following window at
  `0x514ac60` compute — it takes different inputs (r8/rcx) and is not
  part of this chain — and what calls the `0x514ac20`/`0x514ac40`
  pair, given the direct-call census is empty?
