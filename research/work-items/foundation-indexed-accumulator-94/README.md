# RE-001: what does the indexed-accumulator window at 0x514ac60 compute?

- Component ID: `foundation`, one small window; its source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for the window's rule; inference for the
  table/base/addend readings; unresolved for source names, types, what
  the index values mean, and callers.
- Scope included and excluded: included are exactly the one FDE window
  `0x514ac60..0x514ac8c`, its int3 padding, its FDE record, and a
  direct-caller census. Excluded are the preceding windows
  (`0x514ac20`, `0x514ac40`, already bound in #1284; `0x514ab90`,
  `0x514abb0`, `0x514abf0` in #1283/#1282), the following window at
  `0x514ac90` (not examined here), all #115 addresses, target
  execution, and Rust reconstruction.

## Why this packet

The window is the immediate successor of the chained-field pair bound
in #1284, but it is a different protocol, not a member of that family:
it takes its inputs in `r8`/`rcx`/`rdi` (not the `rdi`/`rsi` container
protocol of its neighbours), selects an entry index with a null-guarded
default, and accumulates into two fields of the selected entry instead
of projecting one field into an out pointer. It is bound alone because
no adjacent window shares this protocol.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame record.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ac60 --stop-address=0x514ac90 work/hl-node-94.bin
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
bytes, FDE record, padding, rule edges); with it, it additionally
verifies the target digest, the window bytes, the padding, the FDE
pc range, and the direct-caller scan against that binary. On a
checkout where the LFS artifact is materialized, run the binary form
with `--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_indexed_accumulator.py \
    --check research/work-items/foundation-indexed-accumulator-94/evidence.json
python3 tools/foundation_indexed_accumulator.py \
    --check research/work-items/foundation-indexed-accumulator-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_indexed_accumulator -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; `.text` VA `0x1343c80` maps to file offset `0x1342c80` in this
binary, and the checker resolves every VA through the ELF section
headers rather than assuming VA equals file offset. Boundaries are the
FDE pc range, validated below against the `.eh_frame` record.

Window `0x514ac60` (44 bytes, FDE `.eh_frame+0x0029a158`, range
`0x514ac60..0x514ac8c`, SHA-256
`4aec06b08170d83e53cc0c7ffd81f0f74635ccdffa3ac1f23e993186096ccae9`):

```text
514ac60: endbr64
514ac64: mov (%r8),%rdx
514ac67: mov (%rcx),%rcx
514ac6a: mov $0xd,%eax
514ac6f: test %rdx,%rdx
514ac72: je 514ac78
514ac74: movslq 0x20(%rdx),%rax
514ac78: mov (%rdi),%rdx
514ac7b: lea (%rdx,%rax,8),%rax
514ac7f: addq $0x1,0xb0(%rax)
514ac87: add %rcx,0x40(%rax)
514ac8b: ret
514ac8c: int3 (4 bytes padding; next FDE starts at 0x514ac90)
```

Rule: let `table = [r8]`, `index = 13` when `table == 0`, else
`index = sign_extend32(int32 at [table + 0x20])`; let
`entry = [rdi] + index * 8`. Then `qword at [entry + 0xb0] += 1`
and `qword at [entry + 0x40] += [rcx]`, and the window returns
`index` (eax holds `0xd` on the null path, the sign-extended field
otherwise). The `je` at `0x514ac72` (2 bytes, displacement +4)
lands exactly on the base load at `0x514ac78`, i.e. just past the
`movslq`, so the null path keeps the default. The addend is loaded
from `[rcx]` before the null test, so it is read on both paths.

Callers/callees: the window contains no call, and a scan of `.text`
for direct `e8` calls landing exactly on the window start finds 0
sites. That census covers direct calls only; it is not a complete
xref analysis, and indirect or tail-call callers are not excluded.
The objdump symbol label attached to this address
(`_ZNKSt5ctypeIcE8do_widenEc` plus an offset) is a nearest-symbol
attribution, not an established identity, and no claim is made from
it. Analysis was limited to this window plus the padding and FDE
record beside it; no broader decompilation was attempted.

## Implementation and comparison

Independent Rust path: not yet implemented/measured. No Rust
reconstruction is claimed for this window, and no build comparison
exists. The Python model in `tools/foundation_indexed_accumulator.py`
simulates only the stated rule (including the default-13 path, the
sign-extension edge, and the stride-8 entry arithmetic) and is checked
against the packet bytes and, in binary mode, against the digest-bound
target. Boundary and corruption controls: the test suite flips one
window byte and one binary byte, and corrupts the packet digest,
window hash, field offset, rule offset, and caller count, requiring
failure in each case.

## Results and limitations

- Checker passes in packet mode and in binary mode against the
  digest-verified work binary; all tests pass (pure simulation plus
  binary reproduction plus corruption controls; see the test run in
  the PR description).
- No progress gate is requested: this packet binds one window only
  and does not claim a component mapped, a catalogue denominator, or
  any gate scope.
- Unknowns, kept separate from observations: the source-level names
  and types of the table object, the base object, and the entry's
  `+0x40`/`+0xb0` fields; what index values occur in practice
  (a negative index would address below the base — the model does
  the arithmetic but makes no safety claim); what calls this window
  (no direct caller found); and whether the stride-8 entries overlap
  the `+0x40`/`+0xb0` fields of neighbouring indices by design or
  because the index range is constrained elsewhere.
- Concrete next question: what does the following window at
  `0x514ac90` compute, and what calls this accumulator, given the
  direct-call census is empty?
