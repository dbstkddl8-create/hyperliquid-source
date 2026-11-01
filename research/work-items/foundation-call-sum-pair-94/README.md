# RE-001: what does the call-sum pair at 0x514ae60 and 0x514aea0 compute?

- Component ID: `foundation`, two adjacent windows sharing one
  protocol; their source-level component is not established by this
  packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for the two windows' rules; inference
  for the container reading; unresolved for source names, types,
  the callees' internals, and callers.
- Scope included and excluded: included are exactly the two FDE
  windows `0x514ae60..0x514aea0` and `0x514aea0..0x514aee0`,
  their FDE records, and a direct-caller census for each.
  Excluded are the preceding trio at `0x514add0..0x514ae58`
  (call-through with extension, bound in #1294, not claimed here),
  the following window at `0x514aee0` (a different protocol:
  `0x8f8` load, direct call, no addend field, not claimed here),
  all #115 addresses, target execution, and Rust reconstruction.

## Why this packet

The two windows are one protocol family, bound together rather
than as two single-window items: each pushes `rbp` and `rbx`,
saves the out pointer in `rbx`, loads `[container + 0x788]`,
loads `[[container + 0x788] + 0x8e8]`, adds `0x8f0` to the first
pointer, loads the qword at
`[[[container + 0x788] + 0x8e8] + 0xcd0]` into `rbp`, calls a
small callee with the adjusted pointer, adds `rbp` to the
callee's result, stores the sum to `[rsi]`, and returns 1 with
`rbp` and `rbx` preserved and the stack balanced. They differ
only in the callee: `0x5172db0` for the first window,
`0x5172df0` for the second. The windows are byte-identical —
both call sites sit `0x40` apart and both targets sit `0x40`
apart, so the same rel32 displacement lands on a different
callee from each window. The third field
(`[[[container + 0x788] + 0x8e8] + 0xcd0]`) is the same field
the preceding three-hop trio at `0x514acc0` projects directly,
bound in #1286; here it is an addend to a callee result, not
the whole output, so this pair is a different protocol and is
not folded into that trio. Neither callee's internals are
claimed here; only the window-level rule (call it, add the
field, store the sum) is bound.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ae60 --stop-address=0x514aee0 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so
it cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was
verified to equal the provenance digest for node #94
(`3b7179cd…c0459f`, 91,774,280 bytes) before any byte was read
from it. The checker therefore takes an optional `--binary`
argument: without it, it verifies the packet files against each
other (retained disassembly bytes, FDE records, rule edges);
with it, it additionally verifies the target digest, the
window bytes, the FDE pc ranges, and the direct-caller scans
against that binary. On a checkout where the LFS artifact is
materialized, run the binary form with
`--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_call_sum_pair.py \
    --check research/work-items/foundation-call-sum-pair-94/evidence.json
python3 tools/foundation_call_sum_pair.py \
    --check research/work-items/foundation-call-sum-pair-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_call_sum_pair -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; the checker resolves every VA through the ELF section headers
rather than assuming VA equals file offset. Boundaries are the FDE
pc ranges, validated below against the `.eh_frame` records.

Window `0x514ae60` (64 bytes, FDE `.eh_frame+0x0029a290`, range
`0x514ae60..0x514aea0`, SHA-256
`9c019ce20399e25c10e3374b25f397718b02a0b8390eafb9c9597b09fd757a94`,
0 int3 padding bytes — the next FDE starts immediately at
`0x514aea0`):
`endbr64; push %rbp; push %rbx; mov %rsi,%rbx;
sub $0x8,%rsp; mov 0x788(%rdi),%rdi; mov 0x8e8(%rdi),%rax;
add $0x8f0,%rdi; mov 0xcd0(%rax),%rbp; call 0x5172db0;
add %rbp,%rax; mov %rax,(%rbx); add $0x8,%rsp;
mov $0x1,%eax; pop %rbx; pop %rbp; ret`.
Rule: out = callee result + qword at
`[[[container + 0x788] + 0x8e8] + 0xcd0]` where the callee is
called with `[container + 0x788] + 0x8f0`; return 1; `rbp` and
`rbx` preserved. Direct e8 callers in `.text`: 0.

Window `0x514aea0` (64 bytes, FDE `.eh_frame+0x0029a2b8`, range
`0x514aea0..0x514aee0`, SHA-256
`9c019ce20399e25c10e3374b25f397718b02a0b8390eafb9c9597b09fd757a94`,
0 int3 padding bytes — the next FDE starts immediately at
`0x514aee0`):
identical bytes, call `0x5172df0`.
Rule: same sum rule with the second callee; return 1; `rbp` and
`rbx` preserved. Direct e8 callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container and its fields at
  `0x788`, `0x8e8`, `0x8f0` and `0xcd0` are not established by
  these bytes.
- What the callees at `0x5172db0` and `0x5172df0` compute
  internally is not established here — only the window-level
  rule is bound.
- The `0x514aee0` window (different protocol) is a separate item
  and is deliberately not folded into this bind.
