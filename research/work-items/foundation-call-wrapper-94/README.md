# RE-001: what does the delegating call window at 0x514ad70 compute?

- Component ID: `foundation`, one small window; its source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for the window's rule; inference for the
  shared-container reading; unresolved for source names, types, the
  callee's full semantics, and callers.
- Scope included and excluded: included are exactly the one FDE window
  `0x514ad70..0x514ad8e`, its int3 padding, its FDE record, and a
  direct-caller census for it. Excluded are the preceding window at
  `0x514ad50` (two-hop direct projection, no call, bound in #1287, not
  claimed here), the following window at `0x514ad90` (pushes rbp/rbx,
  calls a different target, reads `[rbx+0x1440]` — different protocol,
  not claimed here), all #115 addresses, target execution, and Rust
  reconstruction.

## Why this packet

The window is the immediate successor of the #1287 two-hop reader but
is not a member of that family: it shares only the first load
(`base = [rdi + 0x788]`) and the store/return protocol, then
delegates instead of projecting — it passes the loaded field as the
callee's first argument to `0x4fec390`, stores the callee's result to
`[rsi]`, preserves `rbx` across the call, and returns 1. It is
therefore bound alone, as one bounded work item: each byte of its own
rule is established independently from this window's retained bytes,
and grouping it with the direct readers would misstate its protocol.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame record.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ad70 --stop-address=0x514ad90 work/hl-node-94.bin
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
python3 tools/foundation_call_wrapper.py \
    --check research/work-items/foundation-call-wrapper-94/evidence.json
python3 tools/foundation_call_wrapper.py \
    --check research/work-items/foundation-call-wrapper-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_call_wrapper -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; the checker resolves every VA through the ELF section headers
rather than assuming VA equals file offset. Boundaries are the FDE
pc range, validated below against the `.eh_frame` record.

Window `0x514ad70` (30 bytes, FDE `.eh_frame+0x0029a1f8`, range
`0x514ad70..0x514ad8e`, SHA-256
`82e67140277bdf97fef55c4d9c869cc7ee9aa59a9e3a14ce26b001452af49dc6`,
2 int3 padding bytes to the next FDE at `0x514ad90`):
`endbr64; push %rbx; mov 0x788(%rdi),%rdi; mov %rsi,%rbx;
call 0x4fec390; mov %rax,(%rbx); mov $0x1,%eax; pop %rbx; ret`.
Rule: out = callee(`[container + 0x788]`), where callee is
`0x4fec390`; return 1; `rbx` preserved. The call target is itself an
FDE window `0x4fec390..0x4fec39d` (FDE `.eh_frame+0x0028ef2c`)
that loads `[rdi+0x28]` and jumps to `0x51f0770`; nothing about the
callee beyond that re-dispatch shape is claimed here.
Direct e8 callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container, the field at
  `0x788`, and the callee are not established by these bytes.
- What the callee computes from the field (beyond loading
  `[field + 0x28]` and jumping on) is not established here.
- The `0x514ad90` window (different protocol) is a separate item
  and is deliberately not folded into this bind.
