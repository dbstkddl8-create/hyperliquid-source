# RE-001: what does the direct-call window at 0x514aee0 compute?

- Component ID: `foundation`, one FDE window; its source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for this window's rule; inference for
  the container reading; unresolved for source names, types, the
  callee's internals, and callers.
- Scope included and excluded: included are exactly the one FDE
  window `0x514aee0..0x514af05`, its FDE record, and a
  direct-caller census for it. Excluded are the preceding
  call-sum pair at `0x514ae60..0x514aee0` (bound in #1296, a
  different protocol: it adds a `0xcd0` field to a callee result
  instead of returning the callee result directly), the following
  window at `0x514af10` (not claimed here), all #115 addresses,
  target execution, and Rust reconstruction.

## Why this packet

The window pushes only `rbx`, loads `[container + 0x788]`,
saves the out pointer in `rbx`, loads
`[[container + 0x788] + 0x8f8]` into `rdi`, calls `0x5172a30`
with that field value, stores the callee's result to `[rsi]`,
and returns 1 with `rbx` preserved and the stack balanced
(push/pop only, no `sub`/`add` on `rsp`). It is deliberately
not folded into #1296's pair: the pair's `0x8f0` is an addend
applied to the first pointer and its output adds a third field
to the callee result, while here `0x8f8` is the callee's whole
argument and the callee result is the whole output. The
callee's internals are not claimed here; only the window-level
rule (call it with the field, store its result) is bound.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
record.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514aee0 --stop-address=0x514af05 work/hl-node-94.bin
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
window bytes, the FDE pc range, and the direct-caller scan
against that binary. On a checkout where the LFS artifact is
materialized, run the binary form with
`--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_direct_call.py \
    --check research/work-items/foundation-direct-call-94/evidence.json
python3 tools/foundation_direct_call.py \
    --check research/work-items/foundation-direct-call-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_direct_call -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; the checker resolves every VA through the ELF section headers
rather than assuming VA equals file offset. Boundaries are the FDE
pc range, validated below against the `.eh_frame` record.

Window `0x514aee0` (37 bytes, FDE `.eh_frame+0x0029a2e0`, range
`0x514aee0..0x514af05`, SHA-256
`5fa03f4591f5387de415f61968fd06fd319396f3866b59739c4c9885ca8f9106`,
11 int3 padding bytes — the next FDE starts at `0x514af10`):
`endbr64; push %rbx; mov 0x788(%rdi),%rax; mov %rsi,%rbx;
mov 0x8f8(%rax),%rdi; call 0x5172a30; mov %rax,(%rbx);
mov $0x1,%eax; pop %rbx; ret`.
Rule: out = callee([[container + 0x788] + 0x8f8]) where the
callee is `0x5172a30`; return 1; `rbx` preserved. Direct e8
callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container and its fields at
  `0x788` and `0x8f8` are not established by these bytes.
- What the callee at `0x5172a30` computes internally is not
  established here — only the window-level rule is bound.
- The following window at `0x514af10` is a separate item and is
  deliberately not folded into this bind.
