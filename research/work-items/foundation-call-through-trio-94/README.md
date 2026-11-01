# RE-001: what does the call-through trio at 0x514add0, 0x514ae00 and 0x514ae30 compute?

- Component ID: `foundation`, three adjacent windows sharing one
  protocol; their source-level component is not established by this
  packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for the three windows' rules; inference
  for the container reading; unresolved for source names, types, the
  third callee's internals, and callers.
- Scope included and excluded: included are exactly the three FDE
  windows `0x514add0..0x514adf7`, `0x514ae00..0x514ae27` and
  `0x514ae30..0x514ae58`, their int3 padding, their FDE records, and
  a direct-caller census for each. Excluded are the preceding window
  at `0x514ad90` (call + post-call sign-extended field read, bound in
  #1292, not claimed here), the following window at `0x514ae60`
  (a different, 64-byte window, not claimed here), all #115
  addresses, target execution, and Rust reconstruction.

## Why this packet

The three windows are one protocol family, bound together rather
than as three single-window items: each pushes `rbx`, loads
`[container + 0x788]`, saves the out pointer in `rbx`, adds `0x8f0`
to the loaded pointer, calls a small callee with that pointer, and
stores an extended form of the callee's result to `[rsi]`,
returning 1 with `rbx` preserved. They differ only in the callee
and in the extension: the first two sign-extend with `cltq`, the
third zero-extends the low byte with `movzbl`. The first two
callees are themselves tiny FDE windows whose loads are observed
here as supporting facts — `0x51723e0` returns
`int32 at [[arg + 0x8] + 0x10]`, `0x51723f0` returns
`int32 at [[arg + 0x8] + 0x28]` — so the first two windows'
composed rules are fully pinned. The third callee `0x5172c70`
is a 26-byte FDE window whose internals are not claimed here; only
the window-level rule (call it, zero-extend its low byte, store
it) is bound.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514add0 --stop-address=0x514ae60 work/hl-node-94.bin
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
other (retained disassembly bytes, FDE records, padding, rule
edges); with it, it additionally verifies the target digest, the
window bytes, the padding, the FDE pc ranges, and the
direct-caller scans against that binary. On a checkout where the
LFS artifact is materialized, run the binary form with
`--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_call_through_trio.py \
    --check research/work-items/foundation-call-through-trio-94/evidence.json
python3 tools/foundation_call_through_trio.py \
    --check research/work-items/foundation-call-through-trio-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_call_through_trio -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; the checker resolves every VA through the ELF section headers
rather than assuming VA equals file offset. Boundaries are the FDE
pc ranges, validated below against the `.eh_frame` records.

Window `0x514add0` (39 bytes, FDE `.eh_frame+0x0029a23c`, range
`0x514add0..0x514adf7`, SHA-256
`608030aa93533d0751ce1f1c24c6f7b9d0cdd5404a80c469a1a11cbfaeeb4805`,
9 int3 padding bytes to the next FDE at `0x514ae00`):
`endbr64; push %rbx; mov 0x788(%rdi),%rdi; mov %rsi,%rbx;
add $0x8f0,%rdi; call 0x51723e0; cltq; mov %rax,(%rbx);
mov $0x1,%eax; pop %rbx; ret`.
Rule: out = sign_extend32(callee result) where the callee is
called with `[container + 0x788] + 0x8f0`; return 1; `rbx`
preserved. Direct e8 callers in `.text`: 0.

Window `0x514ae00` (39 bytes, FDE `.eh_frame+0x0029a258`, range
`0x514ae00..0x514ae27`, SHA-256
`7664a795fda6f8bf208abb729f0b14f26ba6f2718127e4eed74ffd39a3f3877b`,
9 int3 padding bytes to the next FDE at `0x514ae30`):
identical protocol, call `0x51723f0`, `cltq`.
Rule: out = sign_extend32(callee result) with the same argument
construction; return 1; `rbx` preserved.
Direct e8 callers in `.text`: 0.

Window `0x514ae30` (40 bytes, FDE `.eh_frame+0x0029a274`, range
`0x514ae30..0x514ae58`, SHA-256
`edccc20b7e55d78684df3abda3b3aaa87183838e8db10dfca5efd74791af3f5f`,
8 int3 padding bytes to the next FDE at `0x514ae60`):
identical protocol, call `0x5172c70`, `movzbl %al,%eax`.
Rule: out = zero_extend8(low byte of callee result) with the same
argument construction; return 1; `rbx` preserved.
Direct e8 callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container and its fields at
  `0x788` and `0x8f0` are not established by these bytes.
- What the third callee at `0x5172c70` computes internally is not
  established here — only the window-level rule is bound.
- The `0x514ae60` window (different protocol) is a separate item
  and is deliberately not folded into this bind.
