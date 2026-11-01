# RE-001: what do the node #94 windows at 0x514af10 and 0x514af40 compute?

- Component ID: `foundation`, two adjacent FDE windows bound as one
  family item; their source-level component is not established by this
  packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for these windows' rules; inference for
  the container reading; unresolved for source names, types, the
  callees' internals, and callers.
- Scope included and excluded: included are exactly the two FDE
  windows `0x514af10..0x514af35` and `0x514af40..0x514afd8`, their FDE
  records, a direct-caller census for each window, and a direct-caller
  census for the three callees used by the composite. Excluded are
  the preceding direct-call window at `0x514aee0` (bound in #1297, a
  different callee: `0x5172a30` instead of `0x5172ad0`), the following
  window at `0x514afe0` (not claimed here), all #115 addresses,
  target execution, and Rust reconstruction.

## Why this packet

The two windows are grouped because the second is the composite
consumer of the first window's callee, and the .text direct-caller
census confirms the link: `0x5172ad0` has exactly 2 direct e8 call
sites in `.text` — this accessor's call and the composite's third
call. The accessor alone would repeat #1297's shape with only the
callee changed, so it is bound together with the composite window
that actually uses that callee's result, rather than as another
single-window item. Likewise `0x5172a30` has exactly 2 direct call
sites (#1297's window and this composite), and `0x51ca740` has
exactly 1 (this composite).

The accessor pushes only `rbx`, loads `[container + 0x788]`, saves
the out pointer in `rbx`, loads `[[container + 0x788] + 0x8f8]`
into `rdi`, calls `0x5172ad0` with that field value, stores the
callee's result to `[rsi]`, and returns 1 with `rbx` preserved and
the stack balanced (push/pop only, no `sub`/`add` on `rsp`).

The composite pushes `r13`/`r12`/`rbp`/`rbx`, subtracts 8 from `rsp`,
and reads the same container root `[container + 0x788]`, then
`[root + 0x8e8]`, `[root + 0x30]`, `[root + 0x8e8] + 0xa70`, and
`[root + 0x8f8]`. It calls `0x5172a30` with the `0x8f8` field, adds
that result to the `0xa70` field, calls `0x51ca740` with
`[root + 0x30] + 0x40`, and adds that result too, giving
S = field_a70 + call_a30 + call_mid. It then reloads the root,
reads `[root + 0x8e8] + 0xa78` and the `0x8f8` field again, calls
`0x5172ad0` with the field, and forms T = 2 * (call_ad0 +
field_a78) via `add %rbp,%rax; add %rax,%rax`. The tail computes
`rdx = S - T`, compares `rax` (T) against `rbx` (S) with
`cmp %rbx,%rax`, zeroes `eax`, and applies `cmovb %rdx,%rax`, so
the stored result is S - T when T < S in unsigned comparison and
0 otherwise — an unsigned saturating excess of S over the doubled
term. The window restores `rsp`, returns 1, and pops `rbx`/`rbp`/
`r12`/`r13` in order. The callees' internals are not claimed here;
only the window-level rules are bound.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514af10 --stop-address=0x514af35 work/hl-node-94.bin
objdump -d --start-address=0x514af40 --stop-address=0x514afd8 work/hl-node-94.bin
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
python3 tools/foundation_ad0_accessor_composite.py \
    --check research/work-items/foundation-ad0-accessor-composite-94/evidence.json
python3 tools/foundation_ad0_accessor_composite.py \
    --check research/work-items/foundation-ad0-accessor-composite-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_ad0_accessor_composite -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; the checker resolves every VA through the ELF section headers
rather than assuming VA equals file offset. Boundaries are the FDE
pc ranges, validated below against the `.eh_frame` records.

Window `0x514af10` (37 bytes, FDE `.eh_frame+0x0029a2fc`, range
`0x514af10..0x514af35`, SHA-256
`699858207c5735b2502ebd6f9754b4dc862468bb662f63d13d3d0e94c6e096ee`,
11 int3 padding bytes — the next FDE starts at `0x514af40`):
`endbr64; push %rbx; mov 0x788(%rdi),%rax; mov %rsi,%rbx;
mov 0x8f8(%rax),%rdi; call 0x5172ad0; mov %rax,(%rbx);
mov $0x1,%eax; pop %rbx; ret`.
Rule: out = callee([[container + 0x788] + 0x8f8]) where the
callee is `0x5172ad0`; return 1; `rbx` preserved. Direct e8
callers in `.text`: 0.

Window `0x514af40` (152 bytes, FDE `.eh_frame+0x0029a318`, range
`0x514af40..0x514afd8`, SHA-256
`de795c66ac9013ae45e9a916da872a901f1f7c86afddb4f0277a2e3b061d8abe`,
8 int3 padding bytes — the next FDE starts at `0x514afe0`):
pushes `r13`/`r12`/`rbp`/`rbx`, `sub $0x8,%rsp`, loads the
`0x788`/`0x8e8`/`0x30`/`0xa70`/`0x8f8` chain, calls `0x5172a30`
and `0x51ca740` to form S, reloads the root, loads `0xa78` and
`0x8f8`, calls `0x5172ad0` to form T = 2 * (call_ad0 + field_a78),
then `cmovb` stores S - T if T < S (unsigned) else 0 to `[rsi]`
and returns 1. Direct e8 callers in `.text`: 0. Callee census in
`.text`: `0x5172ad0` 2 sites (this accessor, this composite),
`0x5172a30` 2 sites (#1297's window, this composite),
`0x51ca740` 1 site (this composite).

## Unknowns

- Source-level names and types for the container and its fields at
  `0x788`, `0x8e8`, `0x30`, `0xa70`, `0xa78`, and `0x8f8` are not
  established by these bytes.
- What the callees at `0x5172ad0`, `0x5172a30`, and `0x51ca740`
  compute internally is not established here — only the
  window-level rules are bound.
- The following window at `0x514afe0` is a separate item and is
  deliberately not folded into this bind.
