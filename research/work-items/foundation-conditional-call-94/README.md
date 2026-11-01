# RE-001: what does the node #94 window at 0x514b040 compute?

- Component ID: `foundation`, one FDE window bound as a single
  item; its source-level component is not established by this
  packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for this window's rule; inference for
  the null-guard reading; unresolved for source names, types, the
  callee's internals, and callers.
- Scope included and excluded: included are exactly the one FDE
  window `0x514b040..0x514b061`, its FDE record, a direct-caller
  census for the window, and a direct-caller census for its callee.
  Excluded are the preceding trio windows at `0x514afe0` /
  `0x514b000` / `0x514b020` (bound in #1305, an unconditional
  container-root protocol, not this conditional protocol), the
  following windows at `0x514b070` (unconditional call with
  `lea 0x40(%rcx)` argument) and `0x514b090` / `0x514b0b0`
  (unconditional calls with `rdx` argument) — all different
  protocols, not claimed here — all #115 addresses, target
  execution, and Rust reconstruction.

## Why this packet

The window is the null-guarded member of the run: it pushes only
`rbx`, zeroes `eax` up front, saves the out pointer in `rbx`,
tests `rcx` against itself, and jumps exactly past the call when
`rcx` is zero (`je` at `0x514b04d` lands on the store at
`0x514b057`), so the zero path stores the pre-zeroed `eax` — 0 —
without calling anything. On the non-zero path it moves `rcx`
itself into `rdi` (no field is loaded, no offset is added) and
calls `0x51ca580`, then stores the callee's result to `[rsi]`
and returns 1 with `rbx` preserved and the stack balanced
(push/pop only, no `sub`/`add` on `rsp`). The zeroing-before-test
ordering is what makes the guard total: every path stores exactly
one qword and returns 1, and the null path cannot leak a stale
`rax` value.

The `.text` direct-caller census confirms the window is
uncalled directly (0 sites) and that its callee is called from
exactly one direct site — this window itself. The callee's
internals are not claimed here; only the window-level rule is
bound. This window was deliberately not folded into #1305's trio
(the trio passes a loaded container root unconditionally) or
into the following windows (they call unconditionally with
derived arguments); the conditional guard is a different
protocol, and binding it alone keeps the claim exactly as wide
as the bytes support.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
record.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514b040 --stop-address=0x514b061 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so
it cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was
verified to equal the provenance digest for node #94
(`3b7179cd…c0459f`, 91,774,280 bytes) before any byte was read
from it, and the checker accepts `--binary` so a materialized
checkout can cross-check against `artifacts/`.

## Assumptions and unknowns

- The `rcx` value is read as a nullable pointer-like argument
  whose null case yields 0; what the object is, and what the
  callee computes from a non-null argument, is unknown.
- No caller, owner, or source name is established for this window.
- The callee `0x51ca580` is identified only as a direct call
  target; its body is not decoded or claimed here.
