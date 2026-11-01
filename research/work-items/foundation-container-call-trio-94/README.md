# RE-001: what do the node #94 windows at 0x514afe0, 0x514b000 and 0x514b020 compute?

- Component ID: `foundation`, three adjacent FDE windows bound as one
  family item; their source-level component is not established by this
  packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for these windows' rules; inference for
  the container reading; unresolved for source names, types, the
  callees' internals, and callers.
- Scope included and excluded: included are exactly the three FDE
  windows `0x514afe0..0x514affe`, `0x514b000..0x514b01e` and
  `0x514b020..0x514b03e`, their FDE records, a direct-caller census
  for each window, and a direct-caller census for the three callees.
  Excluded are the preceding composite window at `0x514af40` (bound
  in #1302, a different protocol), the following window at
  `0x514b040` (conditional `rcx` call, a different protocol, not
  claimed here), all #115 addresses, target execution, and Rust
  reconstruction.

## Why this packet

The three windows are grouped because they share one byte-level
protocol and differ only in the callee: each pushes only `rbx`,
replaces `rdi` with `[container + 0x788]` (the container root itself
becomes the call argument — unlike #1297/#1302, no second field is
loaded), saves the out pointer in `rbx`, calls its callee, stores the
callee's result to `[rsi]`, and returns 1 with `rbx` preserved and
the stack balanced (push/pop only, no `sub`/`add` on `rsp`). The
second and third windows are byte-identical: both call sites and
both targets sit `0x20` apart, so the rel32 displacement is the same
and both windows share SHA-256 `15b00ba0…`. Binding all three in one
item, rather than as three single-window items, follows the grouping
direction in the intake reviews on the earlier foundation binds.

The `.text` direct-caller census confirms the family shape but does
not overclaim exclusivity: `0x4fec370` has exactly 1 direct e8 call
site (window A), `0x4fec380` exactly 1 (window B), while `0x4fec3a0`
has 2 — window C and one further site at `0x50c97c3`, which is not
claimed here. Each window itself has 0 direct e8 callers. The
callees' internals are not claimed here; only the window-level rules
are bound.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514afe0 --stop-address=0x514affe work/hl-node-94.bin
objdump -d --start-address=0x514b000 --stop-address=0x514b01e work/hl-node-94.bin
objdump -d --start-address=0x514b020 --stop-address=0x514b03e work/hl-node-94.bin
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

- The `0x788` load is read as a container root whose value is passed
  to the callee; what that object is, and what each callee computes
  from it, is unknown.
- No caller, owner, or source name is established for any window.
- The extra `0x4fec3a0` caller at `0x50c97c3` is recorded, not
  interpreted.
