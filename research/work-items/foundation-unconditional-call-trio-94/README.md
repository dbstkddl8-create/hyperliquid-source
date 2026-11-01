# RE-001: what do the node #94 windows at 0x514b070, 0x514b090 and 0x514b0b0 compute?

- Component ID: `foundation`, three adjacent FDE windows bound as
  one family item; their source-level component is not established
  by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for these windows' rules; inference for
  the argument-source readings; unresolved for source names, types,
  the callees' internals, and callers.
- Scope included and excluded: included are exactly the three FDE
  windows `0x514b070..0x514b08b`, `0x514b090..0x514b0aa` and
  `0x514b0b0..0x514b0ca`, their FDE records, a direct-caller
  census for each window, and a direct-caller census for each
  callee. Excluded are the preceding window at `0x514b040`
  (bound in #1306, a conditional call guarded on `rcx`, not this
  unconditional protocol), the following window at `0x514b0d0`
  (a field read with a `jle` guard, not a call-store window), all
  #115 addresses, target execution, and Rust reconstruction.

## Why this packet

The three windows share one skeleton and differ only in how the
single call argument is formed, which is why they are bound as one
family item rather than three lone windows:

- `0x514b070` (27 bytes): push `rbx`, `lea 0x40(%rcx),%rdi`,
  save the out pointer in `rbx`, call `0x51cc540`, store the
  callee's result to `[rsi]`, return 1 with `rbx` preserved.
- `0x514b090` (26 bytes): push `rbx`, `mov %rdx,%rdi`, save the
  out pointer in `rbx`, call `0x50aaf20`, store the callee's
  result to `[rsi]`, return 1 with `rbx` preserved.
- `0x514b0b0` (26 bytes): the same `rdx`-argument protocol with
  callee `0x50aaf30` instead of `0x50aaf20`.

So the rules are: out = callee(rcx + 0x40) for the first window,
and out = callee(rdx) for the other two, each returning 1, with
no branch, no check, and the stack balanced (push/pop only, no
`sub`/`add` on `rsp`). The two `rdx` windows are not byte
identical: their call displacements differ because their targets
sit `0x10` apart, and the tests pin each target separately.

The `.text` direct-caller census confirms each window is uncalled
directly (0 sites). The callee census is recorded, not over
claimed: `0x51cc540` is called from exactly one direct site —
this trio's first window — while `0x50aaf20` has 4 direct sites
and `0x50aaf30` has 2, so the other sites are other windows'
calls, not claimed here. The callees' internals are not decoded
or claimed; only the window-level rules are bound.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra or Java
was used; GNU `--dwarf=frames` output supplies the retained frame
records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514b070 --stop-address=0x514b0ca work/hl-node-94.bin
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

- The `rcx` / `rdx` values are read as pointer-like arguments;
  what the objects are, and what each callee computes from its
  argument, is unknown.
- No caller, owner, or source name is established for any window.
- Each callee is identified only as a direct call target; its body
  is not decoded or claimed here.
