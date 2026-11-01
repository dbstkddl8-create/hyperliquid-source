# RE-001: what does node #94's keyed lookup window 0x514b1c0 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about one target function window, the
  map object it searches, its throw arm and its 13 direct callers;
  the source-level container type and the meaning of the stored
  values remain inferences/unresolved.
- Scope included: the whole 96-byte FDE window 0x514b1c0..0x514b220,
  the map object at 0x578bf20 it reads, the header-node sentinel at
  0x578bf28, the `map::at` throw string at 0x1efeee, the PLT throw
  call at 0x514b21b, the FDE record, and the full direct-e8 caller
  census for the window.
- Scope excluded: the neighboring window 0x514b120 (a 3-way selector
  store that returns 0 and uses no tree walk — a different protocol,
  examined and deliberately not folded in), the neighbor 0x514b160
  (a delete thunk: mov $0x28,%esi then jmp — different protocol),
  the following window 0x514b220 (a different function, unexamined),
  what the mapped values at node+0x28 contain, and what the 13
  callers do with the returned pointer beyond calling with an int32
  key in edi.

## Why this packet is one complete behavior, not a lone window

The window is a whole function with both of its observable outcomes
pinned: on an exact key hit it returns the mapped-value address, and
on every miss it throws `out_of_range("map::at")` through a named PLT
stub. The search itself is pinned end to end — root load, the two
child links, the signed key comparison, the candidate refinement
through the left subtree, and both throw checks — and the window is
not speculative: 13 genuine direct call sites in the same binary
call it with int32 keys in edi (spot-checked at 0x514d7cb,
0x514d7dd, 0x514db62 and 0x514db75, all genuine call instructions;
the caller at 0x514d7d0 sets edi to 0x14 before the 0x514d7dd call,
and the caller at 0x514db67 sets edi to 0x1 before the 0x514db75
call). The
checker verifies the window bytes, the table lea, the throw string
and call, the caller census and the composed rule — not one
window's constants.

## The rule, exactly as the bytes state it

The map object base is r8 = 0x578bf20 (lea at 0x514b1c0:
0x514b1c7 + 0x640d59). The root is [r8+0x10]; the header node
itself sits at r8+0x8, and that address doubles as the not-found
sentinel.

- Empty tree: if the root is null, jump straight to the throw path
  at 0x514b213.
- Walk: rax starts as the sentinel (lea 0x8(%r8)). From a node,
  rcx = [node+0x10] (left child), rsi = [node+0x18] (right child),
  and the signed 32-bit key at [node+0x20] is compared against edi
  (cmp %edi,0x20(%rdx); jl is taken when key < sought, in AT&T
  operand order).
- If key < sought: continue with the right child (+0x18); if that
  link is null, stop.
- Otherwise (key >= sought): record the node in rax as the
  candidate and continue with the left child (+0x10); if that link
  is null, stop.
- Finish: if rax still equals the sentinel (r8+0x8), throw. If the
  candidate's key is greater than sought (cmp %edi,0x20(%rax); jg),
  throw. Otherwise return rax+0x28 — the address of the mapped-value
  slot of the node whose key equals sought exactly.

Throw path (0x514b213): push %rax (the failing candidate or
sentinel is preserved on the stack, it is not an argument); lea
-0x4f5b32d(%rip) into rdi = 0x1efeee, the .rodata string `map::at`;
call 0x5660710, the PLT stub for
`_ZSt20__throw_out_of_rangePKc@plt`. The call never returns, so
the FDE body ends exactly at the next FDE start 0x514b220 with
zero padding bytes.

Composed: map_at(sought) returns candidate+0x28 iff some visited
node's key equals sought exactly after left-subtree refinement;
otherwise it throws out_of_range("map::at"). The comparison is
signed throughout: INT32_MIN and negative keys behave as the jl/jg
branches state, and the tests pin those edges.

## Verbatim evidence note

The disassembly excerpt in window.objdump.txt is the unmodified
output of GNU objdump 2.42 for the FDE range (the command is under
Reproduce below). The instruction entries in evidence.json copy
the mnemonic, operands and raw bytes from that output exactly —
nothing paraphrased, shortened or sanitized. In particular, the
alignment instruction at 0x514b1d6 is recorded as `cs nopw` with
its full 10 bytes `66 2e 0f 1f 84 00 00 00 00 00`, exactly as
objdump prints it; the checker verifies those bytes against the
digest-verified binary, and the excerpt check requires every
recorded mnemonic to appear in the excerpt. This window has no
endbr64: its first instruction is the table lea, not a landing
pad, and no endbr64 is claimed for it. Where earlier packets
recorded `endbr64`, that is likewise the genuine instruction
present in those windows' objdump output (`f3 0f 1e fa`), not a
placeholder — but this packet stands on its own bytes, and its
checker re-derives every byte from the binary rather than trusting
the evidence file.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No cargo, rustc,
git-lfs, Ghidra or Java was used; GNU `--dwarf=frames` output
supplies the retained frame record.

The work binary used here is the materialized node #94 copy whose
SHA-256 matches provenance/artifacts.json
(`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`);
on a materialized checkout the same bytes live at
artifacts/node/94/hl-node. The excerpt was produced with:

```sh
objdump -d --start-address=0x514b1c0 --stop-address=0x514b220 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_map_at.py --check research/work-items/foundation-map-at-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_map_at -v
```

## Evidence

- Entry FDE: offset 0x0029a48c,
  pc=000000000514b1c0..000000000514b220, 96 body bytes, SHA-256
  `0d26da1e47967f1e86995cdc42ec4da44930c557819951068e954e7a41351a0a`,
  0 padding bytes (the noreturn throw call ends exactly at the
  next FDE start 0x514b220).
- Table lea: site 0x514b1c0, bytes `4c 8d 05 59 0d 64 00`;
  0x514b1c7 + 0x640d59 = 0x578bf20; sentinel = table+0x8 =
  0x578bf28.
- Throw lea: site 0x514b214, bytes `48 8d 3d d3 4c 0a fb`;
  0x514b21b - 0x4f5b32d = 0x1efeee, whose .rodata bytes are
  `map::at` followed by a NUL.
- Throw call: site 0x514b21b, bytes `e8 f0 54 51 00`;
  0x514b220 + 0x5154f0 = 0x5660710, the PLT stub for
  `_ZSt20__throw_out_of_rangePKc@plt`.
- Entry direct e8 callers (full .text scan): 0x514d7cb,
  0x514d7dd, 0x514d8ce, 0x514d94e, 0x514d961, 0x514d974, 0x514d987,
  0x514d99a, 0x514d9ad, 0x514d9c0, 0x514daa1, 0x514db62, 0x514db75 —
  13 sites, each a genuine call instruction on spot check.
- Overlap check before building: repo code search for `514b1c0`
  returns 0 hits. No open WalkCrypto PR covers this window.

## Results and limitations

The checker passes in binary mode against the digest-verified
work binary; all unit tests pass, including the search end to end
(empty tree, single-node hit and both misses, left-subtree
refinement hit and miss, right-subtree hit, signed and INT32
edges), the throw-path arithmetic, the caller census and
corruption controls (mutated instruction byte, body SHA, table
displacement, throw target, throw message, caller list and rule
edge each fail). Repo-wide `make catalogue-check` was not re-run:
it fails on the pre-existing LFS-pointer identity error before
reaching this change, as recorded for the preceding submissions;
that failure is not a regression from this PR.

Remaining unknowns, stated not buried: the source-level container
type (the node/header layout is consistent with a libstdc++
ordered map, but no symbol names this window), what the mapped
values at node+0x28 contain, what the 13 callers do with the
returned pointer, and whether other windows search the same map
object at 0x578bf20. No Rust reconstruction is claimed; the
Python model is a behavioral model of this lookup function only.

Next question: do the 13 callers share one key domain (spot-checked
edi values are small ids — 0x1, 0x14), and is 0x578bf20
the same map object other lookup windows search?
