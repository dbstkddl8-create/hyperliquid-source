# RE-001: what do node #94's bracket-search twin windows 0x514b220 and 0x514b2b0 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about two whole target function windows,
  their shared decrement callee and the one direct consumer of the
  second window; the source-level container type and the owning
  component remain inferences/unresolved.
- Scope included: the whole 138-byte FDE windows 0x514b220..0x514b2aa
  and 0x514b2b0..0x514b33a, the `_Rb_tree_decrement` PLT stub both
  call, the consumer function 0x5150e50..0x5151000 insofar as it
  sets up and branches on the twin's result, and the full direct-e8
  caller census for both windows.
- Scope excluded: the neighboring window 0x514b120 (a 3-way selector
  store that returns 0 and uses no tree walk — a different protocol,
  examined and deliberately not folded in), the neighbor 0x514b160
  (a delete thunk: mov $0x28,%esi then jmp — different protocol),
  the following window 0x514b340 (a bounded-length comparison with a
  memcmp call — different protocol, unexamined beyond its first
  lines), the decrement stub's own body, and the rest of the
  consumer function's decision logic beyond the verified branch.

## Why this packet is one complete behavior, not a lone window

Two whole functions, not fragments: each window runs a signed-key
tree walk to completion and returns one of three observable
outcomes (exact hit, predecessor bracket, successor bracket, plus
the empty-tree sentinel). The predecessor step is pinned together
with the PLT callee that implements it, and the second window's
meaning is confirmed end to end by a genuine consumer: an insert
routine that frees its fresh node and returns the existing value
address on an exact hit (second component 0) and proceeds toward
`_Rb_tree_insert_and_rebalance` on a miss (second component
nonzero). The checker verifies both window bodies, the twin
relation, the callee targets, the consumer call site and the
composed rule — not one window's constants.

## The rule, exactly as the bytes state it

The container object is passed in rdi; the sought key is the int32
in esi (moved to ebp). Node layout, shared with the map::at window
0x514b1c0: left child at +0x10, right child at +0x18, signed
32-bit key at +0x20, value slot at +0x28 (confirmed by the
consumer, which returns an existing node's +0x28 address).

- Walk start: rbx = [rdi+0x10]. If it is null, jump to the empty
  path: rbx = rdi+0x8 (the header/sentinel) and continue at the
  decrement check below.
- Walk step: edx = int32 at [rbx+0x20]; rax = [rbx+0x18] (right
  child); if the node key is greater than sought (signed, cmovg),
  rax = [rbx+0x10] (left child) and cl = 1, otherwise cl = 0. If
  rax is not null, rbx = rax and repeat.
- Leaf, key not greater (cl = 0): rsi = rbx. If the leaf key is
  greater than or equal to sought (cmovge), rsi = 0 and the pair
  is (leaf, 0) — this is the exact hit when the key equals
  sought. If the leaf key is smaller (cmovl), rbx = 0 and the
  pair is (0, leaf) — the leaf is the predecessor.
- Leaf, key greater (cl = 1): compare rbx against [rdi+0x18]. If
  equal, the pair is (0, rbx) — the node has no predecessor, so
  it is the successor (and on the empty path, rbx is the header
  itself). Otherwise call `_Rb_tree_decrement` on rbx, set rsi to
  the old rbx and rbx to the predecessor, and re-enter the tail:
  if the predecessor's key is greater than or equal to sought,
  rsi = 0 and the pair is (predecessor, 0) — the exact hit
  reached through the predecessor; if smaller, rbx = 0 and the
  pair is (0, old rbx) — the old node is the successor.
- Returns: rax = first component, rdx = second component, both
  callee-saved registers (rbx, rbp) restored, stack balanced
  (push rbp/rbx, sub rsp,8, add rsp,8 on every path).

Composed: bracket_search(container, sought) returns (exact, 0)
when sought is present; otherwise (0, neighbour), where the
neighbour is the predecessor when the walk ends going right and
the successor when it ends going left; (0, header) on an empty
tree. All comparisons are signed throughout, so INT32_MIN and
INT32_MAX behave as the cmovg/cmovge/cmovl branches state, and
the tests pin those edges.

Worked cases on keys {10, 20, 30} (root 20): sought 20 -> (20, 0)
via the predecessor step; 25 -> (0, 30); 15 -> (0, 10);
5 -> (0, 10); 35 -> (0, 30); 10 -> (10, 0); 30 -> (30, 0).

## The twin relation

The two bodies are byte-identical except for the decrement call's
rel32 displacement (body offsets 0x66-0x67): 0x514b285 calls
0x56604b0 with bytes `e8 26 52 51 00`, 0x514b315 calls the same
0x56604b0 with bytes `e8 96 51 51 00`. Both bodies are 138 bytes
with 6 int3 padding bytes to the next FDE start. Whether the two
copies serve two instantiations of one container type is
unresolved and is not claimed.

## The consumer (insert routine, 0x5150e50..0x5151000)

Verified parts only: it allocates a fresh 0x30-byte node
(`_Znwm@plt` at 0x5150f35), stores the key at node+0x20
(0x5150f51), calls the twin window with rdi = rbp (the container)
and esi = r12d (the key) at 0x5150f6e, then tests rdx. On rdx == 0
(exact hit) it frees the fresh node (`_ZdlPvm@plt` at 0x5150f83,
rdi = r14, esi = 0x30) and returns lea 0x28(%rbx) — the existing
node's value slot. On rdx != 0 (miss) it proceeds toward the
insert path through `_Rb_tree_insert_and_rebalance@plt`
(0x5150f17). This branch is what confirms the pair's meaning
beyond the walk itself. The consumer's wider decision logic (its
other registers and branches) is not decoded and not claimed.

## The container field at +0x18

The decrement check compares the current node against
[container+0x18] and skips the decrement exactly when they are
equal. That field is read here as the smallest node (leftmost):
skipping the decrement is only well-defined when the node has no
predecessor, and on an empty tree the same field equals the header
(rdi+0x8), which is the skip case the empty path takes. This
reading is an inference, stated as one: the walk, the call and
the returns do not depend on it.

## Verbatim evidence note

The disassembly excerpts in window.objdump.txt (both windows) and
caller.objdump.txt (the whole consumer function) are the
unmodified output of GNU objdump 2.42 for the stated ranges (the
commands are under Reproduce below). The instruction entries in
evidence.json copy the mnemonic, operands and raw bytes from that
output exactly — nothing paraphrased, shortened or sanitized. In
particular, the alignment instructions are recorded verbatim as
`nopl` with their full bytes, and the checker verifies every
recorded instruction byte against the digest-verified binary.
These windows have no endbr64: each begins with `push %rbp`, not
a landing pad, and no endbr64 is claimed for them. Where earlier
packets recorded `endbr64`, that is likewise the genuine
instruction present in those windows' objdump output
(`f3 0f 1e fa`), not a placeholder — but this packet stands on
its own bytes, and its checker re-derives every byte from the
binary rather than trusting the evidence file.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No cargo, rustc,
git-lfs, Ghidra or Java was used; GNU `--dwarf=frames` output
supplies the retained frame records.

The work binary used here is the materialized node #94 copy whose
SHA-256 matches provenance/artifacts.json
(`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`);
on a materialized checkout the same bytes live at
artifacts/node/94/hl-node. The excerpts were produced with:

```sh
objdump -d --start-address=0x514b220 --stop-address=0x514b33a work/hl-node-94.bin
objdump -d --start-address=0x5150e50 --stop-address=0x5151000 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_bracket_search.py --check research/work-items/foundation-bracket-search-twin-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_bracket_search -v
```

## Evidence

- Entry FDE: offset 0x0029a4a4,
  pc=000000000514b220..000000000514b2aa, 138 body bytes, SHA-256
  `0f156d1e8a027c6627b8b280ccec1a71dcb685d5f96e1eeeaf2316e88e0f713a`,
  6 int3 padding bytes to the next FDE start 0x514b2b0.
- Twin FDE: offset 0x0029a4d8,
  pc=000000000514b2b0..000000000514b33a, 138 body bytes, SHA-256
  `98deeab84ee1834962b666e8a7a66007ee21c17fadeb639e9dac97cbc8308190`,
  6 int3 padding bytes to the next FDE start 0x514b340.
- Decrement calls: 0x514b285 (`e8 26 52 51 00`) and 0x514b315
  (`e8 96 51 51 00`), both landing on 0x56604b0, the PLT stub for
  `_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base@plt`.
- Consumer call: 0x5150f6e (`e8 3d a3 ff ff`) landing on
  0x514b2b0; consumer function FDE offset 0x0029ade0,
  pc=0000000005150e50..0000000005151000.
- Direct-e8 caller census (full .text scan): 0x514b220 has none;
  0x514b2b0 has exactly one, 0x5150f6e. Reach by other means is
  not claimed for the first window.
- Overlap check before building: repo code search for `514b220`
  and `514b2b0` returns 0 hits. No open WalkCrypto PR covers
  these windows.

## Results and limitations

The checker passes in binary mode against the digest-verified
work binary; all unit tests pass, including the bracket search
end to end (empty tree, single-node hit and both misses,
three-node hit/between/below/above cases, INT32 edges), the twin
relation, the consumer call target, the caller census and
corruption controls (mutated instruction byte, body SHA, twin
call target, caller list and rule edge each fail). Repo-wide
`make catalogue-check` was not re-run: it fails on the
pre-existing LFS-pointer identity error before reaching this
change, as recorded for the preceding submissions; that failure
is not a regression from this PR.

Remaining unknowns, stated not buried: the source-level container
type and the owning component of the consumer function; whether
the twin copies serve two instantiations of one container type;
the decrement stub's own body; and the consumer's wider decision
logic. The predecessor in the Python model is computed by
in-order traversal, which equals `_Rb_tree_decrement` on a valid
binary search tree — the equivalence is an assumption, recorded
here, and the tests use only valid trees. No Rust reconstruction
is claimed; the Python model is a behavioral model of this
search function only.

Next question: which component owns the consumer's container
(rbp), and does the first twin window (0x514b220) have a consumer
reachable by a non-direct call that the e8 census cannot see?
