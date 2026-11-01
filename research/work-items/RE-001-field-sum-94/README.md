# RE-001: field sum over node #94 entries (0x514bcd0)

Task ID: RE-001. Bounded question: what does the 104-byte function at
0x514bcd0 in node #94 compute over the range it walks, and what does
each entry contribute — and how does it differ from its immediate
predecessor, the range-sum function at 0x514bc60? Answer: it sums, over
a range of 16-byte entries, the qword at [slot + 0x50] per entry, where
slot is the entry's first qword; it calls the shared callee 0x5032f40
once per entry but discards the callee's return, stores the 64-bit
wrapping sum to its second argument, and always returns 1.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514bcd0..0x514bd38, 104 bytes, FDE at .eh_frame+0x0029a6dc
  (length 0x34), 8 int3 padding bytes to the next FDE at 0x514bd40.
- No stack canary in this function; four callee-saved registers are
  pushed and popped in balance (rbx, rbp, r12, r13).

## Observations (read from the bytes)

- Arguments: rdi = input object, rsi = out pointer (saved in r13).
- Container chain: rax = [rdi+0x788]; rax = [rax+0x30]; the range
  lives in that sub-object at +0xb18 (begin, into rbx) and +0xb20
  (end, into r12). No source-level type name is claimed for any link
  of this chain. This chain is identical to the range-sum function
  0x514bc60's chain (same offsets, same stride).
- Loop: while rbx != r12 (checked first by the je at 0x514bcff to
  the store, so an empty range stores 0): rax = [rbx] (the entry's
  first qword, the slot); rbx += 0x10 (entry stride, advanced before
  the call); rdi = [rax] (a second load from the address the slot
  holds); call 0x5032f40; rax = [rbx - 0x10] (the slot again, the
  reload at 0x514bd17 overwrites the callee's return without reading
  it); rbp += [rax + 0x50]; loop back while rbx != r12 (jne at
  0x514bd22 to 0x514bd08).
- Callee 0x5032f40 (own FDE at .eh_frame+0x00291728, length 0x10, 13
  bytes, no int3 padding — the bytes after it belong to another
  function's tail): rax = [rdi+0x10]; rax += 0x3e (62); ret. The
  callee is shared with the range-sum function and eight other sites;
  this packet claims the field-sum loop, not exclusive ownership of
  the callee.
- Composed rule: out = sum over entries of [slot + 0x50], where slot
  is the entry's first qword. The sum is a plain 64-bit wrapping add
  (add 0x50(%rax),%rbp); there is no saturation or overflow check.
  The entry's second qword (+0x8) is never read, and the callee's
  return value is never read either.
- The function's epilogue stores rbp to [r13], sets eax = 1, pops
  rbx/rbp/r12/r13 in balance, and returns. The return value is 1 on
  every path, including the empty range.
- Direct-caller census (full .text disassembly scan for e8 rel32
  calls and e9 rel32 jumps): the entry has NO direct callers and NO
  tail jumps. It is bound here as a complete behavior — a whole
  function plus its only callee and its container chain — not as a
  lone window fragment, and no caller is invented for it.
- Callee census (full .text direct-e8 scan): exactly 10 sites —
  0x5031064, 0x514bca2 (the range-sum entry), 0x514bd12 (this entry),
  0x515009a, 0x5156d46, 0x51d04e2, 0x51df04b, 0x51ee7f0, 0x51ee85b,
  0x51f0977. The other nine sites are census only.

## Inferences (labelled, not observations)

- The +0x788/+0x30/+0xb18/+0xb20 chain is read as one container
  object holding a begin/end range; the intermediate objects' types
  are not claimed.
- The double load ([cursor], then [that value]) is read as entries
  holding the address of a slot whose content is the callee argument;
  the model takes the post-deref callee arguments and the slot's
  +0x50 field as input, and the two-load structure itself is recorded
  in records.json and checked against the raw excerpts.
- Whether the per-entry callee call is load-bearing (a side effect
  the sum depends on) or dead code kept by the compiler is NOT
  claimed: the bytes call it once per entry and discard its return,
  and the model does exactly that (one counted call per entry, return
  discarded).

## Unknowns (not claimed)

- How the entry is reached (no direct caller exists): virtual or
  indirect dispatch is possible but not demonstrated, so no dispatch
  mechanism is claimed.
- The source-level type of the range elements, the container, the
  slot, and the callee's +0x10 field is not claimed; the function is
  described by its observed layout and sum behaviour only.
- The other nine callee call sites' enclosing functions are not
  modelled; only their addresses are recorded.

## Overlap notes (checked before building)

- No work item, tool, test, or doc in the tree claims 0x514bcd0, and
  no open WalkCrypto PR covers this function. The only in-tree
  mentions of 0x5032f40 are call-site lines inside other packets'
  disassembly excerpts, not claims on this item.
- Neighbours are distinct and not re-claimed: 0x514bc60 (range sum,
  open PR #1346, preceding function — same chain and callee, but it
  sums the callee return while this entry sums the +0x50 field and
  discards the return), 0x514bd40 (following FDE, a linked-list
  teardown walk ending in _ZdlPvm calls, different protocol).

## Evidence format

- records.json holds semantic records only (carve ranges with SHA-256,
  branch site-to-target pairs, call sites, container-chain offsets,
  caller/callee censuses, the composed rule). It contains no
  per-instruction list.
- Instruction-level detail lives only in the raw objdump excerpts,
  kept whole-function: window.objdump.txt (0x514bcd0..0x514bd40,
  function plus padding), callee.objdump.txt (0x5032f40..0x5032f4d).
  Regenerate them with export_excerpts.py (same binutils 2.42).
- verify.py (in this packet) and tools/foundation_field_sum.py
  (check_packet) are the runnable checkers behind "ALL CHECKS PASSED".
- The endbr64 at 0x514bcd0 and the endbr64 at 0x5032f40 are genuine
  instructions in the target binary, not placeholders; the nopl at
  0x514bd01 is genuine alignment padding before the loop head.

## Reproduction

```
objdump -d --start-address=0x514bcd0 --stop-address=0x514bd40 work/hl-node-94.bin
python3 research/work-items/RE-001-field-sum-94/verify.py --binary work/hl-node-94.bin
python3 tests/test_foundation_field_sum.py
```

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs, no Ghidra/Java, so `make doctor` fails and the repo-wide
`make catalogue-check` is not re-run here (its pre-existing LFS-pointer
identity failure is unrelated to this change); the checks above run
against the digest-verified work binary, not the LFS pointer.
