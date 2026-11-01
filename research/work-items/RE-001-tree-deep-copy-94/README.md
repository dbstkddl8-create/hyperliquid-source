# RE-001: deep copy of a node #94 binary tree (0x514b7e0)

Task ID: RE-001. Bounded question: what does the 556-byte function at
0x514b7e0 in node #94 compute, and how does its node-pool argument
work? Answer: it deep-copies a tree of 0x30-byte nodes, reusing nodes
from a caller-supplied pool when available and allocating fresh nodes
otherwise, with an exception cleanup that destroys the node currently
being built.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514b7e0..0x514ba0c, 556 bytes, FDE at .eh_frame+0x00633cb4
  (length 0x40, CIE 0x006205d0), 4 int3 padding bytes to the next FDE
  at 0x514ba10.
- No stack canary in this function; five callee-saved registers are
  pushed and popped in balance (rbx, rbp, r12, r13, r14).

## Observations (read from the bytes)

- Node layout, from the field accesses: +0x0 int32 value (copied
  verbatim), +0x8 parent pointer, +0x10 left child, +0x18 right child,
  +0x20 16-byte payload (copied with a 16-byte vector move).
- Arguments: rdi = source node (dereferenced unconditionally, so the
  caller must pass non-null), rsi = parent for the new root,
  rdx = pool pair C.
- Pool pair C: [C+0x0] is an old-root handle, [C+0x8] is the pool head.
  A pop takes the head, advances the head to the head's parent link
  (+0x8), and applies one of three fixups recorded verbatim in
  records.json (exhaustion clears [C+0x0]; a right-child take redirects
  the head into the taken node's parent's left subtree; any other take
  clears the parent's +0x10). When the head is 0, operator new
  (PLT 0x5660490) allocates a fresh 0x30-byte node.
- Copy shape: the new node's +0x10 and +0x18 start at 0 and its +0x8
  is the parent argument; the source's +0x18 child is copied by direct
  recursion (two self-call sites, 0x514b854 and 0x514b8d0); the
  source's +0x10 child is copied iteratively as a spine loop, each
  spine node linked as [previous_new+0x10] with +0x8 = previous_new,
  and each spine node's own +0x18 child is copied by recursion.
  The return value is the first node built (the new root).
- Direct-caller census (full .text scan): exactly three direct call
  sites — the two self-recursive sites above, plus one external site
  at 0x514c80e inside the container-copy function 0x514c780..0x514c8e6.
  That caller passes rdi = source root from [r12+0x10],
  rsi = destination header node (rbp+0x8), rdx = a stack pool pair
  ([rsp] = old root, [rsp+0x8] = old rightmost, or 0 when the
  destination is empty). After the call it fixes up the destination
  header's leftmost/rightmost/count fields and destroys leftover old
  nodes while [rsp] is non-null — the caller itself is census evidence
  only and is not modelled here.
- Exception path: a landing-pad stub inside this function's FDE range
  (0x514ba00: endbr64, move rax to rdi, jump to 0x514b7b4) reaches the
  shared cleanup at 0x514b7b4 (own FDE 0x00633cf8, 38 bytes, 6 int3
  padding to 0x514b7e0). The cleanup calls __cxa_begin_catch, then the
  recursive destructor at 0x514b690 on the node in r13, then
  __cxa_rethrow; its second entry (0x514b7c6) ends the catch and calls
  _Unwind_Resume. The same cleanup immediately follows the string
  constructor at 0x514b6d0 and serves it as well.
- PLT stubs cited, with GOT slots from their indirect jumps: operator
  new 0x5660490 -> 0x5778f70, __cxa_begin_catch 0x5660520 -> 0x5778fb8,
  __cxa_rethrow 0x5660530 -> 0x5778fc0, __cxa_end_catch 0x5660540 ->
  0x5778fc8, _Unwind_Resume 0x5660110 -> 0x5778db0.

## Inferences (labelled, not observations)

- The node shape (parent/left/right/value/payload) matches a binary
  search tree node; the +0x0 int32 is recorded as a value copied
  verbatim, and any tree-color reading of it is not claimed.
- The pool is read as the old destination tree being recycled: the
  caller seeds it with (old root, old rightmost), the copy drains it
  node by node, exhaustion clears the old-root handle, and the caller
  destroys whatever remains. The pop sequence itself is
  transliterated, not interpreted, in tools/foundation_tree_deep_copy.py.
- The cleanup's "node in r13" is read as the node currently being
  built (r13 is the callee-saved register that holds the new node
  throughout the function body).

## Unknowns (not claimed)

- The LSDA action table for the landing pad is not decoded here; only
  the stub-to-cleanup jump and the cleanup's own calls are claimed.
- The source-level type name of the tree is not claimed; the function
  is described by its observed node layout and copy behaviour only.
- No claim is made about the destructor at 0x514b690 beyond its use
  here: it is bound by an earlier work item and is used, not re-claimed.

## Overlap notes (checked before building)

- No work item, tool, test, or doc in the tree mentions 0x514b7e0 or
  0x514ba0c, and no open WalkCrypto PR covers this function.
- Neighbours are distinct and not re-claimed: 0x514b620 (devirtualized
  getter, already bound), 0x514b690 (recursive destructor, already
  bound, used by the cleanup), 0x514b6d0 (string constructor, preceding
  function, shares the cleanup), 0x514b7b4 (shared cleanup, claimed
  here only as this function's exception path), 0x514c780 (container
  copy, census evidence only).

## Evidence format

- records.json holds semantic records only (carve ranges with SHA-256,
  branch site-to-target pairs, call sites, PLT/GOT records, pool and
  copy rules, caller census). It contains no per-instruction list.
- Instruction-level detail lives only in the raw objdump excerpts,
  kept whole-function: window.objdump.txt (0x514b7e0..0x514ba10),
  cleanup.objdump.txt (0x514b7b4..0x514b7e0),
  caller.objdump.txt (0x514c780..0x514c8f0), plt.objdump.txt.
  Regenerate them with export_excerpts.py (same binutils 2.42).
- verify.py (in this packet) and tools/foundation_tree_deep_copy.py
  (check_packet) are the runnable checkers behind "ALL CHECKS PASSED".
- This function has no endbr64 at its entry (it starts with register
  pushes); the endbr64 at 0x514ba00 belongs to the landing-pad stub
  and the endbr64 at 0x514b7c6 belongs to the cleanup's second entry.
  Both are genuine instructions in the target binary, not placeholders.

## Reproduction

```
objdump -d --start-address=0x514b7e0 --stop-address=0x514ba10 work/hl-node-94.bin
python3 research/work-items/RE-001-tree-deep-copy-94/verify.py --binary work/hl-node-94.bin
python3 tests/test_foundation_tree_deep_copy.py
```

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs, no Ghidra/Java, so `make doctor` fails and the repo-wide
`make catalogue-check` is not re-run here (its pre-existing LFS-pointer
identity failure is unrelated to this change); the checks above run
against the digest-verified work binary, not the LFS pointer.
