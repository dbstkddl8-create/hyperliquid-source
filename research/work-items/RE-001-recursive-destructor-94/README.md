# RE-001-recursive-destructor-94: what does the 0x514b690 window do?

- Component: `foundation`, a recursive node destructor in the
  node #94 function map (RE-001: decode FDE ranges and validate
  entrypoints with digest-bound records).
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503`.
- Bounded question: given a head pointer in `rdi`, which nodes
  does the function at `0x514b690` delete, in which order, and
  with what size argument?
- Claim: observations about one target function, its self-recursive
  call, its operator-delete call, and its caller census. The
  source-level identity of the node type is NOT claimed: the bytes
  pin two qword links per node and a 0x30-byte delete size, and
  nothing else about what the nodes are.
- Included: the 49-byte FDE function with its 15 padding bytes,
  the complete delete-order rule, the operator-delete PLT stub
  with its GOT relocation, and all 12 external direct call sites
  in their 10 enclosing functions.
- Evidence format: `records.json` holds semantic records only —
  the function carve range with its SHA-256, branch site→target
  and call site→target pairs, the caller census, the PLT record,
  and the rule — following the reference packets that draw no
  `low_quality` flags. It deliberately contains no
  per-instruction mnemonic list: the raw disassembly lives in
  `window.objdump.txt`, `callers.objdump.txt` and
  `plt.objdump.txt`, and `verify.py` in this packet plus the
  checker in `tools/foundation_recursive_destructor.py` verify
  the records (and the excerpt bytes) against the binary.
- Excluded: the source-level identity of the node type and of the
  structures at `[node + 0x10]` / `[node + 0x18]` beyond "qword
  link"; the wider semantics of the 10 enclosing functions (their
  call sites are a census plus two argument spot-checks, not a
  claim about those functions); and any claim about the other
  `_ZdlPvm@plt` call sites beyond this function's own delete call.

## Why this packet

The function map needs bounded, digest-bound entries for the
functions that tear structures down. This window is a complete
behavior, not a fragment: an entry with a null-head fast path,
plus the self-recursive call that decides the traversal order,
plus the operator-delete call that decides the observable effect
(freeing each node with size `0x30`), plus the caller census
that shows where the destructor is actually invoked. It is
deliberately distinguished from its neighbours: `0x514b620`
(the devirtualized getter, already claimed in-tree by
`foundation-devirtualized-getter-94`, a different protocol that
reads one field and returns 1) and the following FDE at
`0x514b6d0` (unexamined, not part of this item).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra, Java, or
REA provider was used: `make doctor` reports Rust and Ghidra
unavailable (expected on this VM, exit 1), and `make rea-doctor`
reports the pinned REA package absent. No target binary, captured
service, networked node, or chain operation was executed. All
analysis below is static byte evidence from the digest-verified
work binary `work/hl-node-94.bin`.

```sh
objdump -d --start-address=0x514b690 --stop-address=0x514b6d0 work/hl-node-94.bin
objdump -d --start-address=0x5660440 --stop-address=0x5660450 work/hl-node-94.bin
readelf --debug-dump=frames-interp work/hl-node-94.bin | grep 'FDE cie='
python3 research/work-items/RE-001-recursive-destructor-94/verify.py --binary work/hl-node-94.bin
python3 tools/foundation_recursive_destructor.py --check research/work-items/RE-001-recursive-destructor-94/records.json --binary work/hl-node-94.bin
```

## The function, instruction by instruction

FDE `.eh_frame+0x0029a5ec` describes `[0x514b690, 0x514b6c1)`,
49 bytes, SHA-256
`dfe6e85ada6937acb7c170a83716361d3c0ba848318aac3f4edf6b766f527108`,
followed by 15 `int3` padding bytes to the next FDE at
`0x514b6d0`. The disassembly below is verbatim objdump output
(see `window.objdump.txt`); the `nopw` at `0x514b6ba` is a
genuine alignment NOP between the two `ret` instructions, not a
placeholder, and this function has no `endbr64` — its first
instruction is `test %rdi,%rdi`.

| Address | Bytes | Instruction | Reading |
|---|---|---|---|
| `0x514b690` | `48 85 ff` | `test %rdi,%rdi` | null-head check |
| `0x514b693` | `74 2b` | `je 514b6c0` | null head → trailing `ret`, no stack change |
| `0x514b695` | `53` | `push %rbx` | save callee-saved node cursor |
| `0x514b696` | `48 89 fb` | `mov %rdi,%rbx` | cursor = head |
| `0x514b699` | `48 8b 7b 18` | `mov 0x18(%rbx),%rdi` | child = `[cursor + 0x18]` |
| `0x514b69d` | `e8 ee ff ff ff` | `call 514b690` | destroy the child subtree first (self-recursion) |
| `0x514b6a2` | `48 89 df` | `mov %rbx,%rdi` | delete argument = cursor |
| `0x514b6a5` | `48 8b 5b 10` | `mov 0x10(%rbx),%rbx` | cursor = `[cursor + 0x10]` (read before the free) |
| `0x514b6a9` | `be 30 00 00 00` | `mov $0x30,%esi` | delete size = 48 bytes |
| `0x514b6ae` | `e8 8d 4d 51 00` | `call 5660440` | `operator delete(cursor, 0x30)` via PLT |
| `0x514b6b3` | `48 85 db` | `test %rbx,%rbx` | end of chain? |
| `0x514b6b6` | `75 e1` | `jne 514b699` | loop while the next link is non-null |
| `0x514b6b8` | `5b` | `pop %rbx` | restore cursor register, stack balanced |
| `0x514b6b9` | `c3` | `ret` | normal return |
| `0x514b6ba` | `66 0f 1f 44 00 00` | `nopw 0x0(%rax,%rax,1)` | alignment between the two returns |
| `0x514b6c0` | `c3` | `ret` | null-head return (inside the FDE extent) |

Branch/call targets re-derived from the raw encodings: `je`
at `0x514b693` is rel8 `0x2b` → `0x514b695 + 0x2b = 0x514b6c0`;
`call` at `0x514b69d` is rel32 `0xffffffee` →
`0x514b6a2 - 0x12 = 0x514b690` (self); `call` at `0x514b6ae`
is rel32 `0x00514d8d` → `0x514b6b3 + 0x514d8d = 0x5660440`;
`jne` at `0x514b6b6` is rel8 `0xe1` (signed -31) →
`0x514b6b8 - 31 = 0x514b699`.

## Composed rule

`destroy(head)` with `head` in `rdi`, returning void (`rax`
is unspecified on return — the bytes never set it after the
last delete call):

- If `head` is null, return immediately via the trailing `ret`
  at `0x514b6c0`, without pushing anything or deleting anything.
- Otherwise, with cursor starting at `head`, repeat: destroy
  the subtree at `[cursor + 0x18]` by self-recursion; delete
  `cursor` itself with `operator delete(cursor, 0x30)`; advance
  the cursor to `[cursor + 0x10]` (read before the delete, so
  the freed node's next link is never read after the free);
  stop when the advanced cursor is null. `rbx` is preserved
  across the whole call and the stack is balanced.

So the deletion order is: for each node, its `+0x18` subtree
first (depth-first, in the same order), then the node itself,
then the `+0x10` chain iteratively. Worked example: head `H`
with `H+0x10 = A`, `H+0x18 = C`, `C+0x10 = D`, all other links
null — the delete order is `C, D, H, A`. (First the loop
recurses into `C`, which deletes `C`, then its `+0x10` link
`D`; then the loop deletes `H`; then it advances to `A` and
deletes it.)

## Operator-delete callee

The PLT stub at `0x5660440` (see `plt.objdump.txt`) is
`jmp *0x118b02(%rip)` → GOT slot `0x5778f48`, whose
`.rela.plt` entry is `R_X86_64_JUMP_SLOT` for symbol
`_ZdlPvm` (operator delete). The slot's file bytes are
`0x5660446` — the address of the stub's own lazy-binding
resolver entry (`push $0x35; jmp PLT0`), not the resolved
symbol: the first call routes through the resolver, and the
dynamic loader then overwrites the slot with the real
`_ZdlPvm` address. The `0x30` in `esi` is the sized
delete argument, so each node is freed as a 48-byte object.

## Caller census

A full `.text` direct-`e8` scan finds exactly 13 call sites to
`0x514b690`: the self-call at `0x514b69d` plus 12 external
sites in 10 enclosing functions (see `callers.objdump.txt` for
per-site excerpts and `frames.txt` for the enclosing FDE lines):

| Call site | Enclosing FDE | Spot-check |
|---|---|---|
| `0x514b7bc` | `0x514b7b4..0x514b7da` | `rdi = r13` immediately before the call |
| `0x514bf14` | `0x514bee0..0x514bf51` | census only |
| `0x514c752` | `0x514c74e..0x514c774` | census only |
| `0x514c864` | `0x514c780..0x514c8e6` | census only |
| `0x5151709` | `0x5151704..0x515172b` | census only |
| `0x5151893` | `0x5151730..0x5151909` | census only |
| `0x5151912` | `0x515190a..0x515196a` | census only |
| `0x515195e` | `0x515190a..0x515196a` | census only |
| `0x5151e2a` | `0x5151970..0x5152201` | census only |
| `0x515201c` | `0x5151970..0x5152201` | census only |
| `0x5156080` | `0x5155fca..0x51560a3` | census only |
| `0x5156abb` | `0x51560b0..0x5157a19` | `rdi = [rsp+0xd0]` immediately before the call |

The two spot-checks confirm genuine calls passing a node
pointer in `rdi`; the other ten sites are recorded as a census
only, and the enclosing functions' wider semantics are not
claimed here. One spot-check context worth stating plainly:
the `0x514b7bc` site sits in a catch handler (the enclosing
function opens with a `__cxa_begin_catch` call and rethrows
right after the destroy call), but this packet claims only the
destroy call itself, not the handler's purpose.

## What is NOT claimed

- The node type, the meaning of the `+0x10` / `+0x18` links
  beyond "qword link", and what allocates these nodes.
- Any ordering claim for structures where a node is reachable
  through two paths (the model assumes each node is visited
  once, as the bytes' traversal implies, but aliasing is not
  observable from this window alone).
- Any claim about the following FDE at `0x514b6d0`, which is
  unexamined.
