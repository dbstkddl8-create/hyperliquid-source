# RE-001: what does node #94's object-keyed map::at 0x514b490 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about one target function, its
  throw arm and its 14 direct callers in one consumer function;
  the source-level name of the map and the consumer's wider
  logic remain inferences / unresolved.
- Scope included: the whole 84-byte FDE function
  0x514b490..0x514b4e4, its out_of_range("map::at") throw arm,
  and all 14 direct-e8 call sites in the consumer function
  0x514d0c0..0x514d76e, each with its key setup and its first
  use of the returned value pointer.
- Scope excluded: the consumer's wider logic (only its call
  sites, key setups and first value uses are recorded), the
  node type behind the tree (only the +0x10/+0x18/+0x20/+0x28
  layout the bytes use), and the neighboring functions
  0x514b390 (a larger string-replace function, different
  protocol) and 0x514b4f0 (a different function, not examined
  here).

## Why this packet is one complete behavior, not a lone window

The function is a whole lookup, pinned end to end: it takes a
map object and a signed int32 key, walks the tree to the
lower bound, and has exactly two observable outcomes — it
returns the hit node's value pointer (node + 0x28) on an exact
key hit, or it throws out_of_range("map::at") on every miss
(empty tree, no candidate, or a candidate whose key is greater
than the sought key). Both outcomes are observable in the
bytes, and the behavior is actually used: 14 genuine direct
call sites in one consumer all pass the same map object (rbx)
with descending small keys and immediately read a double (or
convert one) from the returned pointer. This is not a fragment
delegating its meaning elsewhere: the only callee is the
throw stub, reached only on the miss path.

## Not a redo of #1314's map::at window

PR #1314 bound the window 0x514b1c0, a different function
that hardcodes a global table: its first instruction loads the
table address 0x578bf20 into r8 and it takes the key in edi.
This function takes the map object in rdi and the key in esi
and reads the root from [rdi + 0x10]; it has its own FDE
(0x0029a570, pc 0x514b490..0x514b4e4), its own 14 call sites,
and a different consumer (0x514d0c0..0x514d76e, not #1314's
0x514d770 consumer). The shared +0x10/+0x18/+0x20 layout and
the shared "map::at" throw string are the common map
implementation, not a duplicated claim.

## The rule, exactly as the bytes state it

Arguments: rdi = map object, esi = sought key (signed int32,
compared as a 32-bit value). No register is preserved across
the call except by the caller's own saves; the return is a
pointer (node + 0x28) on a hit, and the function does not
return at all on a miss.

1. Root load (0x514b490 `mov 0x10(%rdi),%rdx`,
   0x514b494 `test %rdx,%rdx`, 0x514b497 `je`): the root is
   [object + 0x10]. A null root jumps straight to the throw
   tail — an empty tree always throws.
2. Lower-bound walk (0x514b499 `lea 0x8(%rdi),%r8` sets the
   candidate default to the header node at object + 0x8;
   0x514b4b0 `mov 0x10(%rdx),%rcx` loads the left child,
   0x514b4b4 `mov 0x18(%rdx),%rdi` loads the right child,
   0x514b4b8 `cmp %esi,0x20(%rdx)` compares the node key
   against the sought key, 0x514b4bb `jl`): when the node key
   is strictly less than the sought key, the walk continues
   with the right child (0x514b4a8 `mov %rdi,%rdx`, with a
   null right child falling out of the loop to the candidate
   check); otherwise the node becomes the candidate
   (0x514b4bd `mov %rdx,%rax`) and the walk continues with
   the left child (0x514b4c0 `mov %rcx,%rdx`), so the final
   candidate is the smallest node whose key is greater than
   or equal to the sought key, or the header when no such
   node exists.
3. Hit test (0x514b4c8 `cmp %rax,%r8`, 0x514b4cb `je`):
   a header candidate throws — the tree held no key greater
   than or equal to the sought key. 0x514b4cd
   `cmp %esi,0x20(%rax)`, 0x514b4d0 `jg`: a candidate whose
   key is strictly greater than the sought key also throws.
   Only an exact key equality falls through.
4. Hit return (0x514b4d2 `add $0x28,%rax`,
   0x514b4d6 `ret`): the returned pointer is the hit node
   plus 0x28 — the value slot, matching the +0x28 value
   address #1314's window returns.
5. Throw tail (0x514b4d7 `push %rax`, 0x514b4d8 `lea`
   the .rodata string at 0x1efeee, 0x514b4df `call`
   0x5660710): the string bytes at 0x1efeee are
   `map::at` plus a NUL terminator, and 0x5660710 is the
   `__throw_out_of_range` PLT stub, so every miss raises
   out_of_range("map::at") and never returns.

Composed rule: `at(object, key)` returns the value pointer
for `key` when the tree contains exactly that key, and
throws out_of_range("map::at") otherwise. The key comparison
is signed 32-bit: a node key of -1 sorts below 0, and
INT32_MIN / INT32_MAX behave as ordinary signed bounds.

## Callers (all 14 direct-e8 sites, full .text scan)

Every site lives in the one consumer function
0x514d0c0..0x514d76e, passes the same object in rbx (via
`mov %rbx,%rdi` just before the call, except where noted),
and reads a double from the returned pointer immediately
after the call. Keys descend from 21:

- 0x514d101 — key 21 (`mov $0x15,%esi` at 0x514d0e9);
  after the call, `movsd (%rax),%xmm2`.
- 0x514d118 — key 20 (`mov $0x14,%esi` at 0x514d106);
  after the call, `movsd (%rax),%xmm3`.
- 0x514d12f — key 19 (`mov $0x13,%esi` at 0x514d11d);
  after the call, `cvttsd2si (%rax),%rsi`.
- 0x514d151 — key 18 (`mov $0x12,%esi` at 0x514d141);
  after the call, `cvttsd2si (%rax),%rsi`.
- 0x514d1ee — key 16 (`mov $0x10,%esi` at 0x514d1e3);
  after the call, `cvttsd2si (%rax),%eax`.
- 0x514d26e — key 14 (`mov $0xe,%esi` at 0x514d263);
  after the call, `movsd (%rax),%xmm6`.
- 0x514d285 — key 13 (`mov $0xd,%esi` at 0x514d277);
  after the call, `movsd (%rax),%xmm7`.
- 0x514d36e — key 10 (`mov $0xa,%esi` at 0x514d363);
  after the call, `movsd (%rax),%xmm5`.
- 0x514d385 — key 9 (`mov $0x9,%esi` at 0x514d377);
  after the call, `movsd (%rax),%xmm6`.
- 0x514d406 — key 7 (`mov $0x7,%esi` at 0x514d3fb);
  after the call, `movsd (%rax),%xmm2`.
- 0x514d41d — key 6 (`mov $0x6,%esi` at 0x514d40f);
  after the call, `movsd (%rax),%xmm3`.
- 0x514d437 — key 5 (`mov $0x5,%esi` at 0x514d426);
  after the call, `movsd (%rax),%xmm1`.
- 0x514d451 — key 4 (`mov $0x4,%esi` at 0x514d440);
  after the call, `movsd (%rax),%xmm0`.
- 0x514d46b — key 3 (`mov $0x3,%esi` at 0x514d45a);
  after the call, `movsd (%rax),%xmm0`.

Keys observed at these sites: 21, 20, 19, 18, 16, 14, 13,
10, 9, 7, 6, 5, 4, 3. Keys 17, 15, 12, 11, 8, 2 and 1 have no
direct call to this function in this consumer and are NOT
claimed for it — the consumer may reach them another way,
and that way is not part of this packet. The consumer also
contains 7 direct calls to the same throw PLT stub; those
are its own throw paths, not calls to this function, and
are recorded only to avoid miscounting them as callers.

## Observations, inferences, unknowns (kept separate)

- Observed: the function never writes through any pointer,
  never stores a result, and returns only the hit node's
  value pointer; its only side effect is the throw on a miss.
- Observed: all 14 callers read a double from the returned
  pointer (via movsd, or cvttsd2si for keys 19, 18 and 16),
  so the values in this map are doubles as consumed here —
  but the map's source-level value type is not pinned by
  these bytes alone.
- Inference (not claimed as fact): the node layout
  (left +0x10, right +0x18, key +0x20, value +0x28, header
  at object + 0x8) matches a std::map node, and the function
  looks like std::map::at; the bytes alone do not name the
  map, so the packet claims only the byte-level rule.
- Unknown: the source-level name of this map and of the
  consumer function, what the consumer does with the 14
  doubles, and how the consumer reaches the unlisted keys.

## Verbatim evidence note

The disassembly excerpt in window.objdump.txt (the whole
function) and the per-site excerpts in callers.objdump.txt
are the unmodified output of GNU objdump 2.42 for those
ranges (the commands are under Reproduce). The instruction
entries in evidence.json copy the mnemonic, operands and
raw bytes from that output exactly — nothing paraphrased,
shortened or sanitized. This function has no endbr64: its
first instruction is `mov 0x10(%rdi),%rdx`, not a landing
pad, and no endbr64 is claimed for it. One caller excerpt
contains a `nopw` alignment instruction inside the function
itself, recorded with its full bytes exactly as objdump
prints it. The checker re-derives every byte from the
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
objdump -d --start-address=0x514b490 --stop-address=0x514b4e4 work/hl-node-94.bin
objdump -d --start-address=0x514d0c0 --stop-address=0x514d76e work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_map_at_object.py \
  --check research/work-items/foundation-map-at-object-94/evidence.json \
  --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_map_at_object -v
```

Environment limits, stated honestly: `make catalogue-check`
fails on this checkout for the pre-existing LFS-pointer identity
reason ("Byte coverage target identity differs") before reaching
this item's files; that failure is not a regression from this
change, and the item's own checker and tests are the verification
that runs here. Rust and Ghidra are unavailable on this VM
(expected); no Rust component is claimed.
