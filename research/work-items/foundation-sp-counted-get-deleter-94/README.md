# foundation-sp-counted-get-deleter-94: what does the 0x514b5d0 window do?

- Component: `foundation`, a standard-library control-block window in the
  node #94 function map (RE-001: decode FDE ranges and validate
  entrypoints with digest-bound records).
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503`.
- Bounded question: what does the virtual function at `0x514b5d0`
  return for a given `std::type_info`, and through which consumer is
  it reached?
- Claim: observations about one target function, its only callee
  (strcmp), its GOT sentinel, its tag-name string, and the vtable
  slot that consumes it; the class identification below is an
  inference from the vtable and type_info records, not a
  source-level fact.
- Included: the 71-byte FDE function with its 9 padding bytes, the
  complete type-gate rule (sentinel, name-pointer, star-name, and
  strcmp arms), the strcmp PLT arm, the vtable slot and its four
  sibling virtuals, and the `__si_class_type_info` object that owns
  the vtable.
- Excluded: the dispose function's own chain-walking semantics
  (`0x514bb10`, recorded only as a vtable sibling), what the
  CacheHandleGuard object contains, and any claim about callers
  beyond the vtable slot (this function has no direct-e8 callers;
  it is reached by virtual dispatch).

## Why this packet

The function map needs bounded, digest-bound entries for the small
virtual functions that larger components dispatch through. This
window is a complete behavior, not a fragment: an entry function
plus the callee that decides one of its arms (strcmp) plus the
consumer that calls it (vtable slot `0x575b068`) plus the GOT
sentinel and tag-name string that decide the other arms. It is the
`_M_get_deleter` virtual of a `std::_Sp_counted_ptr_inplace`:
asked for a type_info, it returns the address of the in-place
stored object exactly when the type_info is the
`_Sp_make_shared_tag` type, and null otherwise.

This window was checked for overlap before building: no work-item,
tool, or test in the tree claims `0x514b5d0`, `_Sp_make_shared_tag`,
or `_M_get_deleter`, and no open WalkCrypto PR title mentions it
or a counted-pointer get-deleter. It is deliberately distinguished
from its neighbours: `0x514b4f0` (string move-assign, a different
protocol, previous cycle), `0x514b5c8` padding, and `0x514b620`
(the following FDE, a container accessor with its own GOT sentinel
at `0x5778020`, not examined beyond its first lines).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra, Java, or
REA provider was used: `make doctor` reports Rust and Ghidra
unavailable (expected on this VM, exit 1), and `make rea-doctor`
reports the pinned REA package absent. No target binary, captured
service, networked node, or chain operation was executed. All
analysis below is static byte evidence from the digest-verified
work copy `work/hl-node-94.bin`.

```sh
python3 tools/foundation_sp_counted_get_deleter.py --check research/work-items/foundation-sp-counted-get-deleter-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_sp_counted_get_deleter -v
```

Raw exports were generated with:

```sh
objdump -d --start-address=0x514b5d0 --stop-address=0x514b620 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
readelf -r work/hl-node-94.bin
```

The `window.objdump.txt` file retains complete disassembly of the
function including its 9 padding `int3` bytes. The `frames.txt`
file retains the function FDE line and the four sibling FDE lines.
The `relocations.txt` file retains the readelf relocation lines
for the GOT sentinel slot, the vtable slots, the type_info object
slots, and the neighbouring Reporter/Reader/FragmentBufferedReader
type_info objects (context only, not claimed). `evidence.json`
was generated programmatically from the objdump output and the
binary bytes, and the checker re-derives every claim from the
binary. `MANIFEST.sha256` covers `window.objdump.txt`,
`frames.txt`, `relocations.txt`, `evidence.json`, and this README,
and the checker verifies those hashes.

## Verbatim-evidence note, stated head-on

Every mnemonic, operand, and instruction byte in `evidence.json`
is copied exactly as GNU objdump emitted it, and the checker
verifies each recorded mnemonic against its own line in
`window.objdump.txt` and each recorded instruction byte against
the binary. The `endbr64` at `0x514b5d0` is a genuine instruction
present in the target binary, not a placeholder, and the `nopl` at
`0x514b60c` is a genuine compiler alignment NOP, not a placeholder.
The 9 `int3` bytes after `0x514b617` are padding to the next FDE
at `0x514b620`, not code.

## Observations

All addresses below are ELF VAs. Section mappings used: `.text`
file offset = VA - `0x1000`; `.rodata` file offset = VA;
`.data.rel.ro` file offset = VA - `0x2000` (all re-derived from
the PT_LOAD program headers by the checker, not assumed).

### Entry, FDE extent, and padding

- `.eh_frame+0x0029a5b4` describes `[0x514b5d0, 0x514b617)`,
  71 bytes. Complete linear decoding from that start gives the
  23 instructions in `evidence.json`, ending exactly at the FDE
  endpoint (the last body instruction is the `ret` at `0x514b616`
  on the star-name path; the shared return path ends at
  `0x514b60b`).
- Nine `int3` bytes follow: the next FDE starts exactly at
  `0x514b620`.
- The function preserves `rbx` and balances the stack (one `push
  %rbx` at entry, one `pop %rbx` on each return path). No stack
  canary is present.
- The objdump nearest-symbol label is stripped-binary arithmetic,
  not an identity, and no source-level function is claimed from it.

### The type gate, arm by arm

Arguments: `rdi` = counted object, `rsi` = `std::type_info`
(a vtable pointer at +0x0, the `__name` character pointer at
+0x8). Return: `rdi+0x10` on a match, 0 otherwise.

- Sentinel arm (`0x514b5d4`–`0x514b5e0`): the function compares
  `rsi` against the runtime pointer in GOT slot `0x5777a10`
  (`R_X86_64_RELATIVE`, addend `0x7ea4a8`). On equality it jumps
  to the shared return with `rbx` = `rdi+0x10`, set by the `lea`
  at `0x514b5dc`. The sentinel is never dereferenced: this arm
  succeeds even if the type_info's name field were unreadable.
- Name-pointer arm (`0x514b5e2`–`0x514b5f0`): `rdi` becomes
  `[rsi+0x8]` (the name pointer) and `rsi` becomes `0x7ea0d0`
  (the tag-name address, by `lea` at `0x514b5e6`). If the two
  pointers are equal, return `rdi+0x10` without calling strcmp.
- Star-name arm (`0x514b5f2`–`0x514b5f5`): if the name's first
  byte is `0x2a` (`'*'`), return 0. For this tag name the arm is
  outcome-redundant — the tag name starts with `S`, so strcmp
  would fail anyway — but the bytes contain the branch, so it is
  recorded and modelled.
- Strcmp arm (`0x514b5f7`–`0x514b607`): the function's only call,
  `strcmp@plt` (`0x56605e0`), compares the name against
  `St19_Sp_make_shared_tag` (bytes verified at `0x7ea0d0` plus
  its null terminator). A zero result keeps `rbx` =
  `rdi+0x10`; a nonzero result zeroes `rbx` via `cmovne`, and
  the shared return moves `rbx` to `rax`.

### The vtable consumer

- The function has no direct-`e8` callers in `.text` (full `.text`
  scan). It is reached by virtual dispatch: `.data.rel.ro` slot
  `0x575b068` holds `0x514b5d0` (`R_X86_64_RELATIVE`), as the
  fifth virtual (index 4) of the vtable whose address point is
  `0x575b048` (offset-to-top slot `0x575b038`, holding 0 with no
  relocation, and type_info slot `0x575b040`, holding
  `0x575b020`).
- The four sibling virtuals, in slot order:
  - slot 0, `0x514ac90` (FDE `0x0029a16c`, 5 bytes): `endbr64`
    then `ret` — a no-op complete-object destructor.
  - slot 1, `0x514aca0` (FDE `0x0029a180`, 14 bytes): `mov
    $0x28,%esi` then a jump to operator delete — a deleting
    destructor freeing a `0x28`-byte object.
  - slot 2, `0x514bb10` (FDE `0x00633d1c`, 133 bytes): dispose
    (its chain-walking internals are not claimed here).
  - slot 3, `0x514b160` (FDE `0x0029a458`, 14 bytes): `mov
    $0x28,%esi` then a jump to operator delete — destroy,
    freeing the same `0x28`-byte allocation.
- The two deleting paths agree on the object size `0x28`. The
  `_Sp_counted_base` prefix is `0x10` bytes (vtable pointer plus
  two 4-byte counters), so the in-place storage starts at
  `+0x10` — exactly the address this function returns. The
  returned address is the stored object, not a counter: the
  counters live at `+0x8` (use) and `+0xc` (weak) as 4-byte
  fields, and `+0x10` is the first byte past the base prefix.

### The owning type_info object

- At `0x575b020`: a `__si_class_type_info` object. Its vptr slot
  holds the `__cxxabiv1` class-type vtable address point
  (`R_X86_64_64`, addend `0x10`); its name slot `0x575b028`
  holds `0x7edfa0`; its base-type slot `0x575b030` holds
  `0x5756d90` (the base class's type_info).
- The name at `0x7edfa0` (bytes verified plus null terminator)
  is
  `St23_Sp_counted_ptr_inplaceIN7rocksdb16CacheHandleGuardINS0_24CacheEntryStatsCollectorINS0_13InternalStats19CacheEntryRoleStatsEEEEESaIvELN9__gnu_cxx12_Lock_policyE2EE`
  — a `std::_Sp_counted_ptr_inplace` holding a RocksDB
  `CacheHandleGuard`. The neighbouring type_info objects in the
  same table region (Reporter at `0x575b070`, Reader at
  `0x575b080`, FragmentBufferedReader at `0x575b090`) are
  context only.

## Inferences, kept separate from observations

- The name "`_M_get_deleter`" and the class identification are
  inferences from the vtable shape (five virtuals in the
  `_Sp_counted_base` order: two destructors, dispose, destroy,
  get-deleter), the `0x28` object size, and the
  `_Sp_make_shared_tag` comparison. They are not established
  source-level names.
- The `+0x10` = in-place storage reading is an inference from
  the base-prefix size and the `0x28` total; the bytes alone show
  the returned address is `object+0x10`.
- The sentinel's referent beyond identity is not claimed: GOT
  slot `0x5777a10` holds the runtime address `0x7ea4a8` (the
  file bytes there are zero padding after another type_info
  name), and the function only ever compares against it, never
  dereferences it.

## Unknowns

- What the sentinel address `0x7ea4a8` denotes beyond being the
  pointer identity this gate accepts; no other use of GOT slot
  `0x5777a10` is claimed.
- What the stored `CacheHandleGuard` object contains, and what
  the dispose function (`0x514bb10`) does with it.
- Whether any caller asks this gate for a type other than
  `_Sp_make_shared_tag` in practice; the gate's answer for every
  other type is null, as modelled.

## Environment limits, stated honestly

- `make doctor` exits 1 on this VM (Rust toolchains and Ghidra
  unavailable); `make rea-doctor` reports the pinned REA package
  absent. Analysis is GNU objdump/readelf static evidence only.
- Repo-wide `make catalogue-check` was not re-run this cycle;
  earlier cycles report its pre-existing LFS-pointer identity
  failure ("Byte coverage target identity differs"), which is
  unrelated to this PR's files and is not claimed as a regression.
- The checker and tests run offline against the digest-verified
  work copy; where the checkout path `artifacts/node/94/hl-node`
  is still an LFS pointer, pass `--binary work/hl-node-94.bin`
  (the tests try the artifact path first, then the work copy).
