# foundation-compression-bounds-94: which compression-bound helpers does node #94 link, and what do they compute?

- Component: `foundation`, toward its first task ("distinguish standard-library code from private helpers"), with a direct lead for `storage` (RocksDB block compression) and `net_utils` ("compression boundaries").
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `15f79350`.
- Reference pin: can1357/hl was not used for this packet. No implementation was copied.
- Claim: observations about two leaf instruction windows, their FDEs, their direct callers and their arithmetic. Library names are inferences and are kept separate.
- Included: the 27-byte window at `0x546af50` and the 45-byte window at `0x546e280`, their padding and neighbouring FDEs, exact rules with proven magic-number divisions, the complete direct-`e8` caller list for each, and the observation that two caller FDEs call both windows.
- Excluded: caller semantics beyond the reserve/resize pattern, compressor bodies, the Rust `lz4_flex` transport path, versions, target execution, Rust reconstruction and any progress gate.

## Why this packet

The binary links three compression implementations whose code must be kept apart from Hyperliquid's own: C++ Snappy (`N6snappy6SourceE`, `N6snappy4SinkE`), the C LZ4 library (RocksDB's `kLZ4Compression`/`kLZ4HCCompression` option names) and Rust `lz4_flex-0.11.6` used by `net_utils/src/tcp/lz4_stats.rs`. Strings alone do not say where any of that code is. These two windows are small, leaf, and arithmetic-only, so their rules read directly from their bytes, and each rule matches one library's documented output-size bound exactly. They are therefore two binary anchors for the library code, and their shared callers are concrete entry points for the storage compression path.

Overlap check before building: no work item, tool or test mentions `0x546af50`, `0x546e280` or either FDE offset; no open pull request diff mentions them. The existing `RE-001-lz4-counter-order-94` packet covers the transport LZ4 statistics counters at `0x3d2...`, not these windows. `foundation-mask-rounding-94` names `0x50814d0` and `0x5343ab0` only as callers of a different helper.

## Reproduce

Working directory: repository root. Platform: Debian, Python 3.12.15, GNU objdump 2.44 (`x86_64-linux-gnu-objdump`, Binutils for Debian). The checker and tests use the Python standard library only.

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_compression_bounds.py --check research/work-items/foundation-compression-bounds-94/evidence.json
python3 -m unittest tests.test_foundation_compression_bounds -v
```

No target binary, captured service, networked node or chain operation was executed. All analysis is static.

Raw exports:

```sh
objdump -d --start-address=0x546af50 --stop-address=0x546af70 artifacts/node/94/hl-node
objdump -d --start-address=0x546e280 --stop-address=0x546e2b0 artifacts/node/94/hl-node
objdump -d --start-address=0x5343ab0 --stop-address=0x53440f8 artifacts/node/94/hl-node
objdump -d --start-address=0x50814d0 --stop-address=0x5081fe5 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node   # excerpted
```

`window.objdump.txt` keeps both windows with their padding; `caller.objdump.txt` keeps the two complete shared caller FDEs; `frames.txt` keeps the shared CIE and the four FDE records (each window and its successor). `MANIFEST.sha256` covers every packet file plus the tool and test.

## Observations

All addresses are ELF VAs. `.text` file offset = VA - `0x1000`; `.eh_frame` (VA `0xce1518`) has equal file offsets and VAs. The tool resolves sections rather than assuming either.

### Window A: `0x546af50`, 27 bytes

- `.eh_frame+0x2be1a0` describes `[0x546af50, 0x546af6b)`; GNU's frame dump agrees. Five `int3` bytes follow, and the next FDE (`+0x2be1b4`) starts exactly at `0x546af70`.
- Linear decoding ends exactly at the FDE end:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x546af50` | `endbr64` | CET landing pad |
| `0x546af54` | `movabs $0xaaaaaaaaaaaaaaab,%rax` | divide-by-6 multiplier |
| `0x546af5e` | `mul %rdi` | unsigned 128-bit product; high half in RDX |
| `0x546af61` | `shr $0x2,%rdx` | RDX = floor(n / 6) |
| `0x546af65` | `lea 0x20(%rdi,%rdx,1),%rax` | n + n/6 + 32 |
| `0x546af6a` | `ret` | |

- Rule: `rax = (32 + n + floor(n/6)) mod 2^64` for 64-bit `n` in RDI. The multiplier is `ceil(2^66/6)` with error term `0xaaaaaaaaaaaaaaab*6 - 2^66 = 2 <= 2^2`, so the quotient is exact for every u64. There is no overflow guard; inputs near `2^64` wrap.
- Direct `e8` callers (complete byte scan of `.text`, each an instruction start in GNU's linear decoding of its FDE): `0x5081ae3`, `0x5343c43`, `0x546b097`, `0x546c24f`. No `.rela.dyn` addend names the window.

### Window B: `0x546e280`, 45 bytes

- `.eh_frame+0x2be544` describes `[0x546e280, 0x546e2ad)`. Three `int3` bytes follow; the next FDE (`+0x2be558`) starts at `0x546e2b0`.

| VA | Instruction | Role |
| --- | --- | --- |
| `0x546e280` | `endbr64` | |
| `0x546e284` | `xor %eax,%eax` | default result 0 |
| `0x546e286` | `cmp $0x7e000000,%edi` | input limit |
| `0x546e28c` | `ja 0x546e2ac` | **unsigned** above: return 0 |
| `0x546e28e` | `movslq %edi,%rax` | sign-extend n |
| `0x546e291` | `mov %edi,%edx` | |
| `0x546e293` | `imul $0xffffffff80808081,%rax,%rax` | divide-by-255 multiplier |
| `0x546e29a` | `sar $0x1f,%edx` | sign of n |
| `0x546e29d` | `shr $0x20,%rax` | high half |
| `0x546e2a1` | `add %edi,%eax` | add-back step of the signed magic |
| `0x546e2a3` | `sar $0x7,%eax` | |
| `0x546e2a6` | `sub %edx,%eax` | EAX = trunc(n / 255) |
| `0x546e2a8` | `lea 0x10(%rdi,%rax,1),%eax` | n + n/255 + 16 |
| `0x546e2ac` | `ret` | shared by both paths |

- Rule on the raw 32-bit EDI: `0` when `EDI > 0x7e000000` unsigned, else `EDI + floor(EDI/255) + 16`. Because the comparison is unsigned (`ja`), every negative `int32` also returns 0 and the division always sees a non-negative value. The multiplier `0x80808081 = ceil(2^39/255)` has error term 127, exact for `n < 4,328,785,936`, which covers the admitted range. A separate exhaustive NumPy restatement of the instruction sequence over all 2,113,929,217 admitted inputs matched the closed form with 0 mismatches (not part of the unit tests; they use edges, 255-multiples ±1 and 22,000 random inputs).
- Edges: `0 -> 16`, `254 -> 270`, `255 -> 272`, `0x7e000000 -> 0x7e7e7e8e`, `0x7e000001 -> 0`, `0x80000000 -> 0`.
- Direct `e8` callers: `0x5081bcf`, `0x5081ce0`, `0x5343e07`, `0x5343ec0`, `0x5489260`. No `.rela.dyn` addend names the window.

### Callers

- Two caller FDEs reach **both** windows: `[0x50814d0, 0x5081fe5)` and `[0x5343ab0, 0x53440f8)`. Each calls window A once and window B twice. Every one of those six calls is followed within a few instructions by a call to `std::string::resize(size_t, char)` (PLT `0x56606b0`) with the returned bound, then calls to other routines, then another `resize`: a reserve-to-bound, compress, shrink-to-actual shape. Both FDEs also contain separate `cmp $0x2,%ecx` branches before each arm.
- `0x5489260` sits in an 83-byte FDE at `0x5489240` that passes ECX to window B, sets R9D to 1 when the returned bound is greater than R8D, and tail-calls `0x5488f30` with the original arguments plus that flag.
- `0x546b097` sits in a 228-byte FDE at `0x546b030` that clamps its size argument at `0x10000`, derives a power-of-two table size, adds window A's result and calls `operator new`. `0x546c24f` (FDE `0x546c1a0`, 774 bytes) was not analyzed.

## Inferences

- Window A is Snappy's `MaxCompressedLength`, whose definition is `32 + source_bytes + source_bytes/6`. Basis: identical formula, Snappy C++ RTTI strings in the binary, and the `0x10000` clamp in caller `0x546b030`, which matches Snappy's 64 KiB block size in its working-memory setup.
- Window B is the LZ4 C library's `LZ4_compressBound`: `(unsigned)isize > LZ4_MAX_INPUT_SIZE (0x7E000000) ? 0 : isize + isize/255 + 16`. Basis: identical constants and unsigned comparison, plus caller `0x5489240`, whose "bound > capacity" flag matches LZ4's choice between limited and unlimited output in its `compress_fast_extState` path. It is **not** the Rust `lz4_flex` bound, which uses a different formula, so the transport LZ4 path and this C LZ4 code are distinct.
- The two shared callers are most likely RocksDB-style block compression dispatch (one arm per compression type, with LZ4 and LZ4HC both using window B). Basis: RocksDB option strings and the reserve/compress/shrink shape. Their identities are not established here.

## Unknowns

- Snappy, LZ4 and RocksDB versions; the meaning of the `cmp $0x2,%ecx` branches (possibly a compression format version); the two other compressor calls in each arm.
- Indirect callers: the scan covers direct `e8` sites only.
- Whether a separate LZ4HC bound exists elsewhere (both LZ4 arms here use window B).

## Limits

- No source-level name, library version or caller identity is claimed as fact.
- The `e8` scan is not a complete xref census, and the relocation check covers `.rela.dyn` addends only.
- No progress gate is requested or claimed; generated progress files are unchanged.
