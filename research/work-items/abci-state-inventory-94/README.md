# RE-001 / RE-009: node #94 exact-file ABCI state qualification

- Component: `abci`, restricted to the captured path `l1/src/abci/state.rs`.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline commit: `391fe838467760eefc04072c0ea762a7a1155c78`.
  Unlicensed reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Status: static observations; source identities beyond Locations, semantic
  constant roles and reconstructed behavior remain unresolved. No gate requested.
- Intended changes: only [collector](../../../tools/abci_state_inventory.py),
  [tests](../../../tests/test_abci_state_inventory.py) and this packet.

## Bounded question and existing work

Can every exact-path panic Location be attributed to an actual unwind extent
and an instruction boundary, with length-bearing literals, local numeric
setups and direct edges qualified from bytes? What parts of the reference
hints remain unsupported?

[RE-009](../RE-009-storage-state-roots/README.md) already reports the census,
all the scoped ranges (including the unseeded ones), the linked-state log,
and the inline `/dev/null` comparisons. None is a new discovery here.
[RE-017 / merged #381](../RE-017-abci-state-link-94/EVIDENCE.md) owns the
`:66 -> :107` GOT link and materializer-slot handoff; this packet does not
re-claim that link. [RE-019](../RE-019-rmp-json-loader-94/EVIDENCE.md) already
names the loader and its caller sites; our direct-edge records revalidate
instruction boundaries, displacements and the same-setup Location witnesses.

The additional evidence is complete sequential decoding of the scoped FDEs,
explicit shared-file attribution, adjacent pointer/length and counted-chunk
proofs, failure/absence records, and locally decoded EDX/source-address setups.
The different displacement triplet in `0x446da60` prevents treating all the
reference's suggested layouts as interchangeable. See [RESULT.md](RESULT.md).

The active task was blocked on reproducible instruction-boundary and
length-bearing qualification: the existing RE-009 collector uses byte scans
and does not provide these proofs; its optional disassembly also cannot meet
the requested Python-only reproduction. The new collector adapts the MIT
`node-rs-inventory-94` decoder at
`4647df111947397d3039cbb97df80a155c63cd62`, retaining its corruption controls.
It uses the existing ELF/FDE parsers unchanged. No infrastructure, imported
record, progress state, dependency or reference source was changed.

## Reproduce

Run from the repository root with Python 3.10+ standard library. Development
validation uses CPython 3.13.5 on Linux x86-64. No optional Python package,
REA connection, native disassembler, installation or network is needed.
The target is opened read-only via mmap, authenticated before parsing, and
never executed or emulated. Mutation tests use private copy-on-write mappings.

```sh
python3 tools/abci_state_inventory.py --out research/work-items/abci-state-inventory-94/
python3 -m unittest tests.test_abci_state_inventory -v
python3 research/work-items/abci-state-inventory-94/verify.py
make verify
```

`verify.py` checks an exact packet file whitelist, manifest hashes, pinned
facts, byte-identical regeneration and every generated report table. The
collector's JSON includes hashes of itself, the unchanged ELF/FDE helpers,
the reference lead file and overlapping prior records. The manifest includes
README, RESULT, verifier and both JSON exports; it does not hash itself.
No analyst paths, environment values, hostnames or timestamps are exported.
The original compiler path is retained as hexadecimal evidence only.

## Method and completeness

The census follows every RELATIVE relocation whose addend starts with the
exact embedded compiler-path prefix plus the scoped file. The complete
path bytes and length are checked, including `.rs` termination: prefix
matches to another path are rejected. Each record is aligned `.data.rel.ro`
data with a zero pre-relocation pointer, u64 path length and u32 line/column.
Duplicate relocation slots and malformed candidate records fail closed.
Distinct record addresses are retained even when line/column pairs repeat.

LEA scans are candidates only. The acceptance pass decodes every byte from
the actual `.eh_frame` FDE start through its declared end and checks internal
direct-branch targets against instruction boundaries. It reconciles the
unwind index with actual FDE/CIE records, retaining both records and body
hashes. It never treats the next indexed start as an exact body end.
Unknown encodings stop extraction; there is no resynchronization, objdump
fallback or skipping of undecodable owners. This proves bounded linear
instruction segmentation, not CFG reachability or original source functions.

Every reported LEA, call, immediate MOV and address setup has raw bytes,
ELF link-time VA and file offset. `instructions.json` covers the entire
selected extents. Candidate `e8`/`e9` bytes inside operands cannot become edges.
Edges require an exact scoped entry or the separately authenticated RE-019
entry; interior targets and all other calls remain outside the admitted set.

Literal bindings require a scoped decoded RIP LEA plus either adjacent
pointer/u64-length fields, a supported non-clobbering register/length setup,
or the bounded u8-length/ASCII/C0 chunk pattern. Neighboring pool bytes alone
never bind. The counted pattern establishes bytes and counts, not Rust
formatter grammar, interpolated arguments or rendered log output. Generic
panic text and unrelated node diagnostics do not inflate the probe set.
Reference-only absent strings are identified by source line, hash and length;
their unlicensed text is not copied into the packet.

## Derived inventory

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| call_edges | 3 |
| constant_operand_anchors | 18 |
| constants_bound | 3 |
| constants_unresolved | 9 |
| counted_fragment_anchors | 12 |
| decoded_instructions | 7052 |
| diagnostics_absent | 3 |
| diagnostics_bound | 4 |
| diagnostics_probed | 10 |
| diagnostics_unresolved | 3 |
| indirect_calls_unresolved | 409 |
| indirect_jumps_unresolved | 4 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 169 |
| location_leas | 38 |
| locations | 28 |
| named_callee_rel32_calls | 3 |
| pointer_length_anchors | 4 |
| scoped_fde_bytes | 37052 |
| scoped_fdes | 20 |
| scoped_rel32_calls | 0 |
| scoped_rel32_jumps | 0 |
| shared_first_party_fdes | 2 |
| source_setup_triplets | 5 |
| unique_line_column | 17 |
| unresolved_external_rel32_calls | 213 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x569db28 | 398:78 | 0x2208db6 | 0x2208580 |
| 0x569db50 | 196:9 | 0x2209015 | 0x2208e60 |
| 0x569db68 | 196:32 | 0x2209327 | 0x2208e60 |
| 0x569db80 | 203:9 | 0x2209243 | 0x2208e60 |
| 0x569db98 | 209:13 | 0x220950b | 0x2209450 |
| 0x56c4e48 | 145:17 | 0x2812804 | 0x28127a0 |
| 0x56c4e60 | 145:35 | 0x2812a17 | 0x28127a0 |
| 0x56c4e78 | 154:83 | 0x28121d0 | 0x2811e40 |
| 0x56c4e90 | 188:56 | 0x28126b3 | 0x28122a0 |
| 0x56c4ea8 | 190:17 | 0x28123a0 | 0x28122a0 |
| 0x56c4ec0 | 190:64 | 0x281261b | 0x28122a0 |
| 0x56dfba0 | 60:77 | 0x32729c5 | 0x32725d0 |
| 0x56dfbc8 | 63:100 | 0x3272a2e | 0x32725d0 |
| 0x56dfbe0 | 66:21 | 0x3272a47 | 0x32725d0 |
| 0x56dfbf8 | 107:37 | 0x3273856 | 0x3273810 |
| 0x56dfc10 | 97:9 | 0x22af04e | 0x22ae8a0 |
| 0x56dfc28 | 86:40 | 0x22aefdb, 0x4546bbe | 0x22ae8a0, 0x4546ba0 |
| 0x571fda8 | 398:78 | 0x444c1c6, 0x444d0a6 | 0x444b430, 0x444c310 |
| 0x571fdd0 | 196:9 | 0x446dc15, 0x446e205 | 0x446da60, 0x446e050 |
| 0x571fde8 | 196:32 | 0x446df27, 0x446e517 | 0x446da60, 0x446e050 |
| 0x571fe00 | 203:9 | 0x446de43, 0x446e433 | 0x446da60, 0x446e050 |
| 0x571fe18 | 209:13 | 0x446e6fb | 0x446e640 |
| 0x572e3e8 | 145:17 | 0x46cec4b, 0x46d007b | 0x46cea60, 0x46cfe90 |
| 0x572e400 | 145:35 | 0x46cef6e, 0x46d039e | 0x46cea60, 0x46cfe90 |
| 0x572e418 | 154:83 | 0x46cf3c0 | 0x46cf030 |
| 0x572e430 | 188:56 | 0x46cf8a3, 0x46cfda3 | 0x46cf490, 0x46cf990 |
| 0x572e448 | 190:17 | 0x46cf590, 0x46cfa90 | 0x46cf490, 0x46cf990 |
| 0x572e460 | 190:64 | 0x46cf80b, 0x46cfd0b | 0x46cf490, 0x46cf990 |
<!-- END GENERATED LOCATIONS -->

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA | First-party path count |
| --- | --- | --- | --- | --- |
| 0x2208580 | 0x2208e5c | 2268 | 0x1090040 | 1 |
| 0x2208e60 | 0x220944c | 1516 | 0x10900fc | 1 |
| 0x2209450 | 0x22095bd | 365 | 0x1090154 | 1 |
| 0x22ae8a0 | 0x22b107c | 10204 | 0x109d448 | 3 |
| 0x2811e40 | 0x2812291 | 1105 | 0x10ffa78 | 1 |
| 0x28122a0 | 0x2812794 | 1268 | 0x10ffacc | 1 |
| 0x28127a0 | 0x2812adb | 827 | 0x10ffb20 | 1 |
| 0x32725d0 | 0x3272b3a | 1386 | 0x115bf68 | 1 |
| 0x3273810 | 0x327396c | 348 | 0x115bfdc | 1 |
| 0x444b430 | 0x444c305 | 3797 | 0x12463a0 | 1 |
| 0x444c310 | 0x444d1e5 | 3797 | 0x1246490 | 1 |
| 0x446da60 | 0x446e04c | 1516 | 0x12479ac | 1 |
| 0x446e050 | 0x446e63c | 1516 | 0x1247a04 | 1 |
| 0x446e640 | 0x446e7ad | 365 | 0x1247a5c | 1 |
| 0x4546ba0 | 0x4546c51 | 177 | 0x1259688 | 2 |
| 0x46cea60 | 0x46cf026 | 1478 | 0x127e83c | 1 |
| 0x46cf030 | 0x46cf481 | 1105 | 0x127e890 | 1 |
| 0x46cf490 | 0x46cf984 | 1268 | 0x127e8e4 | 1 |
| 0x46cf990 | 0x46cfe84 | 1268 | 0x127e938 | 1 |
| 0x46cfe90 | 0x46d0456 | 1478 | 0x127e98c | 1 |
<!-- END GENERATED FDES -->

The following FDEs contain Location references to other first-party paths.
Even the other ranges' observed single-file path sets do not prove exclusive
source ownership: inlining without a Location remains possible.

<!-- BEGIN GENERATED ATTRIBUTION -->
| FDE | First-party Location paths |
| --- | --- |
| 0x22ae8a0 | base/src/lu.rs, l1/src/abci/state.rs, node/src/hl_node.rs |
| 0x4546ba0 | l1/src/abci/state.rs, node/src/hl_node.rs |
<!-- END GENERATED ATTRIBUTION -->

## Verification, limits and next question

The focused tests exercise actual target bytes below the digest gate as well
as synthetic decoder boundaries. They corrupt Locations, relocations,
sections, FDE lengths/index pointers, LEA sites/displacements, literal lengths,
source registers, adjacent fields, counted markers, direct calls and numeric
setups. Tests also reject report drift, omitted records, extra files, manifest
traversal/symlinks, invalid opcodes, truncations and embedded fake instructions.
Regeneration and verifier tests forbid external processes and network access.

See [RESULT.md](RESULT.md) for validation outcomes and unresolved work.
No Rust implementation, Cargo scope, rebuilt binary or raw/normalized byte
comparison was produced; normalization masks are empty. This is neither a
function-coverage denominator nor progress toward a full-scope gate by itself.
Next bounded question: resolve the call-slot/register provenance and input
object identities for the differing `0x446da60` source-address triplet before
assigning fields or copy semantics.
