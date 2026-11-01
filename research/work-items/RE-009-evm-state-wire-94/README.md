# RE-009: EVM state snapshot wrapper and database placeholder

The #94 EVM-state writer represents its database field with a `NoEvmDb` variant rather than emitting the database contents in that field, while `block_hashes` is serialized separately, allowing a reconstruction to keep snapshot metadata distinct from database persistence.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `15f79350f790a04aed73b5fc9319f85b535f8282`; unlicensed can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` used as a lead, never copied.
- Claim status: observation for selected instructions, data, call edges and conditional branches; inference for the serialization and field-role interpretations below; unresolved for persistence wiring and the nonempty hash-row representation.
- Scope included and excluded: selected MessagePack writer and nested variant, a JSON-shaped writer, their named fields and failure exits; selected MessagePack and JSON-shaped readers, outer map/sequence decisions, and the variant-name check. Excludes full decoder grammar, complete nonempty `block_hashes` encoding, callee internals beyond the listed windows, matching a particular snapshot entry point, runtime I/O, other releases and execution.

## Reproduce

From the repository root, with Python 3.12.3 and the standard library plus the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/evm_state_wire94.py --out work/evm-state-wire-94
python3 -m unittest tests.test_evm_state_wire94
cmp work/evm-state-wire-94/evidence.json research/work-items/RE-009-evm-state-wire-94/evidence.json
cmp work/evm-state-wire-94/decisions.tsv research/work-items/RE-009-evm-state-wire-94/decisions.tsv
(cd research/work-items/RE-009-evm-state-wire-94 && sha256sum -c MANIFEST.sha256)
```

The generator checks the full input digest before parsing, reads ELF bytes directly, verifies the FDE records and header entries with the shared parsers, verifies the selected complete body hashes, and decodes selected fixed instruction encodings. It invokes no subprocess and never executes the captured binary. Output contains no time, host path, or hash-iteration-dependent ordering. GNU objdump 2.42 was used only to inspect bounded instruction windows manually; no objdump output is an input to generated evidence. No network, database, key, or chain access was used.

## Evidence

All addresses are unrelocated ELF virtual addresses. Endpoints in `evidence.json` are exclusive; a recorded FDE extent is unwind metadata, not by itself a proof that every function boundary or cold part is known. The 17 selected FDE bodies, 31 bounded raw byte windows, 25 direct call sites and 38 conditional branch destinations are retained in `evidence.json`. This is selected-window analysis, not a whole-node census. The TSV gives the corresponding bounded decision table.

### Writer and nested placeholder

The MessagePack-shaped writer at `0x2206a70` chooses a two-element map header when serializer byte `+0xb` is nonzero and a two-element array header when it is zero. On the intended byte values 0 and 1, the following selected operations occur in order:

| Stage | Evidence in ELF VA | Named mode (1) | Positional mode (0) |
| --- | --- | --- | --- |
| outer header | `0x2206a9e..0x2206ad5` | map of 2 | array of 2 |
| first field | `0x2206aec..0x2206b2c` | emit `evm_db`, then call nested writer | omit outer field name, then call nested writer |
| nested variant | `0x1e5a1ae..0x1e5a239` | map of 1, key `NoEvmDb`, empty map | map of 1, key `NoEvmDb`, empty array |
| second field | `0x2206b4b..0x2206b77` | emit `block_hashes`, then call child | omit outer field name, then call child |

The first field's variant writer is called with the literal `EvmDbSerde`, discriminant argument zero, the seven bytes `NoEvmDb`, and field count zero. Its emitted outer variant map always has one entry; its inner empty container depends on serializer byte `+0xb`. The first field's current database data is not passed to that nested writer on this selected path. `0x25a8f80`, `0x25a9bd0`, `0x25aa7f0` and `0x25acc20` supply the pinned map, array and short-string marker decisions. Each tested header or child failure takes an error-return route before subsequent stages; the concrete branch destinations and calls are recorded, without asserting allocator or I/O behavior.

The second child receives the input at `+0x1b20`. Its selected writer at `0x25ede50` collects a 16-byte-entry sequence, and `0x1e31f20` writes an array header then calls an element writer in its loop. For an empty input container, the zero-count branch in `0x2567250` returns a zero-length collection and the resulting array is empty. The internals of the nonempty element writer are excluded.

For a successful write and an empty `block_hashes` input, the static marker model produces these complete examples (hex, no whitespace):

| Mode | Bytes |
| --- | --- |
| named | `82a665766d5f646281a74e6f45766d446280ac626c6f636b5f68617368657390` |
| positional | `9281a74e6f45766d44629090` |

These are model outputs derived from the admitted bytes, not captures or executions of the node. In particular they do not show that a live snapshot uses either configuration. Byte values other than 0 and 1 at the mode byte are outside this analysis.

A separately located JSON-shaped writer at `0x2206be0` names the same two fields in the same order and passes `evm_db` to `0x295ed40`, which supplies `NoEvmDb` and zero fields to a nested helper. It also passes input `+0x1b20` to the second field writer. This establishes the selected calls and names, not the entire JSON byte stream or equivalence of the two concrete entry paths.

### Reader decisions and failure paths

The MessagePack-shaped reader `0x1854ef0` has separate map and sequence routes. Selected string-key comparisons at `0x1855cc6..0x1855d9e` compare exactly six bytes `evm_db` or twelve bytes `block_hashes`; other names go to the unknown-value helper. For a recognized `evm_db`, the seen-bit branch at `0x1856147` reaches the duplicate-field diagnostic if already present; otherwise it calls `0x16891f0`. For `block_hashes`, the corresponding branch at `0x18560b6` reaches its duplicate-field diagnostic or calls the second child. On map completion, the reader checks `evm_db` first, then `block_hashes`, using the respective missing-field diagnostics if absent. These statements are conditional on successful preceding parsing; they do not assert a global error precedence over malformed children.

On the sequence route, length 0 selects the first-element error. After the first child succeeds, length 1 selects the second-element error; length at least 2 invokes the second child. If that child succeeds, exactly 2 reaches the normal join and a larger count selects the extra-element error. `decisions.tsv` records those alternatives; child failure, exhaustion, cleanup and exception paths remain distinct and are not simulated as successful.

The first child `0x16891f0` accepts the one-entry map-size route before it calls the variant-name reader. It also has distinct short-input and wrong-size routes. The two downstream name-check implementations at `0x22e4cb0` and `0x22e4d90` compare exactly seven bytes `NoEvmDb`; the second uses overlapping four-byte XOR comparisons at offsets 0 and 3. This is a byte-level name predicate, not proof that a complete arbitrary input with that name is accepted.

The JSON-shaped reader `0x1cc7c00` has both `[` and `{` entry branches. Its map route compares the same two field names and has separate duplicate and missing-field diagnostics; it is a separate monomorph and does not establish identical malformed-input behavior across formats. The field and variant labels are inferred from the binary's field strings and call structure; they are not a recovered Rust type declaration.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No build, compiled byte comparison, normalization masks, call-target closure, runtime fixture, or native execution is claimed. The extractor's example bytes are a static model, not target-observed serialized files. The focused unit tests include wrong digest, rehashed mutated code and literal, changed opcodes and branches, NOBITS/unmapped addresses, mismatched names, and all single-byte replacements of the seven-byte variant name. The sample models condition on normal helper returns and a zero-length hash collection.

## Results and limitations

The extractor binds 17 selected FDE-described bodies, 31 windows, 25 direct calls and 38 conditional branches to the target digest. Twelve focused test methods pass, including 1,785 single-byte variant substitutions. These numbers describe this selected analysis, not function coverage or behavior equivalence. No full-scope milestone gate is requested. The identity and layout of nonempty `block_hashes` elements, sorting and duplicate-key rules, reader inner payload grammar, the entry point that supplies the EVM state to snapshot serialization, and runtime/on-disk compatibility remain unresolved.

Next question: trace the nonempty hash-row writer and its matching reader through their entry points, then validate complete fixtures in a separately authorized offline execution harness.
