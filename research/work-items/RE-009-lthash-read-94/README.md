# RE-009: nested lattice-state checkpoint reader

The node #94 checkpoint reader handles three lattice records whose map forms require `n_elements`, `n_bytes`, and a 2,048-byte `hash` on the selected byte-sequence path, giving a reconstruction concrete field-presence, duplicate, and size decisions for restoring the state.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 hl-node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `3324e50333042b391312515e542279ca21f63dc8`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only.
- Claim status: observations and bounded control-flow inferences, not a complete codec or compatibility claim.
- Scope included and excluded: the two selected nested reader paths, their field classifiers, selected failure paths, and fixed-size byte readers. The contextual file-loader call sites only establish the connection; their enclosing functions are not reanalysed. Excluded are the complete marker grammar, arbitrary string decoding, hash algorithms, durability, other releases, and execution of captured programs.

## Reproduce

From the repository root, with Python 3.12.3, its standard library, and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 tools/lthash_read94.py --out research/work-items/RE-009-lthash-read-94
python3 -m unittest tests.test_lthash_read94
(cd research/work-items/RE-009-lthash-read-94 && sha256sum -c MANIFEST.sha256)
```

`records.json` is the complete generated output. The generator first checks the binary digest, reads ELF sections and actual FDE records through the shared parsers, excludes NOBITS from file-backed VA resolution, and checks fixed instruction windows, direct call displacements, relative table entries and diagnostic references. It does not invoke external programs or run the binary. GNU objdump 2.42 was used only for human inspection of bounded instruction windows; its output is not generator input. The addresses below are linked ELF virtual addresses; FDE ends are exclusive. An FDE is an unwind-described extent, not by itself a full function-boundary proof. Analysis covers selected decisions, not every instruction or possible entry.

## Evidence

The already studied checkpoint construction path formats the `/lt_hashes.json` template at call-site vicinity `0x3269b8a` and invokes a loader at `0x3269bc2`. Within that loader, contextual sites `0x3c1606e` and `0x3c1615c` call the JSON entry and the MessagePack-style outer reader respectively. The generator checks the template, call bytes, and that those two sites lie in the called loader's FDE. These contextual sites identify the path; the loader is not claimed as a new function. Prior work `RE-009B-lt-hashes-format` describes the writer's three top-level names, while leaving nested value encoding and reading unresolved.

| Selected reader role | FDE extent |
| --- | --- |
| MessagePack-style outer | `0x2dba370..0x2dbbc6e` |
| MessagePack-style nested value | `0x2bb0b50..0x2bb22a4` |
| MessagePack-style fixed byte sequence | `0x2b0cd60..0x2b0d746` |
| Outer and inner field classifiers | `0x37a4a90..0x37a4b29`, `0x37a4b30..0x37a4ba1` |
| JSON entry and outer | `0x2fe3140..0x2fe3255`, `0x30c2a20..0x30c357f` |
| JSON sequence helper and nested value | `0x300ad20..0x300aea1`, `0x315f920..0x316057e` |
| JSON fixed byte value | `0x3094730..0x3094b6d` |

The records carry the authoritative FDE endpoints, selected bytes, and body hashes. Roles are inferred from the call and data flow; no ownership is inferred from an FDE alone.

### Outer record

The outer classifier checks length and contents, producing these tags. Its relative dispatch table is read directly from file-backed ELF bytes. The fourth tag selects an unknown-field helper; its complete behavior is not established.

| Field | Tag | Map arm | Duplicate branch target |
| --- | ---: | --- | --- |
| `accounts_hash` | 0 | `0x2dbb6c6` | `0x2dbbb38` |
| `contracts_hash` | 1 | `0x2dbb812` | `0x2dbbb72` |
| `storage_hash` | 2 | `0x2dbb754` | `0x2dbbb55` |

Each arm tests its own presence slot before calling the same nested reader. Each duplicate target supplies the corresponding field name to the `duplicate field` diagnostic. Missing-field routes supply the same three names to `missing field`. Each successful nested value is copied as `0x810` bytes; the assembled outer value is copied as `0x1830` bytes. The array path calls the nested reader three times, checks count 3 after the third value, and takes a separate error route for another count. That observation is conditional on the child decoders' results; it is not a claim that all three-element arrays succeed.

The JSON outer parser has three calls to its own nested reader for map values and three to a sequence helper. Its selected map completion checks all three presence flags; selected duplicate and missing routes reference the same names. The JSON entry checks remaining bytes after success against a bit mask whose set positions are 9, 10, 13 and 32, and creates an error for other trailing bytes. This is a trailing-byte observation, not a complete JSON grammar.

### Nested value and failures

The nested classifier yields tag 0 for `n_elements`, 1 for `n_bytes`, 2 for `hash`, and 3 for other names. Its dispatch table sends the three recognized names to distinct presence checks. Repeating a recognized name reaches a `duplicate field` diagnostic, and completion without a required name reaches a `missing field` diagnostic. The two scalar arms call the same scalar reader. The `hash` arm calls the fixed-byte reader and propagates its error result. The success path copies `0x800` bytes and then places two qwords at offsets `+0x800` and `+0x808` of the `0x810`-byte value. These offsets describe the in-memory result, not fixed offsets in a serialized file.

For the selected MessagePack-style sequence arm of the fixed-byte reader, each accepted child contributes one byte, the loop stops at `0x800`, and the subsequent comparison requires the input count to equal `0x800`; the unequal arm constructs an error carrying that expected count. The JSON fixed-byte reader selects between a quote-led string path and a bracket-led array path. The array path reads byte results in a loop bounded by `0x800`; the string path tests the helper's returned length against `0x800`. The selected failure branch is retained in `records.json`. The conversion performed by the string helper and alternate marker forms remain unresolved, so no hex, base64, or general MessagePack bin-format claim is made.

The nested sequence path also checks a count of 3 after its selected children. The JSON nested reader separately refers to the same three field names and uses the fixed-byte JSON reader for `hash`. The three name matches, scalar/helper edges, payload size checks, and result-copy offsets support treating the two paths as readers for corresponding nested records. Their full accepted input languages and error types are not proven identical.

### Inferences and boundaries

The names and the contextual call chain connect the selected readers to the stored lattice-state value. `accounts`, `contracts`, and `storage` are treated as field labels, not proof of what entries feed the accumulators. Size and field checks are static control-flow observations: they do not prove that a checkpoint was present, successfully loaded, or compatible with any other release. A branch in a byte-pinned window is interpreted at an instruction boundary verified by manual disassembly; no general disassembler is embedded in the generator.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler, build, compiled-byte comparison, masks, helper closure, actual database fixture, and target execution: not yet measured. The input fixture is the authenticated binary alone. The 12 focused unittest methods include changed instruction windows, altered call opcode and destination, altered conditional destination, altered relative table target, wrong digest, wrong field names, NOBITS, unmapped and crossing-section addresses. These controls test evidence extraction, not the native reader's runtime behavior.

## Results and limitations

The record pins 10 FDE-described extents, 19 selected call sites, two four-entry relative tables, 6 duplicate branches, 20 selected RIP references, and 26 selected instruction windows. They are selected evidence, not a census of readers or callers. No full-scope milestone gate is requested. No live state data, chain access, network, binary execution, or synthetic binary transplant was used.

Next question: resolve the quoted-string conversion and the full non-map nested encoding, then validate boundary and corruption cases against an authorized offline fixture.
