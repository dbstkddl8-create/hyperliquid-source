# RE-007: size-decimal update gate and asset-index construction

Node #94 changes a perp size-decimal byte only after building an asset-keyed collection and finding that asset's nested map empty; this establishes the write gate and its place in the vote path for a reconstruction.

- Component ID: RE-007, clearinghouses and risk; size/price precision metadata.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `d3af75257a396c85d20857f421c370ddb8cb40e5` / `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim status: observation for the selected bytes, decoded branches and relocations; inference for field names and row semantics; unresolved for the collector's full contents.
- Scope included and excluded: the selected vote arm, its list-size guard, updater, collector, two collection-initialization helpers and nested-map writer. The full vote dispatcher, name resolver, insertion allocation internals and downstream price calculations are outside this packet. The other two vote copies are checked at their selector, list guard and updater edges; their full arm bodies are excluded. This is a static, limited-range analysis, not a complete risk-engine map.

## Reproduce

From the repository root, Linux x86-64, Python 3.12.3; the extractor requires only the standard library and the repository's shared ELF/FDE readers. It authenticates the target before analysis and does not execute it. GNU objdump 2.42 was used only to inspect the instruction-aligned windows shown below; the generator and tests do not call it or parse its output.

```sh
python3 tools/artifacts.py verify
python3 tools/risk_size_decimal_update94.py --out research/work-items/RE-007-size-decimal-update-94
python3 -m unittest tests.test_risk_size_decimal_update94
python3 tools/catalogue.py --check
```

The generator writes `evidence.json`, `decisions.tsv` and `seeds.tsv`. `MANIFEST.sha256` records packet file hashes. The SHA-256 of each complete FDE extent is in `evidence.json`, as are the exact byte windows, decoded branch destinations, call encodings and relative relocation slots. No operands are normalized. `decisions.tsv` models the final gate under specified collector results; `seeds.tsv` models small initializer intervals and overflow. Neither is a captured execution.

## Evidence

All addresses below are ELF virtual addresses. FDE extents are unwind-described ranges, not proof of complete function boundaries. The generator selects file-backed sections only and checks seven FDEs:

| Role | FDE range |
| --- | --- |
| Vote list limits | `0x1e801c0..0x1e802ba`, `0x445c750..0x445c84a` |
| Update one asset | `0x36ff3c0..0x36ff4e2` |
| Collect asset rows | `0x3705690..0x37067a9` |
| Build initial tree | `0x3315e90..0x3316087` |
| Generate initial rows | `0x3bdc1b0..0x3bdc2fd` |
| Insert or replace inner-map entry | `0x33a83d0..0x33a869a` |

The selected jump-table word at `0x3dd1dc` dispatches normalized selector 9, corresponding to raw tag 27, to `0x2357565`; the other two selector words resolve to `0x4cabe1e` and `0x4cb47ae`. The inferred reference calls this `NewSzDecimals`; that name is a lead, while the dispatch is observed. At `0x2357586` the arm calls the list limit. Both checked limit implementations accept count at most 10,000 and returns `0x186`; above that it returns `0x143` and drains owned entries. The arm iterates accepted rows. A name of 101 bytes or more reaches `0x143`; otherwise the resolver's non-`0x186` result is copied to the output. After each successful resolution, the arm immediately calls the common updater. Consequently, an error on a later row does not undo earlier completed writes in this arm; the resolver and allocator behavior are outside the claim.

The indirect call at `0x23576be` resolves through `R_X86_64_RELATIVE` slot `0x5773da0` to the updater. Two other call sites, `0x4cabf77` and `0x4cb4907`, resolve through the same slot. The updater calls the collector at `0x36ff3dc`, through slot `0x5775dc0`. The collector calls the tree builder at `0x37056d4`, and the builder calls the row generator at `0x3315ea3`. All these call targets are decoded from bytes; indirect targets also require the matching ELF relocation.

### Initialization and collection

The row generator reads an index interval, allocates 32-byte rows, and starts each row with `dex * 10000 + index`; the inner-map root and count start at zero. It has distinct overflow branches for multiplication and addition. The collector supplies the interval beginning at zero and ending at the metadata row count. Thus ordinary metadata rows have seeded keys even before collected records are added. The builder materializes the keyed tree from those rows.

The collector chooses on the byte at clearinghouse `+0x1a0`. In one branch it processes a 72-byte source-record sequence and exits that sequence on a word equal to 2. In the other it traverses user/position-shaped structures, copies 64-byte records and skips a record when its word at `+0x10` is zero. Both paths call the same inner-map writer `0x33a83d0`: it compares 20-byte keys and stores 64-byte values. On an equal key the old 64-byte value is returned and replaced; otherwise it inserts a new entry and increments the count. The words at clearinghouse `+0xf8` and `+0x158` correspond to the user table and active-user set documented in prior risk evidence; their names and the identity of the copied record as a position are inferences. The collector's full domain and completeness have not been proven. In particular, an empty inner map does not by itself prove the absence of open orders, positions or other exposure in all modes.

### Final gate and failure branches

The updater takes a clearinghouse pointer, an asset id and a byte. Its lookup precedes both metadata bounds checks:

| Condition after collection | Observed action |
| --- | --- |
| Key absent | Drop the temporary tree and return without the metadata store. |
| Key present, inner-map count nonzero | Drop the temporary tree and return without the metadata store. |
| Key present, inner-map count zero; asset quotient differs from dex id | Construct a `0x60` tagged value and call the reporting helper. |
| Key present, inner-map count zero; local index at least the row count | Take the same `0x60` reporting branch. |
| Key present, inner-map count zero; both metadata checks pass | Store the supplied low byte at metadata row `+0x2a`, with stride 48. |

The arm does not read an updater return value at the call site. This packet does not infer whether the reporting helper aborts, logs, or returns under every environment. The byte at row `+0x2a` is inferred to be size decimals from the existing price-scaling evidence, not from a symbol in this function. The updater itself contains no separate byte-range test before the store; admission elsewhere is not established.

The updater obtains quotient and remainder using multiplication by `0x346dc5d63886594b`, high-half extraction and a shift by 11, followed by subtraction of quotient times 10,000. The generator reads both the magic and divisor from the instruction bytes and proves the quotient identity over all unsigned 64-bit inputs. The initializer uses the same divisor. The eight decision rows exercise precedence and the two sides of the metadata boundary, with the collector result explicitly supplied.

For human inspection, selected instructions are:

```text
36ff453  cmpq   $0x0,0x58(%rax,%rdi,1)
36ff459  jne    36ff4b0
36ff46b  shr    $0xb,%rdx
36ff46f  cmp    0x30(%r15),%rdx
36ff47f  sub    %rcx,%rax
36ff482  cmp    0x10(%r15),%rax
36ff494  mov    %bl,0x2a(%rcx,%rax,1)
```

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker flags, two-build result, native-byte comparison and normalization masks: not yet measured. The generator validates fixed instruction windows and models the last decision; it does not emulate or execute target code. It binds four indirect call sites and seven direct calls, but does not close the transitive helper, relocation or data graph. Inputs are the authenticated artifact and artificial values in `decisions.tsv`, not captured user fixtures. Negative controls reject a bad digest, altered instruction and call bytes, out-of-range addresses, NOBITS-only addresses and model values outside their widths.

## Results and limitations

The retained extractor checks 28 instruction windows, 15 conditional-branch destinations, seven FDE extents, four relocation-backed call sites, seven direct calls, three jump-table entries, eight decision examples and six seed examples. Ten unit tests pass without skipped tests. These are selected controls, not function, behavior or binary-equivalence coverage denominators. No reviewed full-component gate is requested. The other collector mode, the complete row provenance, allocator failures, the resolver and the reporter remain unresolved. Next question: establish the exact provenance and completeness of each collector mode's per-asset maps, including how pending orders and position records contribute.
