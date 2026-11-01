# RE-007: positive per-DEX risk-row collection on node #94

This packet establishes the ordered mode gates, per-DEX eligibility scan, positive-result filter and nested output layout for one risk-collection path, allowing a reconstruction to build the same candidate rows without treating a zero or negative helper result as a candidate.

- Component ID: RE-007, clearinghouse risk.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `3324e50333042b391312515e542279ca21f63dc8` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference tree is an unlicensed lead, not recovered source.
- Claim status: observations are machine bytes, FDE ranges, branch conditions, layouts and call edges; the business names below are inference. Unresolved behavior is listed under Results and limitations.
- Scope included and excluded: three previously unclaimed FDEs `0x251c9d0`, `0x24fdfe0`, `0x21bc7c0`; the risk helper at `0x3708bf0` is an identified edge only. The helper body, allocation internals, caller's parallel scheduling, and all live-node behavior are excluded.

## Reproduce

From the repository root, Linux x86-64 and Python 3.12.3 were used. The tool reads the authenticated ELF and the repository's shared ELF/FDE parsers; it invokes no external program and does not load or execute the captured node. It checks the full input digest, exact FDE extents, hashes of all three bodies, selected conditional targets, all 18 instruction-start call encodings, their direct targets or relative relocations, and the source Location record before writing:

```sh
python3 tools/artifacts.py verify
python3 tools/positive_risk_scan94.py --out research/work-items/RE-007-positive-risk-scan-94
python3 -m unittest tests.test_positive_risk_scan94
```

For an independent comparison, run the tool with `--out <tmp-dir>` and compare its four generated files to the corresponding files here. The tool only writes `evidence.json`, `branches.tsv`, `function-bytes.tsv`, and `decision-windows.tsv`; it does not write this README or the manifest. The branch table holds 27 selected instruction-start conditional branches, the byte table holds every byte of the three FDEs, and the window table provides 11 address-bound excerpts for the decisions and outputs. All paths in the output are repository-relative or sanitized suffixes.

## Evidence

Coordinates are ELF virtual addresses, with file offsets explicitly marked. The unwind records describe ranges and do not alone prove source-level function boundaries. The 1,497 bytes in these three ranges have no operand masks. Byte and branch records are complete for the stated ranges and selected branch sites respectively; this is not a whole-program call census.

| Observed role | FDE range, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| per-DEX filter | `0x21bc7c0..0x21bc94e` | `0x21bb7c0` | 398 |
| one-user collector | `0x24fdfe0..0x24fe266` | `0x24fcfe0` | 646 |
| batch fold | `0x251c9d0..0x251cb95` | `0x251b9d0` | 453 |

The fold calls the collector at `0x251ca72`. The collector calls the filter at `0x24fe0b7` and `0x24fe16b`. The filter calls through slot `0x57738b8` at `0x21bc867`; the slot's `R_X86_64_RELATIVE` relocation names `0x3708bf0`. `evidence.json` records all 18 instruction-start calls across the three FDEs, including the calls on allocation and failure or cleanup paths; each direct target or relative relocation is checked. Their bodies are outside the packet. Names such as allocation and growth describe call context rather than recovered symbols. A Location referenced by the filter's index-failure route at `0x21bc927` resolves to suffix `l1/src/perp_meta.rs:194:38`; the original Location pointer is relocated. This supports the metadata attribution, not a function name or the contents of the called helper.

### Outer admission and collection

The collector reads a byte at `+0x3c` from its fourth argument and two bytes at `+0x118` and `+0x119` from the object reached through its second argument. These are raw field offsets, not recovered type names. The following table describes whether it proceeds to scan the DEX array:

| Fourth-argument byte | Condition to scan |
| --- | --- |
| 0 or 1 | Never |
| 2 or 3 | byte `+0x119` is zero |
| 4 or above | byte `+0x118` is zero |

A refused entry writes the `0x8000000000000000` sentinel at output `+0x18`. An allowed entry scans the row array in order, each row 752 bytes apart. The first present filter result starts a vector; remaining present results are appended in the same array order. If none is present, the sentinel is returned and no result vector is emitted. The first successful row causes an allocation of 64 bytes for four 16-byte entries; later capacity exhaustion calls a growth helper. An allocation failure enters the allocator failure path. The normal present result contains the 20 bytes supplied at the third argument and a vector represented at output `+0x18`, `+0x20`, `+0x28` as capacity, pointer and length. Each vector item consists of the DEX row's `+0x30` word followed by the signed positive helper result.

The batch fold consumes 16-byte input pairs and calls the collector once per pair in order. It skips the sentinel and appends every present result to its accumulator in 48-byte records. It returns the accumulator including its supplied context word. No sort is visible in this bounded fold; upstream ordering and parallel merging are not established.

### Per-DEX decision sequence

For a row, the filter takes the nested input kind byte, a 20-byte value, and a row pointer. It first returns no item if **all** of these are true: the kind byte is 2, row `+0x30` is at most 109, row `+0x230` is not 3, and the 20-byte input equals the 20 bytes reached through row `+0x208`, at offsets `+0x74` and `+0x84`. An id of 110 does not take that shortcut; neither does a different byte in the compared 20 bytes.

Otherwise it checks the asset table. The row count is at `+0x10`, the table pointer at `+0x08`, and each metadata row is 48 bytes. The encoded starting id is `row_id * 10000`; the observed multiply checks unsigned overflow. The loop checks the quotient and local index and reads byte `+0x28` of each metadata row. A zero byte immediately returns no item; nonzero advances to the next row. After all rows pass, including an empty table, the function calls the risk helper with the copied 20-byte value, raw mode 4 and the byte at row `+0x2ed`. It emits `(row_id, helper_result)` only if the helper's signed return is strictly greater than zero. A zero or negative result emits no item.

The multiplication-overflow route is conditional: a nonempty table reaches an arithmetic failure; an empty table still proceeds to the helper. An encoded id whose quotient disagrees with the DEX id, or whose local index is out of bounds, reaches the Location-backed failure route. An increment wrapping below the starting id reaches a separate failure. Failure paths are static observations; this packet does not execute them.

For example, the following human-readable excerpt is from the authenticated target, with Intel syntax; generated files contain raw bytes rather than disassembler text:

```text
21bc862: mov edx, 0x4
21bc867: call QWORD PTR [rip+0x35b704b]  # slot 0x57738b8
21bc86d: test rax, rax
21bc870: jle 0x21bc885
21bc872: mov QWORD PTR [rbx+0x8], r14
21bc876: mov QWORD PTR [rbx+0x10], rax
```

### Interpretation

The row layout, the asset-index failure Location, the identified risk helper and its mode argument support interpreting this as collection of positive per-DEX margin-like capacity for an account. The names DEX, asset and account are inferences from that context; the instructions alone establish the data flow and comparisons. This does not establish a withdrawal rule, the helper's exact formula, or the economic meaning of mode 4. The raw helper return is signed; its wei/notional unit, decimal exponent, price source, rounding and overflow behavior inside the helper remain unresolved.

## Implementation and comparison

Rust implementation: not yet implemented. Raw or normalized compiled comparison: not yet measured. The full FDE bytes are retained with no normalization. The generator validates selected boundaries and static call edges, rather than interpreting or executing target instructions. No target-derived runtime fixtures are claimed. The unit tests include a changed input hash, a flipped body byte, every recorded condition inverted, a changed call opcode, a corrupted relocation type, an altered immediate opcode, and out-of-range and NOBITS address controls.

## Results and limitations

Eight focused unittest methods pass with no skips. They bind three FDEs, 18 call edges and 27 selected conditional branches; the condition inversion control covers all 27 branch records. The tests validate byte binding and parser rejection, not the full semantic rules by differential execution. The full node, later release, data/vtable closure, helper body, upstream caller, all exceptional cleanup paths and actual chain state remain out of scope. The default account identity, the two flag fields, the economic unit and the reason for the 109 boundary are unknown. No milestone gate changes are requested.

Next question: establish the producer and unit of the signed result at the already identified risk-helper edge, then connect an independently confirmed upstream caller to determine when this collector is used.

The artifact verification passed. The catalogue check passed in a temporary validation copy with the authenticated artifacts placed inside that copy. In the original checkout the same check rejects the externally linked artifact paths before catalogue comparison. No tracked input was modified to change that behavior.
