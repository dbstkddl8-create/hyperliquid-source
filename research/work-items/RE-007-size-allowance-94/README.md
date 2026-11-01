# RE-007: directional size allowance and keyed lookup in node #94

This packet shows how a two-word size limit is raised by a direction-dependent reduction allowance, including the two-key lookup's missing-entry behavior and the signed-value failure paths; a reconstruction can preserve this adjustment separately from the still-open computation of its input limits.

- Component ID: RE-007, clearinghouses and risk.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `3324e50333042b391312515e542279ca21f63dc8` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference tree is a lead, not implementation source.
- Claim status: byte observations and control-flow deductions; position, allowance and risk labels are inferences. Unit and cap-provider semantics remain unresolved.
- Scope included and excluded: two selected FDE ranges and their connecting relocation; the external cap provider, hash helpers, panic implementation and caller are boundary dependencies. No complete RE-007 path or component gate is claimed.

## Reproduce

From the repository root, with Python 3 and the captured file installed at `artifacts/node/94/hl-node`:

```sh
python3 tools/risk_size_allowance94.py --out research/work-items/RE-007-size-allowance-94
python3 -m unittest tests.test_risk_size_allowance94
python3 tools/risk_size_allowance94.py --out <first-output-dir>
python3 tools/risk_size_allowance94.py --out <second-output-dir>
diff -r <first-output-dir> <second-output-dir>
```

The generator uses only Python's standard library and `tools/elf_index.py` and `tools/fde_extents.py`; it verifies the complete target SHA-256 before it reads ELF facts. It checks both selected bodies and key instruction sequences against pinned bytes, and obtains the connecting indirect call's target from the ELF relative relocation. It writes `evidence.json` and `cases.tsv` deterministically. GNU objdump was used for human instruction interpretation, never by the generator or tests. The captured executable is never run. The sample table is a scalar model, not target execution or a differential test.

## Evidence

All code addresses are ELF virtual addresses; `evidence.json` also records file offsets, full bytes and SHA-256 of both selected FDE ranges. The unwind ranges are `0x2a1e9e0..0x2a1eb16` and `0x370e870..0x370ea4a`; FDEs are not a complete function census or proof of all boundaries. The connecting instruction at `0x2a1ea74` calls through slot `0x5775340`, whose `R_X86_64_RELATIVE` addend resolves to the second range. An earlier call at `0x2a1ea3e` supplies two signed words and remains a boundary. No relocation or instruction bytes are masked.

### Observed decision chain

Let `p` be the signed word loaded through the input context at `0x2a1ea7e`, `s` be the incoming low-byte selector, and `a`, `b` the two words returned by the earlier call. The lookup returns two words; the adjustment uses the second, `q`. The selected caller supplies `s` to both calls. The following is an interpretation of the pinned instruction sequence, not independently executed target behavior:

| Order | Condition | Observed control flow |
| --- | --- | --- |
| 1 | `p == 0` | Skip the subtraction, use zero as the adjustment. |
| 2 | `p > 0` and `s == 1`, or `p < 0` and `s == 0` | Compute `abs(p) - q` after the signed checks below. |
| 3 | Other sign/selector combinations | Use zero as the adjustment; do not test `q` for negativity. |
| 4 | Matching sign and selector, with `p == i64::MIN` or `q < 0` | Transfer to the common non-returning error arm at `0x2a1eaf1`. |
| 5 | `a < 0` or `b < 0` | Transfer to the same error arm, even when the adjustment was skipped. |
| 6 | Otherwise | Return `(max(a, adjustment), max(b, adjustment))`, using signed comparisons. |

The subtraction in step 2 can be negative: a value of `q` greater than `abs(p)` does not itself cause failure. Since both returned input words must be nonnegative, a negative adjustment cannot lower either returned word. The model restricts `s` to 0 or 1; the lookup itself uses the low byte as an index and contains no selector bounds check. It is not safe to extrapolate the model to arbitrary selector bytes.

### Lookup

The second FDE first checks an outer table and compares a 20-byte key, then checks an inner table and compares an eight-byte key. The observed outer and inner bucket strides are `0x50` and `0x40`; lookup uses hash helpers whose implementations are outside this packet. An empty outer table, an absent outer key, an empty inner table, or an absent inner key reaches a return with both words zero. A found entry loads the two words from offsets `-0x38 + 8*s` and `-0x28 + 8*s` relative to the computed inner control pointer. Those are code-level offsets, not a complete independently established struct layout. `evidence.json` records 14 selected conditional branch encodings and their relative targets; its raw bodies permit review of the rest of both ranges.

### Interpretation and units

The existing `RE-006-match-resting-order-94` packet identifies the earlier slot as a size-cap provider and infers its first result as a maximum-position size and its second as a margin size from separate status texts. Combined with that prior inference, the signed-word and direction behavior here is consistent with preserving a position-reducing size allowance even if either input limit is smaller. The labels `position`, `side`, `selected` and `size` are therefore useful hypotheses, not independently proven source names. This packet does not determine whether `q` is reserved order size, prove a buy/sell mapping, establish a price scale, or prove that the two results have identical units. It does not prove the external provider's formula. `cases.tsv` uses raw signed integer words and deliberately makes no decimal, wei, rounding or price-unit claim.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Target/source build, Cargo lockfile, compiler flags, two-build comparison, raw or normalized source comparison, relocation and data closure: not yet implemented or measured. There are no masks. The scalar model covers 17 selected sign, selector, ordering and boundary combinations; those expected outputs derive from the manually interpreted pinned instructions, not from running the target. Tests also reject a wrong target digest, corrupted arithmetic and lookup bytes, an invalid branch opcode, an unmapped address, a NOBITS address, and invalid model inputs. The model does not execute a node instruction or exercise the hash table on target data.

## Results and limitations

The reproducible record contains two FDE ranges, one resolved connection, 14 conditional branch records and 17 model cases, including four modeled error cases. These are selected counts, not function-coverage or completion denominators. The semantic names, the hash helpers, full call chain, external provider, exact failure implementation, side-index invariants and price/size units remain open. No RE-007 completion gate is requested. Next question: establish the provenance and units of both input words and the selected lookup word, then test their composition with the provider against an authorized isolated target harness.
