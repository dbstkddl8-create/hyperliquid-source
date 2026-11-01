# RE-004: scaled two-lane value readers in node #94

This packet establishes that two previously unclaimed readers use a 10^14 divisor, with one reader rounding a product twice before a further conversion, enabling a reconstruction to preserve the intermediate rounding and overflow checks.

- Component ID: RE-004, quantities and rounding (BOLE-related lane values).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `3324e50333042b391312515e542279ca21f63dc8`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23` is an unlicensed lead, not copied implementation.
- Claim status: observation for FDEs, bytes, branch destinations, call slots, result stores and constants; inference for the quotient helper contract and BOLE field names; unresolved items below.
- Scope included and excluded: two FDE-bounded readers, their local lookup and arithmetic decisions, four indirect calls and 29 selected conditional branches. The called quotient and conversion helpers, callers, indirect-call census, target execution and other releases are excluded. FDEs establish unwind ranges, not complete function discovery.

## Reproduce

From the repository root, on Linux x86-64 with Python 3.12 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/bole_scaled_exposure94.py --out research/work-items/RE-004-bole-scaled-exposure-94
python3 -m unittest tests.test_bole_scaled_exposure94
(cd research/work-items/RE-004-bole-scaled-exposure-94 && sha256sum -c MANIFEST.sha256)
python3 tools/bole_scaled_exposure94.py --out <tmp-dir>
```

The input digest is checked before parsing. The program reads ELF bytes and the shared `tools/elf_index.py` and `tools/fde_extents.py`; it does not execute the binary, invoke binutils or access a network. `evidence.json` retains the complete selected FDE bytes, their SHA-256, FDE records, file offsets, selected branch encodings and call relocations. `steps.tsv` groups the bytes by local decision, `slice-coverage.tsv` records interpreter visits, `cases.tsv` contains results, and `summary.json` contains bounds and counts. The interpreter reads exact instruction encodings but stubs division and stops before the final conversion helper; none of these results is captured node execution. Analysis is limited to the selected ranges.

## Evidence

Coordinates below are ELF virtual addresses; file offsets and raw bytes are in `evidence.json`. The ranges are `0x28db270..0x28db4dd` (621 bytes) and `0x394b660..0x394b7d3` (371 bytes). Each range matches its own FDE and locked byte hash. Addresses are for this digest only.

Both use `mul` to form a full 128-bit product, then the call slot `0x576e1a8`, relocated to `0x565f5a0`. They pass a 128-bit dividend and the nonzero 128-bit denominator 10^14. The conditional interpretation below assumes that callee returns the exact unsigned 128-bit quotient. The helper is outside this packet; its division role and the separate RE-004 u128-division packet are corroboration, not an independent proof here. The immediate bytes for the denominator occur once in the first reader and twice in the second.

For `p = a*b`, `q = floor(p / D)`, `r = p - q*D`, and `D = 10^14`, the local code tests the rounding byte and, when nonzero, reconstructs `q*D` in two limbs, subtracts it from the original product, and adds one to the quotient if either remainder limb is nonzero. The low-word addition propagates carry into the high word. A nonzero high quotient gives status 3; the accepted value is the low word. This interpretation is conditional on the helper contract, and on the byte being a Boolean. It follows the instruction order and does not rely on the inferred reference implementation.

### One-stage reader

`0x28db270` searches one tree, falling back to a second tree if the key is absent; an absent key in both leads to status 9. After finding that row it searches another tree: an absent row gives a successful zero. A found pair supplies two 64-bit words to the 10^14 operation. The row field selected by `(flag ^ 1)` is at offset `0x58` with stride `0x20`; the other value comes from the second tree. The result is returned at output `+8` with tag byte 0, or error tag byte 1 with status at `+1`. The first reader tests `bpl`, the low byte of its flag.

On the fitted quotient path, a test of the second tree value against zero and the quotient against nonzero can produce status 2 in the instructions. Assuming exact unsigned multiplication and division by positive D, this edge is unreachable: if that factor is zero then the product and rounded quotient are zero. The conditional branch still appears in the evidence.

### Two-stage reader

For Boolean `flag`, `0x394b660` selects lane `flag ^ 1`: it loads `a` from its first input at `+8 + 0x10*lane` and `b` from another record at `+0x58 + 0x20*lane`. It computes `q1 = round(a*b/D)` and, only if it fits u64, computes `q2 = round(q1*c/D)` for the passed 64-bit `c`. Both stages use the same rounding flag and each independently checks the high quotient word. The first flag test uses the 32-bit register and the second uses its low byte; the Boolean restriction is material. The zero-factor/status-2 checks after each stage are likewise unreachable under the exact-division assumption.

After both stages the reader passes `q2` and other arguments to slot `0x57738b0`, relocated to `0x32815f0`; it writes the returned word at output `+8` only when bit 0 of the helper return is set. Otherwise it stores status 7. The helper's own exponent, bounds and failure behavior are outside this packet; the separately published `RE-004-spot-wei-scale-family-94` examines it. Earlier failure status 3 prevents the helper call. The `cases.tsv` helper-success flag is a controlled model input, not a claim about the helper's reachability for arbitrary arguments.

The two rounding points cannot generally be collapsed. For `a=2`, `b=c=3*D/4`, floor at each stage gives `q1=1`, `q2=0`, while flooring the exact combined fraction gives 1. For `a=1`, `b=c=D+1`, ceiling at each stage gives `q1=2`, `q2=3`, while ceiling the combined fraction gives 2. Both examples are mathematical consequences of the byte-backed sequence and appear in `cases.tsv`.

### Width and failure boundaries

Each factor is u64, so `a*b < 2^128`. The maximum rounded quotient of such a product divided by D also fits u128, so incrementing it cannot wrap the full 128-bit quotient. For floor, status 3 occurs exactly when `a*b >= D*2^64`; for ceiling it occurs exactly when `a*b > D*(2^64-1)`. These bounds hold for every u64 operand pair, conditional on the assumed quotient contract. The model includes an attainable product just above the ceiling bound but below the floor bound, so floor fits and ceiling fails. Intermediate u64 fit is checked before the second product; a combined wide calculation cannot reproduce that error order.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo lock, compiler flags, build, raw comparison, normalizations or equivalence measurements exist. No binary execution was performed. `run_first_slice` and `run_second_slice` interpret the encoded multiply, subtract, carry, conditional branch and status instructions in the two arithmetic slices. Both stub the quotient call with exact integer division; the second treats the selected memory word as an input and stops before the final helper. `machine_scale` separately models the limbs, while `scale` computes an arbitrary-precision quotient/remainder formula. Their agreement is a consistency check, not an independent target oracle. Negative controls cover a wrong input digest, altered immediate with a recomputed digest, out-of-range and NOBITS addresses, incorrect branch/call opcodes, absent relocation, out-of-domain arguments, corrupted instructions in both slices, an incorrect stubbed quotient, overflow boundaries and both helper outcomes.

## Results and limitations

`summary.json` records 338 single-stage interpreter runs (33 of 34 defined slice sites reached), 3,420 two-stage interpreter runs (75 of 75 defined slice sites reached), 338 comparisons of the two arithmetic models and 29 selected branch records. The two-stage grid runs each arithmetic case with both modeled helper outcomes; those outcomes are not executed by the interpreter. The one unreached first-slice site is the status-2 store, reached by the deliberately incorrect quotient control. Eleven unit tests pass without skips. Slice-site coverage does not establish full-function coverage or caller reachability. The full 128-bit bounds above are mathematical, conditional on the quotient helper; sample comparisons do not prove the binary's complete behavior.

The reference's 10^14 scale and BOLE exposure/asset field names are consistent leads, but the exact quantities, units, ownership, validity of flag values outside 0 and 1, complete tree invariants and the downstream helper effects remain unestablished. No milestone gate is requested. Next question: recover a non-overlapping producer of the two lane words and connect their units to the downstream conversion.
