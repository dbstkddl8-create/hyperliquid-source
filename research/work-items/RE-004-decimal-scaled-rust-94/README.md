# RE-004: reconstruct the established Decimal-to-scaled-u64 value relation

- Component: quantities/rounding, bounded Decimal conversion.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: main `3324e50333042b391312515e542279ca21f63dc8` plus shared minimal
  CI prerequisite `516b1e3a` / #1295, not additional contribution credit.
- Established evidence: merged PR #94 and the unchanged
  `RE-004-decimal-scaled-u64-94` packet / `tools/decimal_scaled_u64.py`.
- Outcome: independently authored Rust value/note-request projection in the
  real dependency-free `src/node94-fixed-point` component. No inferred code
  copied, dependency invented, original ABI recovered or full gate requested.

## Gap and qualified boundary

The existing library implements eight accepted arithmetic families but not
this established Decimal relation. This change implements the complete bounded
arithmetic family together: exponent guard, 96-bit product reduction, all mode
bytes, strict tolerance, half-even rounding, remaining-fraction/sign rejection,
the exact cap and the opaque note request. It does not split these into quota
items or propose an unapproved production quantity policy.

Entry is the actual FDE `0x3750350..0x3750604` (692 bytes / 190 decoded
instructions), in ELF virtual coordinates. The old `coverage.tsv` retains eleven
evaluated entry/helper FDEs with reached counts, not whole-program coverage.
Multiply, rounding, fractional-part, comparison and add/subtract helpers are
captured instructions in the independent evaluator; the Rust recovers their
composed scalar relation, not separate original functions or machine bytes.
The old evidence retains target identity, relocations, constants and 35 entry-
slot call sites. Imported captures, reference pins and old evidence stay intact.

The native input is observed as four words (flags/high/low/middle). This API
accepts independent numeric parts: a sign boolean, mantissa below `2^96`, scale
`0..=28`, mode byte and exponent byte. Reserved flags and malformed parts remain
outside scope. `UnsupportedDecimalParts` refuses them as a separate safe API
policy; neither original validation behavior nor Rust object layout is claimed.
The outcome projects observed success/rejection without naming the native
`0x186/0xa8` enum. Units and production caller ownership remain unknown.

The note target `0x14385c0` through slot `0x576f488` is **not** recovered. The
accepted evaluator models a normal-return opaque call, records its occurrence
and conservatively clobbers caller-saved registers/flags. Rust returns a boolean
request without performing its external side effects. Both value and note
projection assume normal callback return. Panic/unwind and complete-function
runtime equivalence remain open.

## Fresh pre-Rust instruction replay

Commit `85f3cf91` freezes `PRE-RUST-REPLAY.json` before `decimal_scaled.rs`
exists, including original library/evaluator hashes. A fresh **25,325-case**
replay took 28.729 seconds. All four generated evidence/fixture/coverage/call-
site files exactly match the accepted originals and their recorded hashes.
Reproduce without overwriting them:

```python
# Repository root; PYTHONPATH=tools.
from pathlib import Path
import decimal_scaled_u64 as original
data = original.TARGET.read_bytes()
original.check_target(data)
outputs = original.generate(data)
accepted = Path('research/work-items/RE-004-decimal-scaled-u64-94')
for name, text in outputs.items():
    assert text.encode() == (accepted / name).read_bytes()
```

This is separately authorized **offline Python captured-instruction evaluation**,
and must not be described as no emulation. Neither a native captured node/visor
nor Unicorn is launched. Counterfactual evaluation uses the same authorized
Python evaluator on private byte arrays. No live dataset or chain action is used.

## Arithmetic and overflow argument

The conceptual `mantissa * 10^exponent` can require 160 bits. Rejecting u128
overflow would reject valid cases. Since the original mantissa fits 96 bits,
at most `exponent` zero digits must be dropped to restore that bound. Rust finds
the first fitting product by reducing the power-of-ten factor before multiplying.
A failed u128 checked multiply proves the product exceeds the tighter 96-bit
bound and takes the same reduction step. Exhausting scale first rejects; at
factor one the original mantissa fits, so reduction cannot pass through zero.
This preserves the accepted exact-reduction theorem without a new dependency.

The remaining scale is at most 28, so its decimal power fits u128. Quotient and
remainder give half-even rounding. Mode one uses `gap * 1000 < 10^scale`;
the value is below `2^96`, divisor at most `10^28` and gap at most half the
divisor, so these intermediate products fit u128. Mode zero remains exact;
all other modes round. Negative results are rejected only after rounding and
only when nonzero. The cap is exactly `2^63-2`. Zero still obeys the exponent
guard. A nonzero mode-one adjustment records a note even if later rejected.

## Actual builds, comparisons and controls

The accepted fixture covers every mode/exponent byte, limb/Decimal/cap edges,
scales, tolerance sides, signs, ties and generated cases. All expectations
precede Rust. The new oracle pins every original evidence-file hash and evaluator
identity, cross-checks the fixture with the independent integer model and emits
an input-only corpus. Expected values never enter the production driver.

Both actual Rust 1.94.1 builds (opt levels zero/three) match **25,325** values
and note requests each. Each also passes all **28 unit tests** and **11 existing
integration tests**, unfiltered. Identical optimized recipes yield raw-equal
own rlibs without normalization. This is the repository research compiler,
not recovered original build provenance. The real edition-2024 manifest and
lockfile are unchanged. Offline Cargo debug/release builds, tests, clippy with
warnings denied and formatting checks also pass; exact state is in `validation.json`.

Four compiled Rust mutants make tolerance inclusive, use half-up at ties,
increase the cap and reject a >u128 intermediate. Production comparisons reject
them with **57 / 307 / 24 / 24** mismatches respectively. These are compiled
value differences, not compile failures or self-derived expected answers.
Three actual private edits evaluated by Python lower the cap at `0x37505e6`
(rejecting `2^63-2`), alter the odd-tie mask at `0x4ead2cc` (3.5 becomes 3)
and double tolerance mantissa at `0x206d30` (1.0015 snaps to 1 with a note).

`build-result.json` retains actual source/compiler/linker hashes, SDK, recipes,
profile/mutant output hashes and evaluator controls. `$REPO`, `$OUTPUT`, `$RUSTC`
and `$LINKER` substitute private path spelling only; no code operand is masked.
Raw logs/products stay in the fresh output folder. Arm64 macOS rlib reproducibility
is not an x86-64 Linux target match; target raw/normalized counts are unmeasured.

```sh
python3 -m unittest tests.test_decimal_scaled_rust tests.test_decimal_scaled_u64 -v
python3 tools/decimal_scaled_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
make doctor verify catalogue-check reproduce
make test
git diff --check
```

The focused run passes **26 tests in 5.798 seconds**. An initial test queried
an equivalent Decimal representation absent from the frozen corpus; its KeyError
is retained privately. Correcting it to the existing scale-ten row changed no
fixture or expectation. Safe checks pass; full-suite state is recorded separately
and pending must not imply passed. The next question is the opaque note helper
and an actual caller's input/side-effect ownership. All full gates stay unchanged.
