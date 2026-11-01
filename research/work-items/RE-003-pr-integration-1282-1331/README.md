# RE-003: integration review of PRs #1282–#1331

- Question: do the 50 pinned heads preserve the authenticated inputs, reproduce
  their bounded evidence, and integrate with the existing reconstruction?
- Base: `3324e50333042b391312515e542279ca21f63dc8`; exact heads and draft status
  are recorded in `reviewed-heads.json`.
- Node #94: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Node #115 comparison/scalar targets:
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Components: foundation, quantities, serialization, state snapshots, startup,
  release comparisons and the minimal fixes for blocked research validation.
- Claim status: local static and bounded Rust validation. No component gate,
  native execution, original ABI or compiled-target identity is claimed.

## Evidence and reconstruction

Native GNU/Capstone checks agree on 4,080 instruction partitions across the
53 exported ranges in `native/`, including the four bucket-guard ranges.
Actual `.eh_frame` records confirm the declared complete extents. Selected
instruction records are checked against native boundaries and complete bytes;
this found the ten truncations corrected below. These counts describe review
exports, not a deduplicated node-function or rebuilt-byte denominator.

Six generator replays reproduce all 32 retained output files byte for byte:
EMA cross-release rounding, Aqav2 diagnostic drift, node115 cache publication,
node115 numeric selection, localhost fileSnapshot admission and EVM state wire
decisions. The weak-pidfd target observations also agree; provider receipts are
handled separately below. The ABCI generator's target facts and complete
instruction export remain identical after rebinding its two helper hashes.
All 52 current incoming manifests verify, covering 457 file entries.

The eight smaller Rust qualifications pass using Rust 1.94.1 on macOS arm64:
limb folding, wide subtraction, keyed mixing, divide-by-61, wrapping round-up,
node115 quantity preparation, integer Reader cursor/error behavior and Decimal
scaled conversion. The submitted runners check their frozen inputs, debug and
optimized outputs, ordinary tests and compiled negative controls. Their full
scope restrictions remain: numeric projections and chosen safe interfaces do
not recover opaque formatters, pointer aliases, faults or a complete node ABI.

Both draft controllers receive additional independent host qualification.
The formatter reproduces all 1,066 frozen transcripts in debug and optimized
builds; the numeric selector reproduces all 8,892. Four formatter and nine
selector compiled semantic mutants produce mismatches. Selector tests genuinely
link the unchanged accepted decimal-digit component. The original 103-payload
Linux provider receipts remain intact; this review uses the installed macOS
compiler and does not claim to repeat that provider audit. Opaque callbacks are
supplied fixtures, not recovered rendering or live behavior.

## Integration corrections

- Four tests assumed `work/hl-node-94.bin`. They now use the repository's
  authenticated artifact path, matching the tools' existing defaults.
- Bucket-guard validation imports Capstone unconditionally, but CI did not
  install it. The active #1303 check failed with `ModuleNotFoundError`. Capstone
  5.0.7, the packet's declared decoder, is installed locally and added to the
  existing CI bootstrap. This is limited to unblocking that research check.
- Weak-pidfd tests compared Python/binutils executable identities and a whole
  provider frame-dump hash as target facts. Only those provider-specific fields
  are excluded from the target comparison. Original receipts remain unchanged;
  FDE headers, bytes, relocation records, instruction records and branches still
  compare exactly. A regression verifies that changed target/extent identities
  remain detectable.
- #1304 changes the ELF/FDE helper source identities. The later ABCI packet still
  recorded the old helpers. Its actual generator is rerun; only the two helper
  hashes in `inventory.json` change. Target facts and `instructions.json` agree
  exactly, and the packet manifest is refreshed.
- Five compaction-stats instruction records and five decimal-index/parser
  records stopped at GNU's default seven-byte display width. Native decoding
  establishes the complete 8-, 9- and 10-byte encodings. The records are fixed;
  raw objdump exports are preserved. The compaction checker rejects truncated
  versions of the affected encodings. The decimal excerpt parser joins only
  contiguous continuation bytes and enforces the x86 instruction-length limit.
  Two compaction regressions and one decimal parser regression fail against
  the submitted versions and pass after correction.

`original-integration/` retains changed incoming files. Initial failed test logs,
the failing new regressions, final retests and source identities are retained.
No imported source, capture or submodule pin is altered.

## Validation and reproduction

The full current inventory contains 954 test files. Fresh isolated unittest
discovery runs every file; seven initial failures are corrected and rerun.
Final results: 15,209 reported tests, 15,142 passed, 67 explicit skips, zero
failed modules. `regression-validation.json` binds each result to its test
source hash; `initial-regression.json` preserves the original failures.

`make doctor verify catalogue-check index reproduce` passes locally across the
review. The real index-boundary probe passes all eight corrected CLI scenarios,
including rejecting a replaced private capture and preserving existing output
on count mismatch. It reads disposable copies as data and never executes them.
Successful index writes remain nontransactional against later I/O failures.

Host tools: Python 3.13.2, GNU binutils 2.47, Capstone 5.0.7 and Rust 1.94.1.
Run from the repository root with GNU binutils/LLVM on `PATH`. Executed scripts
are retained in `review-scripts/`; replace `<repo>`/`<review-output>` placeholders
and restore the ignored work-directory layout when reusing them. Raw transient
logs, compiled clients and fresh outputs remain under
`work/merge-open-1282-latest/`. Published paths are sanitized; native instruction
rows are unchanged. Hosted CI is a separate result.

## Remaining scope

No completion gate is requested. These additions and corrections do not change
the README's accepted-module or reconstructed-byte percentages. In particular,
two original bodies agreeing after relocation masking, static decoder agreement,
and own-Rust reproducibility are different measurements from target equivalence.

Next question: close an explicitly bounded caller/callback boundary in one of
the newly qualified Rust components, with authenticated input/output layouts and
independent behavioral expectations.
