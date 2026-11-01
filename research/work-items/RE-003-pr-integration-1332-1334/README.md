# RE-003: review of PRs #1332–#1334

- Question: do the tree-copy, u128 remainder and ASCII-address additions agree
  with their pinned evidence, and is the new comparison interval counted once?
- Base: `e80dc0f3`; exact reviewed heads are in `reviewed-heads.json`.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Scope: bounded foundation/serialization semantics and one published-artifact
  correspondence. No full component gate, original ABI or whole-node claim.

## Observations and checks

The tree-copy packet's 16 tests pass against the authenticated artifact. Its
test path is corrected from a private `work/hl-node-94.bin` to the repository
artifact; the submitted test is preserved under `original/`. Independent GNU
and Capstone decoding agree on 137 rows in the 556-byte copy body, nine rows in
the 38-byte cleanup body, and 87 rows in the 358-byte caller. Actual FDE bounds
agree. Pool reuse and ordinary tree shape are covered; allocator behavior,
LSDA action selection and complete exception semantics remain qualified by the
original packet's limits.

The complete official Rust 1.94.1 x86_64 standard-library distribution is fetched
from its provenance URL and checked against SHA-256
`74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03`.
The extracted compiler-builtins archive matches
`f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6`.
The unchanged collector authenticates the entire archive and target, checks
both named complete definitions, and reproduces the retained record exactly.
Both 197-byte source bodies equal the complete target body without masks.
Independent GNU/Capstone decoding agrees on its 68 rows and actual FDE.

The independent u128 bit-prefix implementation matches all 53,366 frozen cases
at O0 and O3 on the local Rust 1.94.1 macOS/arm64 compiler. Three compiled
mutants are detected. Emitted library IR contains no division/remainder
operations. The complete native mathematical proof is inspected separately;
finite cases supplement that proof. This host replay does not repeat the
submitted Linux provider audit or claim matching machine code for the new Rust.

The ASCII-address implementation matches all 10,872 corpus rows in debug and
optimized profiles, including the separately labelled outside-domain cases.
Its three compiled mutants, ordinary tests, target controls and own-library
reproducibility checks pass. Non-ASCII behavior, allocated errors, hidden ABI
state and caller ownership remain outside this scalar projection.

## Byte accounting and integration

The new interval is marked `published-artifact` and counted once even though
two official definitions match it. The ledger now reports 4,583/4,675 raw-equal
positions (98.03%), four raw-equal windows out of nine, and nine out of nine
raw-or-relocation-qualified windows. Its sampled .text coverage is 0.00664%.
These are registered-window measurements, not whole-module correctness.

Two existing tests expected the previous eight-window totals. Their expected
counts are updated and a regression explicitly checks the new interval's
single-entry, 197-byte, zero-mask published-artifact classification. All 15
byte-progress tests pass. `make catalogue` regenerates the tables and README;
`make verify catalogue-check` passes. No module acceptance gate changes.

The preceding batch ran the full 954-file inventory. With the three added test
files and updated progress tests, the current inventory is 957 files and
15,239 reported tests, including 67 explicit skips and no failures. Current
source hashes and the exact prior-versus-focused validation scope are recorded
in `regression-validation.json`; no second full run is implied.

## Reproduce and limits

Local compiled clients, the complete downloaded distribution, logs and replay
scripts remain under ignored `work/merge-open-1332-latest/`. Source identities,
sanitized receipts, native exports and original changed tests are retained here.
Original PR packets preserve their full recipes and provider records. No
captured binary is executed. Hosted CI remains a separate result.

Next question: qualify a concrete caller of one of these primitives, including
its input domain and error/ownership boundary, before assigning broader scope.
