# RE-003: PRs #1351 and #1352 integration review

- Base: `abac38ba`; exact reviewed heads and final source hashes are retained.
- Visor target: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Node #94 target: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Scope: bounded static proof and arithmetic evidence. No runtime execution,
  complete component gate, whole-node reconstruction or matching-built-byte credit.

## Visor NUL admission

All eight normal/optimized survey, integrity, LLVM and algebra commands pass.
No provider admission edits were required. All 20 fresh GNU files match the
retained files byte for byte. GNU 2.47 and LLVM 22.1.4 agree on all 1,076 selected
instruction partitions / 4,666 bytes. Both verifier modes pass ten controls;
the algebra check covers 512 digit transitions and a wrong-constant witness.
All 55 manifest entries verify. The manual first-NUL, appender sticky flag and
call-free spawn rejection argument agrees with the retained native records.

Valid storage, allocation/copy preservation, prior argv growth, cleanup and
the actual prepared input remain premises. Passing this NUL gate is not proof
of successful process creation. No shell command or captured code was run.

## Span-count repair

Review found a concrete validator defect: independent substring searches could
accept an FDE offset from one retained record and a PC/CIE from another.
The original checker accepted a substituted existing offset. Its negative
result and original files are preserved under `span-count-validation/`.

The checker now binds each offset, CIE and PC interval as one record and compares
the association to FDEs parsed from the authenticated binary. New swapped-offset
and swapped-CIE controls reject the original failure. All 26 tests pass. The
43-byte span-count arithmetic uses the object fields after the callee returns;
callee and tail-target behavior remain outside the model.

The original broad similarity and uniqueness statements had no retained corpus,
method or reproducible output. Those statements were removed from the README;
the retained evidence note labels them unverified author assertions. This is
a qualification of unsupported claims, with no additional completion credit.
The packet manifest was regenerated and its raw native exports remain unchanged.

## Integration and reproduction

`make verify catalogue-check` passes. The preceding complete validated inventory
of 970 test files has unchanged source hashes. Adding the repaired 26-test module
gives 971 files, 15,468 reported tests and 67 explicit skips, with no remaining
failure. This is prior full-inventory evidence plus focused validation, not a
second full sweep. The exact chain and source hashes are in
`regression-validation.json`.

Original packets provide the recipes. Fresh review commands, providers, logs,
raw exports and receipts are retained here or under ignored
`work/merge-open-1335-latest`. Existing README progress remains unchanged.
Hosted CI is a separate result.

Next question: establish the span helper's callee/tail-target contract or a
prepared Visor argument's allocation boundary before expanding either claim.
