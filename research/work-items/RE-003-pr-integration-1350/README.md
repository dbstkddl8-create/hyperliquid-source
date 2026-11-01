# RE-003: PR #1350 integration review

- Question: is the size-decimal update gate tied to node #94 bytes and does its
  additive packet preserve the existing validated repository state?
- Base: `be793270`; exact PR head and file hashes are retained beside this record.
- Target SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Scope: static observations and conditional models. No component or byte-ledger
  completion credit, no captured execution and no independent Rust build.

## Checks

All ten new tests pass with no skips. All three regenerated output files match
the packet exactly, and all four manifest entries verify. Independent GNU 2.47
and Capstone 5.0.7 decoding agree on the seven declared FDEs: 6,717 bytes and
1,461 instruction rows. Raw exports and hashes are retained in `native/`.
These unwind extents and byte partitions do not establish complete ownership,
reachability or the full semantic meaning of either collector mode.

Review confirms the final write gate: a present asset with an empty nested map
must pass dex and row bounds before the byte store at row offset +0x2a. Missing
or populated entries skip the store. The unsigned reciprocal, seed overflow
branches and call bindings agree with the captured bytes. Field/action names,
complete collected-row provenance, resolver/reporter behavior, allocation and
broader rollback semantics retain the original packet's qualifications.

`make verify catalogue-check` passes. The preceding complete regression covered
969 test files, 15,432 reported tests and 67 skips after the recorded repairs.
All those test source hashes remain unchanged. Adding this PR's ten passing
tests gives 970 files, 15,442 reported tests and 67 skips with no remaining
failures; no second full sweep is claimed. Machine-readable records identify
the prior validation and the new test separately.

Run the original extractor with `--out` pointing into ignored `work/` and run
`python -m unittest discover -s tests -p test_risk_size_decimal_update94.py -v`.
The replay used Python 3.13.2. All existing progress percentages stay unchanged.
Hosted CI remains separate from local checks.

Next question: determine the source and completeness of each collector mode's
per-asset map before assigning it broader business meaning.
