# RE-003: review of PRs #1335–#1349

- Question: do these additive evidence packets agree with the pinned artifacts,
  and can their static validation run without altering retained evidence?
- Base: `d3af75257a396c85d20857f421c370ddb8cb40e5`; reviewed PR heads are in
  `reviewed-heads.json`. Source identities are recorded separately.
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Visor SHA-256:
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Claim status: bounded static observations and conditional semantic models.
  No component milestone or byte-progress denominator changes.

## Evidence and review

Six node generators reproduce all 29 retained output files exactly. The late
PDI generator reproduces three more. All 14 standalone packet manifests pass;
the formatter packet's embedded 60-file manifest passes separately. The
original evidence and imported artifacts remain unchanged.

Independent GNU 2.47 and Capstone 5.0.7 decoding agree on 52 unique complete
node FDE intervals, 187,445 bytes and
33,986 instruction rows. Raw exports and their
hashes are retained under `native/`. These are unwind extents and linear byte
partitions, not proof of ownership, reachability or complete call closure.

The ceiling leaf's normal and optimized validators pass all 33,066 rational
oracle cases, four semantic mutants and four structural corruption controls.
The PDI table and its 17 branches pass native review; all 256 table entries,
255 recurrence transitions and 100,000 deterministic reciprocal samples agree.
Its helper semantics, possible decimal indices and active FP mode remain open.

Both Visor validators pass in normal and optimized Python modes. GNU/LLVM
partitions agree on 946 bytes / 256 rows for descriptor waiting and 6,488 bytes /
1,583 rows for formatting. Descriptor regeneration matches all eight retained
files. Formatting matches 23 of 24 files exactly; the sole difference is two
GNU version strings in the summary. Only version admission was adjusted in
ignored copies of the formatter validators; original scripts are preserved.
The descriptor copy changes its root location only. Sixteen descriptor and
eleven formatting rejection/preservation controls pass in each Python mode.

Review supports the conditional formatter argument order 0, 1, 1 and descriptor
wait/cache transitions. Allocator prefix preservation, kernel behavior,
prepared command payloads and execution remain unproved. No shell command from
the packet, captured target, emulator or chain action was run.

## Reproduction fixes and validation

Four submitted tests referenced a private binary path. They now use the
canonical pinned artifact. After that first correction, the full sweep exposed
filename-header comparisons and two exporters writing into committed packets.
Regeneration now uses temporary packet copies, with an explicit assertion that
the retained files stay unchanged. The chain and counted-pointer tests normalize
only the filename header. Concat and range-sum compare ordered address/raw-byte
rows because GNU versions can print implicit segment operands differently.
Their original packet verifiers and corruption controls still run.

Submitted sources, exact initially executed sources, initial failed logs and
passing reruns are retained separately. The final inventory is
969 files, 15,432 reported
tests and 67 explicit skips, with no final failing file.
This combines the complete 967-file sweep, four corrected reruns and both late
PDI and field-sum test files. Current source hashes are checked against every result; a second
full sweep is not implied. `make doctor verify catalogue-check` and final
`make verify catalogue-check reproduce` pass locally.

The second late arrival, field sum at 0x514bcd0, is separately verified against
its 104-byte FDE and 13-byte callee. Its callee return is overwritten before
accumulating the field at +0x50. The submitted test had private-path
and provider-text comparison problems; its source and initial failures are saved
with the passing corrected rerun. The target-derived scope stays conditional
on valid container storage and excludes a complete caller or side-effect proof.

## Reproduce and remaining scope

Use the pinned artifacts, Python 3.13.2, GNU 2.47, LLVM 22.1.4 and Capstone 5.0.7.
Run each original packet's documented recipe. Run the complete inventory with
`make test`; the local review scheduled the same per-file unittest discover
commands concurrently. Exact review scripts and commands are retained under
`validation-scripts/`; their original working location was ignored
`work/merge-open-1335-latest`, with the integration checkout at
`work/merge-latest-1153-1160/integration`. Temporary raw provider regenerations
and the complete sweep logs remain there. Receipts here record their hashes.

No Rust implementation or independent rebuilt machine code is added by this
batch. Full helper/data/relocation/ABI/exception closure and full component
acceptance remain open. The README's existing completion percentages remain
unchanged. Hosted CI is a separate result; local success does not certify it.

Next question: establish one packet's unresolved helper or caller contract from
the same target before extending its semantic scope or requesting gate credit.
