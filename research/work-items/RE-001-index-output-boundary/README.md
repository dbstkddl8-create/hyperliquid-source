# RE-001: preserve authenticated index inputs and rejected output packets

Component: node94 function-map prerequisites; ordinary tooling defect, no component gate. Target: node94,91774280 bytes, SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f. New probe/documentation is independently authored under root MIT; no inferred unlicensed implementation is copied. Original captures, imported inventories, references and pins are unchanged.

## Active research blocker

RE-001 requires an index bound to the authenticated capture and retained count before function-map evidence is used. Both production index CLIs check a file path, then reread it for parsing. A changed private capture between those operations is accepted by the old CLI, which publishes the replacement SHA rather than the declared target. Also, invalid/missing/count-mismatched retained inventories are checked after output files have already been created or overwritten. Failed verification can therefore destroy the prior packet needed to diagnose the mapping failure. Existing index/FDE generation cannot safely qualify its result in these cases. This fix addresses that active input/output boundary; it is not generic parser polish or additional node coverage.

## Result and implementation

Both CLI paths validate inventory keys/counts first, read one immutable snapshot, authenticate exactly those bytes, parse them, and compare the count before creating output. The existing independent artifact checker remains for its pointer/materialization diagnostics. The shared generator's optional expected_count/expected_artifact arguments leave unchecked standalone API defaults unchanged; this packet claims the authenticated CLI boundary. Accepted writes are not made transactional against later I/O failures.

## Actual-capture before/after

The reproducible probe copies the actual full pinned node94 into disposable fixtures and copies the three tool source files directly from the recorded Git revisions. It runs the real CLI subprocesses and checker, with no native target or instruction evaluation. It never hardlinks or alters the imported capture. Source hashes in the reports identify the original Git blobs; the replacement case explicitly appends the fixture actor shown in probe.py to artifacts.py, calling its real original checker before replacing the private bytes.

The private replacement changes one actual executable-section byte while keeping ELF/FDE metadata parseable. Its accepted-check hash is the declared target, while the old CLI's reported index hash is the changed private input. This is an observed wrong-snapshot admission, not an invented parse error. Count-negative fixtures change only their private retained count from121299 to121300. Existing-output cases seed deliberately distinct sentinel bytes to make replacement observable.

| Per CLI | Before | After |
| --- | --- | --- |
| Matching authenticated input/count | exit0,121299 entries | same, identical output hashes |
| Wrong count, absent output | exit1 but writes output | exit1, creates no output directory |
| Wrong count, existing sentinel packet | exit1 but overwrites packet | exit1, exact prior bytes preserved |
| Input replaced after real checker succeeds | exit0, reports replacement SHA | exit1, no output directory |

Both elf_index and fde_extents have all four cases: eight actual CLI invocations before and eight after. before.json/after.json preserve return codes, raw stdout/sanitized stderr, source/input hashes and all output hashes. Only ephemeral fixture path spelling is replaced by <fixture>; no substantive diagnostic normalization is applied. No file hashes or instructions are transplanted into reconstruction.

The separate committed four-test regression uses a parseable three-FDE synthetic ELF for18 failing baseline subcases. Those fast tests cover missing/malformed/duplicate/invalid count forms, retained packets, replacement after the real checker, and successful publication. The actual-capture probe above independently establishes the same boundary on the repository's real input.

## Reproduce

Python3.12.14/macOS arm64. All coordinates in the probe are ELF file offsets, not function or source coordinates. The selected modified offset is recorded, never executed. From repository root with materialized node94 and Git:

~~~sh
python3 -B research/work-items/RE-001-index-output-boundary/probe.py --revision 391fe838467760eefc04072c0ea762a7a1155c78 --output work/index-before.json
python3 -B research/work-items/RE-001-index-output-boundary/probe.py --revision e2df02d05141e80e6ba9551338d858022cc778bf --output work/index-after.json
python3 -B -m unittest discover -s tests -p test_index_output_validation.py -v
python3 -B -m unittest discover -s tests -p test_startup_inventory.py -v
make doctor verify catalogue-check reproduce
~~~

e2df02d05141e80e6ba9551338d858022cc778bf is the recorded implementation source revision e2df02d05141e80e6ba9551338d858022cc778bf; its helper source blobs are unchanged at the submission head. The corrected real probe replay is byte-identical to after.json. Ten active dependent inventories are regenerated using their actual producers; only the two helper source hashes change. The separate hl-node startup manifest rebinds those current helper hashes. In the newer startup inventory, all target facts and the complete instruction export remain identical. Historical frozen helper-source evidence is preserved rather than restamped.

## Validation and limits

The newly integrated startup suite passes68 tests in7.270s. Earlier13 explicitly reviewed static-only modules passed496 tests on the original prepared integration; that is historical integration evidence, not a full-suite result for this final head. Required current-head hosted tests must be reported separately after their observed result. The operator has explicitly authorized offline Python captured-instruction evaluation in that full suite; this probe itself remains static. No hosted-CI pass is claimed here in advance.

No original Rust implementation, complete function census, helper/call/data closure, original target runtime or whole-node equivalence is established. All component gates remain false. No native captured executable/Unicorn, service, wallet, signing, chain action, deployment or paid dataset is run.

Current final focused validation: all14 existing elf_index/fde_extents modules pass52 tests; the new four-test regression passes in1.178s, and the new upstream startup module passes68 tests in7.270s. make doctor verify catalogue-check reproduce and git diff --check pass. The actual corrected capture probe replays byte-for-byte after canonical source-revision and diagnostic-field metadata are recorded. Full-suite hosted CI remains a separate pending result.

## Current publication base and CI prerequisite

Publication uses main3324e50333042b391312515e542279ca21f63dc8 plus shared prerequisite PR1295. All three tool source blobs used by the frozen before probe are byte-identical at that current base; the after helper blobs also match this submission exactly. The original captures, before/after results and their source revisions remain intact. The previous index head344ba0ccff20fcea52bbcc62ef2c5ca92dd4f25e completed all875 flat test files in hosted run41300575168; only two unrelated setup classes failed because llvm-objdump was missing. The actual missing-dependency repair is credited solely to PR1295, whose real Ubuntu proof passes both unchanged classes (18 tests). This branch includes that common prerequisite without claiming it again. The old full run remains a failure, and fresh current-head full CI is pending. No tests are removed or weakened.
