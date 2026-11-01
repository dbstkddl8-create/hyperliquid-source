# RE-014: Aqav2 diagnostic and selected call-register drift

Component: asset-associated release drift. Base revision: 6d727b9ea2ca4dc497c96a2de35cfba064e14dcc. This is independently authored static research under the approved RE-014 cross-release mapping task. All addresses are original ELF virtual addresses; ranges are half-open.

The selected relocated Aqav2TokenInfo diagnostic says five elements in node94 and eight in node115. More than the text changes: two selected call-register setup groups replace the old raw ESI value4 with5. Each release has ten retained LEA sites: the selected raw ESI multiset is 0,0,1,1,2,2,3,3,4,4 in94 and 0,0,1,1,2,2,3,3,5,5 in115. These are immediate register values at particular direct calls. Field identities, required wire arity, defaults, positional meaning and helper behavior remain unproved.

## Inputs and prior work

- Node94: 91,774,280 bytes; SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
- Node115: 105,896,032 bytes; SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- [PR1051](https://github.com/lalalune/hyperliquid-source/pull/1051) already retains the94 five-element diagnostic in the aligned-quote packet. Its facts are credited and retained. This packet adds the cross-release relocated records, complete reference-owning FDEs, selected setup/call transfers and actual immediate drift.
- Imported artifacts, signatures, reference sources, pins and component gates remain unchanged. No unlicensed inferred implementation is copied. New code/docs use root MIT.

## Measured code and data

| Release | Complete FDE | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| 94 | 0x1a3f3d0..0x1a4305f | 15,503 | 2,987 |
| 115 | 0x180af90..0x180b82e | 2,206 | 484 |
| 115 | 0x1a072f0..0x1a0a029 | 11,577 | 2,227 |

Denominator: three complete FDE bodies, 29,286 bytes / 5,698 native instructions. Full unnormalized GNU exports, exact body hashes and raw FDE/CIE records are retained. Byte coverage and all selected instruction starts are checked. These are reference-owning bodies; original function names, whole-body semantics and ownership are not recovered. No raw/normalized matching or function-coverage percentage is claimed.

94 slot0x5685d88 has a RELATIVE relocation to0x3afea4;115 slot0x641d1f0 points to0x5c9438. Each length word and complete diagnostic text is checked. Every selected RDX LEA resolves to its release's slot. Adjacent RCX LEAs resolve to pinned32-byte data windows at0x5685ae8 or0x641ce90; their raw bytes and contained RELA entries are retained. These are selected data windows, with role and complete object/vtable extent unproved.

Each local setup contains the two RIP LEAs, optionally a stack-result-pointer LEA, and either XOR ESI,ESI or MOV ESI,imm32. Its next transfer is a direct call or one unconditional in-body jump to a direct call. The selected RDX/RCX/ESI values therefore arrive at that call without an intervening register write. Calls bind to0x1703e70 in94 or0x17fbb40 in115. Actual callee FDE bounds are recorded separately as unmeasured; helper bodies/formatting/error semantics are excluded from the measured denominator and remain open.

The last selected MOV immediate differs at94 site0x1a414ba (value4),115 site0x180b4a9 (value5); another selected path carries the same change. Other format paths, indirect/non-LEA references, value decoding, field names/order/defaults, source types/ABI, complete caller reachability and actual input acceptance remain open. The text count alone establishes no input-length contract.

## Controls and reproduction

macOS arm64; Python3.12.14; GNU readelf/objdump2.47.20260726. Both complete capture identities and the spec hash are verified before interpretation, output or native calls. GNU receives private byte-identical snapshots. No captured native execution or CPU emulator is used by this producer or its six focused tests.

~~~sh
python3 -B tools/aqav2_diagnostic_drift.py --output work/aqav2-diagnostic-check
python3 -B -m unittest discover -s tests -p test_aqav2_diagnostic_drift.py -v
make doctor verify catalogue-check reproduce
~~~

Six focused tests passed in19.502s. The generator reproduced all retained outputs byte-for-byte. Controls change each actual ASCII count digit and actual MOV immediate, observe the changed extracted fact, then reject the changed relation. Further controls attack LEA/call displacements, argument-window bytes, the real RELA addend and all owner FDE extents. Modified, truncated and swapped captures fail before output creation. Unknown helpers are not assigned invented results.

Earlier execution-limited validation (historical): full repository testing was held: the current default suite also contains concrete captured-instruction evaluators outside the separately authorized execution scope. The aggregate attempt was interrupted; it is not a full-suite PASS. Safe make checks and the focused static controls are recorded separately. Hosted CI, Rust reconstruction, original-runtime equivalence and all component gates remain unqualified.

Next: close the callee, additional field readers and input provenance before assigning the raw ESI values a schema or parser meaning.

Safe aggregate validation: make doctor verify catalogue-check reproduce passed; an aggregate checkout containing two other independently prepared changes passed496 tests across13 reviewed static-only modules. That is integration evidence, not an exact-head full-suite result for this standalone change. The stopped full-suite attempt remains incomplete.

## Current submission and shared prerequisite

Publication uses main3324e50333042b391312515e542279ca21f63dc8 plus PR1295, the shared LLVM bootstrap repair. That prerequisite is not new work claimed by this research. Original analysis snapshots and earlier held/interrupted results remain historical. Offline Python instruction evaluation is now explicitly authorized. The prior research headca210e16ac818e80b28baf30f5a5cab536e3e7e9 completed all875 flat test files in hosted run41298922674: this module passed; only two pre-existing classes failed because llvm-objdump was absent. The unchanged failing classes later passed18 tests on real Ubuntu after adding LLVM (proof run41312564822). The old full run is still a failure; fresh current-head full CI is pending. No runner/test is removed or weakened. No captured native executable, Unicorn, live target network, wallet or chain action is run.
