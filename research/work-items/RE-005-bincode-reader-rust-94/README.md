# RE-005: reconstruct both node #94 integer Readers, including failure cursor effects

- Component: serialization fork, bounded unsigned integer Reader family.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: main `3324e50333042b391312515e542279ca21f63dc8`, plus the
  shared CI prerequisite `516b1e3a` / PR #1295, not additional credit.
- Established static input: merged PR #253,
  `research/work-items/RE-005-bincode-slow-widths/`, preserved unchanged.
- Outcome: independently authored Rust for Reader values, error payloads and
  remaining input, extending the real existing `src/bincode-varint` component.
  No inferred-source implementation or dependency is copied.

## Gap and actual byte denominator

The existing Rust implements integer encoders and the u64 **slice fast** path.
It explicitly refuses short inputs and implements neither Reader. The accepted
static sibling already establishes two direct Reader bodies and their shared
error builder. This contribution implements that missing family as one change,
rather than splitting widths, orders or copies into separate contributions.
It serves the approved reconstruction scope and RE-005 task.

| Actual FDE, ELF virtual addresses | Bytes | Included effect |
| --- | ---: | --- |
| `0x466d850..0x466d975` | 293 | u32 Reader |
| `0x466d980..0x466dabc` | 316 | u64 Reader |
| `0x466dac0..0x466dace` | 14 | shared error builder |

Total: three complete bodies, **623 bytes**. `native-records.json` retains their
complete hex and hashes, actual extracted parameters and the shared GOT binding
`0x57745e8 -> 0x466dac0`. Actual FDE extents, both tag jump tables and historical
anchors are checked against the authenticated capture before expectations are
derived. The old packet retains their full native disassembly, independent
verifier, call counts and broader slice-width survey; none is regenerated in
place or re-claimed as new discovery.

All calls from these Reader bodies go through that shared error-builder slot;
the 14-byte callee writes tag 3 and the two supplied code bytes, then returns.
There is no unresolved allocation/formatting callback on these normal-return
paths. Original caller ownership and Rust ABI/layout remain separate questions.
Valid readable input, nonwrapping native slice bounds, disjoint output/reader/
input regions and an ordinary stack are assumptions of the native relation.
Safe immutable input and mutable slice-state borrows express the research API.

## Cursor relation, errors and byte order

The native u32 stores at `0x466d869/0x466d86c` and u64 stores at
`0x466d999/0x466d99c` advance the pointer and decrease length by one before
dispatch. Thus a marker is consumed even when the payload is too short or the
marker is rejected. Empty input instead writes missing count one without a
cursor update. Successful payload arms replace the pointer/length using total
width 3, 5 or 9. Shortfall is computed from required total minus original length;
only the marker has been consumed at that point.

The direct Reader relation is:

| Tag | u32 | u64 | Cursor effect |
| --- | --- | --- | --- |
| `0..250` | value = tag | value = tag | consume one |
| `0xfb` | two-byte payload | two-byte payload | consume three if available; otherwise only marker |
| `0xfc` | four-byte payload | four-byte payload | consume five if available; otherwise only marker |
| `0xfd` | codes 2:3 | eight-byte payload | u32 consumes one; u64 nine if available, otherwise one |
| `0xfe` | codes 2:4 | codes 3:4 | consume one, never a u128 load |
| `0xff` | codes 2:12 | codes 3:12 | consume one |

`dl == 0` selects little endian; nonzero selects the byte-swapped result. Native
CMOVE selectors, swaps and load widths are retained by the full-body check.
The Rust exposes `PayloadOrder` for the two distinct behaviors, accepts observed
non-minimal representations and folds the selected payload bytes without unsafe
loads. Its errors preserve the raw code payloads in an independently authored
enum; inactive bytes in the original result object and its concrete enum layout
are not claimed. These functions are direct Readers, **not** automatic slice
wrappers. The u64 fast slice error arm uses code 2 where the Reader uses 3;
the existing fast API and its twelve integration tests remain unchanged.

## Pre-implementation expectations and controls

Commit `37dbe9b8` freezes input and expected files while the component source is
still its original SHA-256 `1ca06834ee8e83d04a0d2341674d93a613885ffdca69b5ed57d4b04d7073e627`.
Neither `read_u32` nor `read_u64` exists at that freeze. The precursor runner's
hash and target counterfactuals are retained in `PRE-RUST-FREEZE.json`.

The **3,276** cases cover both widths/orders, every initial tag, empty input,
all lengths one through ten for each marker 251..255, asymmetric/zero/all-ones
payloads, non-minimal encodings, trailing suffixes and deterministic generated
bytes. Expectations are a piecewise integer/slice relation using actual native
immediates and table-validated arms; payload values use Python `int.from_bytes`.
The Rust instead incrementally folds bytes. These are finite comparison cases,
not a whole-input-space execution claim.

The separately linked production driver receives only width, order and input
bytes. It emits success value or error payload, consumed count and the complete
remaining suffix. Expected outputs never enter production code or its arguments.
Ordinary compiled tests separately assert the frozen corpus and the concrete
two-read consequence of a short payload consuming its marker.

Three actual private operand/opcode counterfactuals change the equations:
`0x466d8ba` changes required total 3 to 4 (input `fb3412` success becomes need-one);
`0x466da90` changes the u64 `0xfe` expected code 3 to 2;
`0x466d8f9` changes CMOVE to CMOVNE (`fb3412` changes 4660 to 13330).
Historical anchors reject the first two; the new complete-body check rejects the
third below the whole-input gate. No altered capture is executed or emulated.

Three actually compiled Rust mutants omit marker consumption, perturb shortfall
by one and ignore payload order. Their production outputs disagree on
3,272 / 100 / 38 of 3,276 cases, respectively. All three also fail actual compiled
fixture assertions. The first development control attempt failed compilation
because deleting marker consumption made `rest` unused under `-D warnings`;
that failure was retained privately and is not counted as a semantic rejection.
The final mutant explicitly consumes the binding without changing state, compiles
successfully and fails the value/cursor comparator.

## Actual builds and checks

```sh
python3 -m unittest tests.test_bincode_reader_rust tests.test_bincode_varint_slow -v
python3 -I -B research/work-items/RE-005-bincode-slow-widths/independent_verify.py
python3 tools/bincode_reader_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
make doctor verify catalogue-check reproduce
make test
git diff --check
```

Actual local host: macOS arm64. Rust 1.94.1 is the existing repository research
pin, not recovered original compiler provenance. The real dependency-free
component manifest/lockfile are unchanged. The runner directly builds its whole
library and both integration files using edition 2024, warnings as errors,
overflow checks, one codegen unit and opt levels zero/three. It runs **all twelve
existing fast/encode integration tests plus two new Reader tests per profile**,
and compares all 3,276 production outputs per profile. Two identical optimized
recipes yield raw-equal own rlibs, without normalization. Compiler/linker/SDK,
source/input hashes, exact recipes and actual exits are in `build-result.json`.
Path placeholders preserve privacy; they do not mask program operands. Raw logs
and compiler products remain in the requested fresh output folder.

The focused Python run passed **27 tests in 64.456 seconds**. The independent
old-packet verifier reports PASS for both Readers, call counts 2/12 and 22 old
vectors. `make doctor verify catalogue-check reproduce` and `git diff --check`
passed. `validation.json` records full-suite status separately; a pending run
must not be interpreted as success. Original artifacts, imports, reference pins,
negative results and all progress gates remain unchanged.

This new runner builds/executes only independently authored Rust. It does not
launch the captured node/visor or a CPU interpreter. Existing repository Python
evaluators retain their separately authorized scope. The host rlib is not an
x86-64 target-byte match; raw/normalized target comparison remains unmeasured.
Caller/type ownership, full wrapper selection, complete serialization and whole
node behavior remain unresolved. No full component gate is requested. Next work
should qualify an actual caller's wrapper dispatch and error ownership before
using these primitives as a complete deserialization path.
