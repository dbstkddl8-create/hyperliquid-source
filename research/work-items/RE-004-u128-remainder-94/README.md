# RE-004: complete node94 unsigned128 remainder

Task/component: RE-004 arithmetic, foundation runtime dependency. Bounded
question: what numerical value does node94's complete leaf at ELF VA
`0x565f7f0..0x565f8b5` return, on every nonzero unsigned128 divisor?

Target: Linux x86-64 node94,91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base:`3324e50333042b391312515e542279ca21f63dc8`. Coordinates are ELF
virtual addresses before load bias. All component gates remain false.

The complete197-byte,68-instruction FDE returns `n mod d` in RAX:RDX for
entry numerator RDI:RSI and divisor RDX:RCX, under the explicit ordinary-return
domain in [PROOF.md](PROOF.md). The independently authored numerical Rust
component uses128 high-prefix steps and no division/remainder operator.
`NonZeroU128` excludes zero-divisor fault behavior. This resolves one runtime
primitive, not caller guards/units/state, original ABI or whole-node behavior.

The existing RE-028 modexp review lists this FDE only as a static arithmetic
helper. The prior RE-004 quotient theorem and RE-002 quotient correspondence
cover the separate198-byte leaf at`0x565f5a0`; they remain unchanged. This
packet establishes the remainder leaf's own complete branch/correction theorem.
No can1357 inferred implementation was read or copied.

## Target and official artifact evidence

`native/record.json` binds one immutable full target snapshot to its executable
section/PT_LOAD mapping, complete actual FDE/CIE, all68 retained raw instruction
rows, both return sites, and mapped GOT slot`0x576e518`. That slot has one exact
symbol-zero RELATIVE record pointing to the leaf, with global uniqueness across
all RELA tables. No relocation overlaps the body. The complete native listing
has no calls, loops, static-data references, explicit loads/stores or stack saves;
only RET accesses the ordinary return word.

Both defined `__umodti3` candidates in the authenticated official Rust1.94.1
compiler-builtins archive match all197 target bytes, with zero masks. Their
complete FUNC sections have no code relocations. The full archive is4,400,606
bytes, SHA-256`f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6`.
The collector enumerates every matching symbol and requires the complete two
actual definition set, retaining both raw bodies. One selected target interval
is registered once in`research/byte-windows.json`; the duplicate definition
adds no denominator. This is named published-artifact correspondence, separate
from the new mathematical/source proofs. It is not a source build or original
compiler recovery.

[SOURCE-PROVENANCE.json](SOURCE-PROVENANCE.json) preserves the official dist,
source-revision and license identities. The imported excerpts retain the full
[compiler-builtins multi-license](third_party/LICENSE-compiler-builtins.txt),
which is not MIT-only. New code/proofs/tooling are independently authored MIT.
The research Rust toolchain was restored from both exact official archives,
inspected before installation into an owned prefix with`--disable-ldconfig`.
All103 genuine component-manifest payload files matched their authenticated
archive source;`preparation/PROVIDER-AUDIT.json` preserves the complete manifest.
Rust1.94.1 is a research provider, not an identified original node compiler.

## Independent expectation freeze and complete theorem

Before new arithmetic Rust existed, an independent worker read the actual
68-row native listing/FDE/slot records and froze53,366 unique nonzero-divisor
pairs using Python big-integer divmod and Euclidean identities. The original
unchanged generator, compact receipt, independent theorem, and compressed
original authority/input/expectation bytes are under`preparation/`. Decompressed
hashes are checked, so compression does not alter the frozen inputs.

The authority covers all64 normalization shifts, both high-divisor correction
outcomes, direct DIV64 and both first-digit DIV widths, every128-bit divisor
exponent, quotient boundaries, zero/max numerators and10,000 deterministic hash
samples. `tools/u128_remainder_reference.py` authenticates the actual target and
rechecks those53,366 results against both independent divmod and the native
integer branch equations. This is pure integer arithmetic, not a native
instruction evaluator. The complete native proof closes every admitted value,
including DIV overflow safety, e=64 normalization, estimate error, exact128-bit
multiply-back and carry/borrow correction. The source loop has its own
all-input prefix invariant and bounded-shift proof.

The ordinary Rust unit fixture is a13-case subset extracted before`lib.rs`
existed. Its freeze receipt records the parent authority and exact bytes.
The separately linked production client receives only opaque ID/numerator/
nonzero-divisor inputs and is compared against all53,366 expectations outside
its process. It cannot read expected remainders or branch labels.

## Reproduce

From the repository root:

```sh
python3 -B tools/u128_remainder_contract.py \
  --binary artifacts/node/94/hl-node \
  --builtins /path/to/libcompiler_builtins-58c8d4715a55733a.rlib \
  --output /tmp/new-native-remainder-record
python3 -B -m unittest tests.test_u128_remainder_contract -v
python3 -B tools/u128_remainder_rust.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json \
  --output /tmp/new-own-remainder-build --controls
```

Native collection and the eight focused actual-input/corruption controls passed
before any new compiler execution. Source/build and final repository validation
results will be retained in this packet after the corresponding commands run.
The full repository suite is outside this authorized validation scope. Captured
code and instruction evaluators never execute in these tools.

## Limits and next question

No full component gate, zero-divisor process behavior, original ABI/types/
clobbers/compiler, caller error/rounding/unit policy or whole-ELF equivalence is
claimed. Own rlib reproducibility must remain distinct from the197-byte official
artifact correspondence. Next question: which real modexp/multiword consumers
supply the nonzero divisor premises and consume this remainder projection?
