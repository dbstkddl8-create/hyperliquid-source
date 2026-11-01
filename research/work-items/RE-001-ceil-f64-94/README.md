# RE-001: close the scalar contract of node94's ceiling leaf

- Component: `foundation`; shared scalar dependency used by the existing
  RegisterHyperliquidity research path.
- Target: Linux x86-64 node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `d3af75257a396c85d20857f421c370ddb8cb40e5`.
- Reference pin preserved: can1357/hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. Its inferred implementation was
  neither used nor copied for this packet.
- Scope: the complete 119-byte leaf at ELF VA `0x565f670..0x565f6e7`, its two
  constants, and one already-observed caller's binding through a relocated slot.
- Status: static observations and a scalar mathematical argument. No Rust
  implementation, compiled-byte comparison or acceptance gate is claimed.

## Gap addressed

The existing [RegisterHyperliquidity packet](../RE-004-hyperliquidity-register-94/README.md)
lists `0x565f670` as a `ceil` helper but excludes its internal behavior. Its
`slots.tsv` records `0x57747c8 -> 0x565f670`. This packet qualifies that leaf's
own full extent and scalar result, including negative zero, subnormals and
signaling NaNs. It leaves the caller's established research and all progress
files unchanged.

Before selection, live open PRs #1335, #1336 and #1337 concerned other paths.
A title/body search for `565f670 OR ceil` and a local address search found
caller-level references but no dedicated contract for this leaf. PR #1263's
scope and review were also read. This is a bounded extension of its dependency
evidence, not a new claim over the whole caller or a function census.

## Reproduce

From the repository root, after the pinned submodules and LFS objects have
been materialized by `scripts/setup.sh`:

```sh
python3 -B research/work-items/RE-001-ceil-f64-94/verify.py
python3 -O -B research/work-items/RE-001-ceil-f64-94/verify.py
python3 -B research/work-items/RE-001-ceil-f64-94/verify.py --write work/ceil-rechecked.json
cmp research/work-items/RE-001-ceil-f64-94/evidence.json work/ceil-rechecked.json
```

`--write` requires a new output file and refuses to overwrite an existing one.
The verifier uses the existing `Elf` and `.eh_frame` parsers, authenticates the
full target digest, then rechecks byte coverage, FDEs/CIEs, branches, constants,
the caller edge and relocation records. The retained disassembly bytes must
cover both admitted ranges contiguously. The verifier does not independently
decode the text mnemonics; the raw GNU disassembly and the instruction-by-
instruction argument in [PROOF.md](PROOF.md) remain review inputs.

Raw disassembly can be regenerated with GNU binutils:

```sh
objdump -d -M intel --insn-width=16 --start-address=0x565f670 --stop-address=0x565f6e7 artifacts/node/94/hl-node
objdump -d -M intel --insn-width=16 --start-address=0x3261c40 --stop-address=0x3262583 artifacts/node/94/hl-node
readelf --debug-dump=frames artifacts/node/94/hl-node
```

The recorded run used macOS arm64, Python 3.14.3 and GNU binutils 2.47. The
Python verifier has no external package dependency and performs no network
access. No node/visor executable, native excerpt, instruction emulator, chain
operation or signing flow was run. `MANIFEST.sha256` covers the packet files.
Apple LLVM 17.0.0 independently decoded the same 30 instruction boundaries,
byte strings and mnemonics; its complete listing is `ceil.llvm.txt`. The checker
also verifies that listing's byte coverage. The 16 examples in `samples.tsv`
are checked against both the bit equation and the rational oracle.

## Binary observations

All addresses are original ELF virtual addresses, before load bias. The
verifier independently checks section and PT_LOAD mappings. This leaf's file
offset is `0x565e670`; the relationship is not assumed for other sections.

| Evidence | Observed result |
| --- | --- |
| Leaf FDE | VA `0xfbdac0`, section offset `0x2dc5a8`, `[0x565f670,0x565f6e7)` |
| Leaf code | 119 bytes, 30 instructions, five internal conditional edges, three returns |
| Leaf body SHA-256 | `305266cf1728cbf73813d37f53ff4f144253a377fc9258c8732b1f4b3bf5eaeb` |
| Constant at `0x20a730` | bytes `000000000000f03f`, binary64 +1 |
| Constant at `0x20a910` | bytes `0000000000000080`, binary64 -0 |
| Caller FDE | `[0x3261c40,0x3262583)`, 2,371 bytes |
| Caller edge | instruction at `0x3262024`, bytes `ff159e275102`, RIP-relative indirect call through `0x57747c8` |
| Slot binding | one symbol-zero `R_X86_64_RELATIVE` relocation, addend `0x565f670` |

The caller edge is an instruction boundary in the retained complete caller
disassembly, rather than an arbitrary byte-pattern hit. This establishes one
static binding, not a whole-program xref count or a caller execution result.
The relocation check scans all 80,300 records in the two RELA sections. It
finds one write to the selected slot and no overlapping write to the leaf or
either constant, using a conservative eight-byte overlap guard. Both selected
FDE ranges are unique and non-overlapping with other FDEs. Code/data mappings,
raw CIE/FDE bytes and the call's source bytes are retained in `evidence.json`.

GNU prints offsets from the nearest available C++ dynamic symbol in the
listings. Those decorations do not identify these functions. The `ceil`
label here follows the proven scalar value rule, not that symbol or an
unlicensed reference label.

## Scalar result

For finite inputs, the low 64 bits of XMM0 contain mathematical ceiling:
positive values below one become +1, negative values between -1 and zero
become -0, both zero signs survive, and integral values remain unchanged.
Infinity and NaN encodings return bit-for-bit unchanged, including signaling
NaN payloads. The body uses integer operations and moves, so this scalar
result does not depend on the floating-point rounding mode. See the full
exponent partition and carry argument in [PROOF.md](PROOF.md).

## Checks and controls

The integer equation derived from the listing agrees with a separate exact
rational oracle on 33,066 inputs: both signs of all 2,048 exponent fields,
selected fraction/mask boundaries and deterministic hash samples. Input and
expected-output hashes are in `evidence.json`. These are model/oracle checks,
not observations from executing the captured function.

| Deliberately incorrect rule | Mismatches / 33,066 |
| --- | ---: |
| Truncate the positive fractional path | 405 |
| Replace negative-zero results with positive zero | 8,226 |
| Quiet signaling NaNs | 9 |
| Return too early at exponent field 1074 | 10 |

Four separate synthetic mutations change a code immediate, the negative-zero
constant, the relocated-slot addend and the FDE range. All are rejected by
their respective checks. These controls bypass only the outer whole-file
digest gate, so they exercise the structural/content checks rather than all
failing at the same SHA-256 comparison. They never execute changed bytes.

Repository check outcomes and the exact validation commands are recorded in
`VALIDATION.md`. No hosted CI or container result is asserted.

## Limits

This closes one scalar helper's static contract, not the full RE-001 function
map. The source symbol/library version and original build recipe remain
unresolved. No Rust reconstruction, rebuilt target bytes, upper-XMM-lane ABI,
caller input-domain proof or whole-node behavior is claimed. Component gates
remain false; no byte window is registered and no completion metric changes.

The next bounded question is whether the calling path's finite-input guards
and subsequent conversion preserve this result for every admitted deployment
input. That caller-wide proof is outside this packet.
