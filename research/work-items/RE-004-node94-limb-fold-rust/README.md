# RE-004: independent Rust for node94's five-word limb-fold contract

Target: Linux x86-64 node **#94**, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `b7fa68995114d0df89dac43be3076f4494bd9dc3`. Component: `foundation`.
All addresses are ELF virtual addresses before any load bias.

## Gap and bounded progress

The prior [static packet](../foundation-multi-limb-multiply-accumulate-94/README.md)
binds the 123-byte leaf `0x56327f0..0x563286b` and three direct callers, but
explicitly excludes Rust reconstruction. This packet supplies a separately
buildable, independently authored core-only Rust numeric projection over all
five input words, plus a full bit-vector equation proof and actual compiled
Rust qualification. It does not re-claim the earlier mapping as new work.

The exact body SHA-256 is
`2e413a86c8670e24e30144a0d9281fc2ed3a470d6772ed9cd53def98b4c6ecaa`.
Admission rechecks the full capture, FDE/CIE bytes and neighboring extent,
31 fixed instruction rows, five padding bytes, the no-call body, no naming
relocation slots, and incoming sites `0x563b803`, `0x563bc5f`, `0x5640242`.
The existing caller FDEs remain explicit; this is not a new global xref census.
Fresh GNU output is retained as [native.objdump.txt](preparation/native.objdump.txt).

## Established numeric contract

Write the original five little-endian words as `a0..a3,h`, let
`C = 2^32 + 977`, and define:

```
x0 = ((h >> 48) * C + a0) mod 2^64
xi = (ai + (x[i-1] >> 52)) mod 2^64, i = 1..3
out[i] = xi & (2^52 - 1), i = 0..3
out[4] = (h & (2^48 - 1)) + (x3 >> 52)
```

Discarding bit 64 **before** each carry shift is load-bearing. An unbounded
base-2^52 reduction is not an equivalent implementation over the full input
domain. The upper 16 bits of `h` times `C` fit in 48 bits. Each subsequent
carry is at most 4095, and the last sum fits in 49 bits. No final high-word
mask is invented. The integer's purpose, a field modulus, source-level type,
and caller-wide cryptographic or business meaning remain unknown here.

These observations assume an ordinary readable/writable 40-byte input region,
stable code, valid call/return context and no asynchronous memory interference.
The original writes in place and returns the initial base pointer in RAX.
The new `fold_high_bits([u64; 5]) -> [u64; 5]` is a deliberately chosen safe
value API: it does not recover that ABI, physical write order, aliases with
code/stack/other objects, clobbers, or fault behavior.

## Proof and implementation separation

[contract.py](contract.py) was written and admitted before the Rust source.
Its [freeze](preparation/ORACLE-FREEZE.json) records `new_rust_exists_at_freeze=false`.
A separate agent context reviewed the byte/register equations before authoring;
the exact review scope and source hash are in
[PRE-RUST-REVIEW.json](preparation/PRE-RUST-REVIEW.json).

For arbitrary five 64-bit symbolic words, Z3 4.15.4 returns **UNSAT** for any
difference between the fixed native register equations and the wide-add,
low-64-bit truncation recurrence implemented by Rust. No input-bound assumption
limits this numeric 320-bit domain. Two malformed recurrences (wrong coefficient
and retaining discarded bit 64) produce **SAT** counterexamples. This is a
proof of the admitted equations under their stated machine/memory premises,
not execution of the capture or a machine-code proof of the research compiler.

The frozen 1,331 labeled cases include duplicate edge probes: zero/all-ones,
35 single-word boundaries, 14 carry/high-word combinations, 1,024 full-u64
synthetic cases and 256 52-bit-limb cases. Fresh admitted equations must
regenerate the exact frozen bytes before qualification proceeds. They support,
but do not replace, the all-input equation proof.

The [Rust library](../../../src/node94-limb-fold/lib.rs) uses wide u128 additions
followed by explicit low-word extraction. It contains no captured machine bytes,
unsafe code, inferred unlicensed source, fake dependency, or target invocation.
Its actual build scope is a standalone library/client/test pipeline, not a root
Cargo workspace. Rust 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`) is the
pinned **research** compiler, not a recovered original node compiler.

## Actual qualification

[RESULT.json](observed/RESULT.json) and its compressed, path-normalized process streams
[RAW-LOGS.json.gz](observed/RAW-LOGS.json.gz) retain:

- ordinary O0 and O3 production libraries, each with 1,331/1,331 matching
  complete outputs from a separately linked client;
- one actual Rust unit test per profile covering all 1,331 frozen rows;
- three compiled, normal-returning semantic mutants with 1,280, 8 and 1,036
  client mismatches respectively, and actual assertion-failing unit exits 101;
- actual compiler identity, source/library/IR hashes and one inspectable emitted
  `fold_high_bits` function definition for every variant;
- unchanged production source hashes and a repeated target admission after runs.

Clients receive only case IDs and five input words. Expected answers exist in
the qualifier and cfg(test) fixtures, not in production input or library code.
This is reviewed data flow, not filesystem-capability isolation. Only our own
Rust programs are executed. No target, transplanted target bytes or x86 emulator
is run. There is no raw/normalized target-code equality claim or new compared-byte
denominator. Every full component gate remains false.

The preliminary numeric run passed, but its O3 IR was metadata-only because
cross-crate compilation could defer the function body. That original result and
streams are retained under [initial-numeric-run](preparation/initial-numeric-run).
Adding `#[inline(never)]` exposes the own-library body for inspection; the final
qualifier requires its presence. The original run is not presented as inspected
function-body evidence.

## Reproduce and limits

Install the optional proof dependency `z3-solver==4.15.4.0` in a Python 3.10+
research environment. The Rust component has no registry dependencies.

```sh
python3 tools/limb_fold_rust.py --binary artifacts/node/94/hl-node \
  --rustc /path/to/verified/rustc-1.94.1 --output work/new-limb-fold-run
python3 -m unittest discover -s tests -p test_limb_fold_rust_contract.py -v
make doctor verify test catalogue-check
make reproduce
```

The four focused Python controls pass with the pinned proof dependency.
`make doctor`, `make verify`, `make catalogue-check` and `make reproduce`
pass with all pinned inputs and seven pinned submodules materialized. The
required complete test run was interrupted at the user's choice: 74 of 902
modules started, 73 completed, and module 74 (`test_bridge_eth_event_wire.py`)
was interrupted. The runner exited 130 and explicitly reported an incomplete
inventory. This is **not a complete-suite pass**. Optional captured-emulation
tests stayed disabled (Unicorn absent and execution opt-ins unset).

Public command logs replace personal output-directory, repository and home
path prefixes with `$WORK`, `$REPO` and `$HOME`. Numeric outputs, exits and all
other fields remain unchanged. Unmodified private streams remain only in
ignored local storage, including the original preliminary run; that run's
separate normalization record binds the original and public gzip hashes.
The qualifier reproduces the same path-only normalization and retains its
private stream file solely inside its ignored work output directory.

Neither focused
success nor green tooling establishes a whole-node reconstruction, original
ABI/compiler recovery, captured dynamic equivalence or security assurance.
New source/docs use MIT. The capture and derived disassembly retain their
upstream ownership; no unlicensed can1357 implementation was copied.
