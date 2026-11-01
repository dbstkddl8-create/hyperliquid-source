# RE-004: node94 wrapping round-up quotient in Rust

- Component: foundation; one bounded value projection, no component gate requested.
- Source base: `3324e50333042b391312515e542279ca21f63dc8`.
- Node94 capture: SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Addresses below are ELF virtual addresses.
- Function FDE: `[0x4f9ee90, 0x4f9eeac)`, 28 bytes, body SHA-256
  `8b10de3a6ca146497d9b90d33bda8f12ecc373205b430a0eda6e9a63ba9055c6`.
- Getter: `[0x4f9ee80, 0x4f9ee8b)`, 11 bytes, SHA-256
  `0d0a71e699d44caee64d1941f6420f7d24b8542a9951712368272738edba64ea`.

## Gap addressed

The existing `foundation-round-up-division-94` packet maps the instruction
window, getter, frames, padding and one direct caller at `0x4f9aaed`.
It has no independently authored Rust implementation. This contribution adds
that implementation and compiled-client comparisons; it does not claim a new
function discovery. The existing packet at the source base remains unchanged.

The getter loads the dword at object offset `+0x40` and increments it in 32
bits. The caller zeroes RDX, computes `(t-1) mod 2^32`, adds RSI in 64 bits
without propagating the carry to RDX, and performs unsigned DIV by `t`.
For unsigned field `f` and RSI value `x`, the quotient is:

```text
t = (f + 1) mod 2^32
t == 0: native #DE, no quotient
t != 0: (((x + f) mod 2^64) / t), rounded down
```

This is not mathematical ceiling division on the overflow path. With field 1
and `x = 2^64-1`, the native dividend wraps to zero and the quotient is zero.
The Rust API takes the loaded field explicitly and returns `Option<u64>`;
`None` classifies a zero divisor rather than raising a native exception.
It does not implement pointer layout, stack behavior, calling convention,
invalid-memory faults, or binary/ABI identity. RDX remainder is not exposed.

## Evidence and authorship

`contract.py` was written and run before `src/node94-roundup/lib.rs` existed.
It admits the full captured file through the existing static checker, then
compares separately written register-order and integer expressions. The frozen
2,442 cases include 2,048 fixed random inputs and deliberate divisor, quotient,
32-bit getter-wrap and 64-bit numerator-wrap boundaries. The frozen source and
vector hashes are in `preparation/ORACLE-FREEZE.json` and are checked again by
the qualifier. The vectors in preparation and the Rust fixtures are identical.
This is a retained preparation record, not an authenticated external oracle or
a full-domain formal proof.

The existing checker binds exact instructions, target digest, local frame
records, getter, padding, relative call target and direct-caller scan. Its
source and foundation evidence hashes are frozen with this packet. The focused
test changes the DIV instruction and invokes structural checks without the
full-file digest gate, so a checksum refusal is not the sole negative control.
`observed/native.objdump.txt` retains a fresh disassembly of both local bodies.
No captured code was executed, loaded as executable code or copied into Rust.
No can1357 implementation was read or copied for this implementation. The
original compiler and the caller's object-level purpose remain unresolved.

## Reproduce

Use the normal setup to materialize the pinned captures and imports. From the
repository root, with Python 3.12.3, GNU objdump 2.42 and Rust 1.94.1
(LLVM 21.1.8, `x86_64-unknown-linux-gnu`):

```sh
python3 tests/test_roundup_rust_contract.py -v
python3 tools/roundup_rust.py --rustc /path/to/rustc-1.94.1 \
  --output-dir work/roundup-fresh
objdump -d --start-address=0x4f9ee80 --stop-address=0x4f9eeb0 \
  artifacts/node/94/hl-node
make doctor verify catalogue-check
make reproduce
timeout --signal=INT --kill-after=10s 60s make test
```

The qualifier compiles a standalone `no_std`, unsafe-free library and separate
input-only client. No Cargo dependencies or workspace are invented; rustc's
standard library is the only build dependency. Both O0 and O3 use edition 2021
and `-C overflow-checks=yes`. Clients receive case IDs, fields and `x` values,
never expected answers. Exact compiler commands and output are retained in
`observed/commands.json.gz`; only `$REPO` and `$HOME` path prefixes are normalized
there. Original logs remain in ignored `work/`; numeric output is unchanged.
The qualifier verifies the actual emitted LLVM definition of `quotient` and
records its hash; this is not comparison to original machine code.

## Observed result and limits

- O0: 2,442/2,442 static-contract outputs match, zero mismatches, client exit 0.
- O3: 2,442/2,442 match, zero mismatches, client exit 0.
- Compiled mutants (wide getter, saturating add, unadjusted dividend) produce
  22, 56 and 2,328 mismatches respectively. Each client exits 0, while the
  corresponding compiled Rust fixture test exits 101.
- The 3 focused Python tests pass. Both normal Rust fixture tests pass.
- `make doctor verify catalogue-check` and `make reproduce` pass.
- Complete `make test` is **not passed**: a declared 60-second run starts 8 of
  907 modules and completes 7 successfully, then interrupts
  `test_action_dispatch_drift.py`. The timeout wrapper exits 124; the test
  runner records interruption, not an assertion failure. No failed-test summary
  was observed before the interrupt. This is incomplete coverage, not a
  complete suite result. See `observed/GLOBAL-TEST-STATUS.json` and the raw
  compressed log. The focused new tests ran separately to completion.

`observed/results.json` binds the compiler, source, clients and output hashes.
All four full-component gates remain false. No raw-byte equivalence, original
compiler recovery, native exception emulation, target execution, full-domain
equivalence, hosted CI, container result, node115 behavior, financial meaning
or whole-component completion is claimed. Next: establish the caller's field
layout and ownership before attempting a pointer-level or caller integration.
