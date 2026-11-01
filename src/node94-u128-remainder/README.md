# node94 unsigned128 remainder numerical component

`remainder(u128, core::num::NonZeroU128) -> u128` implements the complete
nonzero-divisor value rule proved from node94's complete 197-byte leaf at
ELFVA `0x565f7f0..0x565f8b5`. The implementation is independently authored,
core-only, unsafe-free Rust with no external dependency or Cargo workspace.
The 128-step high-prefix loop uses no division/remainder operator. The ordinary
unit fixture contains 13 cases extracted from an independently frozen 53,366-case
mathematical authority before `lib.rs` existed. The separately linked production
client receives input-only transcripts and is checked on all 53,366 cases.

The real build scope is this standalone numerical library and its own input-only
I/O client, compiled directly by the authenticated research Rust 1.94.1
(e408947bf, LLVM21.1.8). It is not an original node build or ABI recovery.
No Cargo.lock is applicable: there are no registry or non-core dependencies.
Native bytes, theorem, full-source/artifact provenance, exact recipes, logs,
corruption controls and observed validation belong to
`research/work-items/RE-004-u128-remainder-94/`.

From the repository root, with the explicitly authenticated compiler and archive:

```sh
python3 -B tools/u128_remainder_contract.py --builtins /path/to/libcompiler_builtins-58c8d4715a55733a.rlib --output /tmp/new-native-record
python3 -B tools/u128_remainder_rust.py --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json --output /tmp/new-own-build --controls
python3 -B -m unittest tests.test_u128_remainder_contract -v
```

The numerical domain excludes divisor zero by type. Physical register clobbers,
return-address faults, surrounding signal/unwind handling, caller units/guards,
original compiler/code identity, component completion and whole-node equivalence
remain outside this API. Only new own Rust runs during qualification; captured
code and instruction evaluators never execute.
