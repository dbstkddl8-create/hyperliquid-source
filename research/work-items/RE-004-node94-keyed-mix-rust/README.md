# RE-004: node94 keyed multiply/XOR numeric projection in Rust

- Component: foundation; one bounded arithmetic leaf, not a recovered crate.
- Source base: `3324e50333042b391312515e542279ca21f63dc8`.
- Target: node94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Addresses are ELF virtual addresses.
- Function: FDE `[0x399c600, 0x399c646)`, 70 bytes, body SHA-256
  `03a9ea4d6ef3a449f21050b721a7fcef1115ad7953ee29683b7889948067b492`.

## New result and scope

The existing `foundation-keyed-multiply-xor-mixer-94` packet binds this leaf's
instructions, frame records, GOT relocation and two direct callers. It has no
Rust implementation. This packet adds independently authored, unsafe-free
`no_std` Rust and separately linked O0/O3 clients for its numeric value rule.
It builds on that mapping rather than claiming a new function discovery.

The native routine reads overlapping little-endian **qwords** at byte offsets
0, 4, 8 and 12, spanning 20 bytes. The Rust API takes that entire byte array,
the seed value loaded through RDI, and two explicit runtime key words. The
original GOT slot points to a key table that can be initialized later; neither
its initialized contents nor its owner is established here.

For qwords `q0, q4, q8, q12` and keys `k0, k1`, the numeric rule is:

```text
p = (q12 XOR k0) * (q8 XOR k1)        unsigned 64-by-64 -> 128
r = (q4 XOR k0) * (q0 XOR seed)      unsigned 64-by-64 -> 128
t = low64(p) XOR high64(p) XOR low64(r) XOR high64(r) XOR 0x14
z = t * k0                         unsigned 64-by-64 -> 128
return low64(z) XOR high64(z)
```

The complete straight-line disassembly is retained in
`preparation/native.objdump.txt`. The existing admission checker revalidates
the full capture identity, exact body/FDE, padding, GOT/RELATIVE data edge,
caller frames and calls at `0x32ad5f3` and `0x32aea63` before qualification.
The pattern scan is not a complete indirect-xref census.

RE-001 supplies the local frame/caller evidence; RE-002 supplies only the
explicit research compiler pin. The original target compiler remains unknown.
No captured execution is performed, so no RE-003 execution claim is made.
No can1357 implementation was read or copied for this Rust implementation.
Existing inferred labels and historical unretained emulator claims are not
used as a new validation gate.

## Expectations frozen before Rust

`contract.py` contains separately written register-order arithmetic and a
whole-integer byte-window model. Their 1,844 deterministic cases cover all
160 individual input bits, key/seed limits, repeated-byte blocks and a fixed
random corpus. Their agreed expectations and source hash were frozen before
the new Rust directory existed. `preparation/ORACLE-FREEZE.json` retains that
record; qualification checks its hashes and regenerates the cases exactly.

A preliminary comment-only freeze was corrected before writing any Rust:
an inaccurate instruction-count comment and unused import were removed.
The correction is recorded in the final freeze, and the expectations did not
change. This is an agent's chronology record, not independent peer review.

This comparison is **sampled**. It is not a full-domain formal proof, a run of
the captured code, or a proof that Rust is equivalent to the complete binary.

## Compiled qualification and controls

Rust 1.94.1, LLVM 21.1.8, edition 2021, overflow checks enabled. The library has
no package dependencies or invented workspace/lockfile. Clients are compiled
and linked separately. Their stdin includes only case IDs and inputs, never
expected answers. Frozen answers are present only in `cfg(test)` fixtures.

| Actual compiled variant | Cases | Mismatches | Rust fixture exit |
| --- | ---: | ---: | ---: |
| Production O0 | 1,844 | 0 | 0 |
| Production O3 | 1,844 | 0 | 0 |
| Wrong overlapping load offset | 1,844 | 1,088 | 101 |
| Drop first product's high half | 1,844 | 1,296 | 101 |
| Change `0x14` to `0x10` | 1,844 | 1,484 | 101 |

All clients, including mutants, exit normally with status zero; comparison
detects the wrong results. The independently compiled Rust fixture tests also
reject every mutant. Emitted LLVM IR must contain the actual `keyed_mix`
entry definition, rather than only metadata or a closure. The initial generic
entry selector also matched the O0 closure and refused qualification; the
original refusal and correction are retained under `preparation/`.

`observed/RESULT.json` binds compiler identity, product/contract/checker sources,
artifacts, comparison counts and the selected IR definition. These hashes
identify this run, not cross-path byte reproducibility or original code identity.
`observed/RAW-LOGS.json.gz` retains argv, stdin hashes, outputs and exits, with
only local output/repository/home path prefixes normalized to `$WORK`, `$REPO`
and `$HOME`. Original private streams stay only in ignored local `work/`.

## Reproduce and validation limits

Use the normal repository setup to materialize pinned Git LFS inputs and all
seven pinned submodules. Existing native tools were used: Python 3.12.3,
GNU objdump 2.42, Git LFS 3.4.1 and ripgrep 14.1.0. Then:

```sh
python3 tools/keyed_mix_rust.py --binary artifacts/node/94/hl-node \
  --rustc /path/to/rustc-1.94.1 --output work/new-keyed-mix-run
python3 -m unittest discover -s tests -p test_keyed_mix_rust_contract.py -v
make doctor verify catalogue-check
make reproduce
make test
```

The three focused Python checks pass, including an instruction-byte corruption
control that reaches the structural checker without relying on the complete
capture hash. `make doctor verify catalogue-check` and `make reproduce` pass;
doctor reports analysis ready and exact rebuild not ready. Full-suite status
is recorded in `observed/GLOBAL-TEST-STATUS.json`; do not infer a complete pass
from the focused results.

Only new Rust and static parsers execute. The target is never launched,
transplanted or emulated; Unicorn is absent and captured-emulation opt-ins are
unset. The safe value API does not recover native pointer ABI, caller meaning,
runtime key initialization, aliasing/volatile loads, fault behavior or a whole
component. All full-scope gates stay false. Next: independently review the
numeric contract and establish caller-owned key initialization and ABI scope
before any broader reconstruction claim.
