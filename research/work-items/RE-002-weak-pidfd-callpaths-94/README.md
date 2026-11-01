# RE-002: node #94 weak pidfd import paths

- Component: build provenance (RE-002); no completion gate requested.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91774280 bytes.
- Source baseline: `15f79350f790a04aed73b5fc9319f85b535f8282`; target bytes are the pinned
  `artifacts/node/94/hl-node` input, not a locally built equivalent node.
- Status: static observations plus explicitly bounded interpretations.
- Question: which instructions reference the weak `pidfd_getpid` and
  `pidfd_spawnp` slots, and what local guard/fallback edges surround them?
  This follows the open question in `RE-002-version-requirements-94`.

## Reproduce

From the repository root, using the materialized pinned artifacts:

```sh
python3 tools/node94_weak_pidfd.py
python3 -m unittest discover -s tests -p test_node94_weak_pidfd.py -v
```

The producer writes `evidence.json`; it does not execute any captured binary.
It uses only Python standard-library ELF parsing, GNU readelf and GNU objdump.
Commands/options, raw-output hashes, instruction bytes, ELF VAs and file offsets,
relocation-record offsets, symbol indices and tool hashes are in that JSON.
The two adjacent objdump files preserve raw FDE-start disassembly; their hashes
match the producer's independently repeated disassembly.

- python3: `Python 3.11.11`; executable SHA-256 `8219d0acbf6e1b78e322a221c438244034afc7d8c9d08b68019ba320de50afbb`.
- readelf: `GNU readelf (GNU Binutils for Debian) 2.40`; executable SHA-256 `afa25ff2dc25a71b79e853b9e3a9abb7b4e8c83efac17c0a637cbbb687442a4f`.
- objdump: `GNU objdump (GNU Binutils for Debian) 2.40`; executable SHA-256 `19717049e8ecd98cfbb17fd9eb25e9fd896ecec2fc4af6b931f3dd0bc4e903de`.

`evidence.json` includes the producer hash and hashes of the full target, FDE
extents, full readelf relocation output, and full frame output. Generation does
not run setup, download dependencies, alter pins, or change component gates.
Platform: Linux, ELF64 little-endian x86-64 input. Python/binutils are the only
analysis dependencies; no model-backed behavior is tested.

## Evidence and coordinates

Independent ELF parsing identifies undefined WEAK symbols 173/182 with
`R_X86_64_GLOB_DAT`, addend zero, at slots `0x5777380` (`pidfd_getpid`) and
`0x57773f0` (`pidfd_spawnp`). GNU `readelf -Wr` agrees on the name/slot bindings.
The weak binding is an observation, not a minimum-glibc or loader conclusion.

| Import | Instruction VA | File offset | Instruction bytes |
| --- | --- | --- | --- |
| pidfd_getpid | 0x4ee3945 | 0x4ee2945 | `48833d333a890000` |
| pidfd_getpid | 0x4ee3955 | 0x4ee2955 | `ff15253a8900` |
| pidfd_spawnp | 0x4ee76fa | 0x4ee66fa | `48833deefc880000` |
| pidfd_spawnp | 0x4ee8320 | 0x4ee7320 | `48833dc8f0880000` |
| pidfd_spawnp | 0x4ee834d | 0x4ee734d | `ff159df08800` |

Scan denominator (executable SHT_PROGBITS sections only):

- `.text`: 70370352 byte offsets; eligible starts for lengths 6/7/8: 70370347, 70370346, 70370345.
- `.init`: 27 byte offsets; eligible starts for lengths 6/7/8: 22, 21, 20.
- `.fini`: 13 byte offsets; eligible starts for lengths 6/7/8: 8, 7, 6.
- `.plt`: 4464 byte offsets; eligible starts for lengths 6/7/8: 4459, 4458, 4457.

Every byte offset is considered for the declared RIP-relative forms: FF 15/25,
REX MOV/LEA with RIP ModRM, and REX 83 3D disp32 imm8. Each form includes its
last complete eligible start, excludes truncated tails, and computes signed
displacements. This is **not** an exhaustive instruction/xref census: register
loads, other encodings, dynamically written pointers and indirect reachability
are outside this denominator. Candidate bytes might otherwise occur inside
instructions. All five observed candidates are confirmed at instruction starts
by complete contiguous GNU disassembly of their covering readelf FDE ranges:

- `[0x4ee38d0, 0x4ee398c)`: 57 instructions.
- `[0x4ee64f0, 0x4ee8b89)`: 1998 instructions.

Coverage is complete only within those two decoded extents and selected scan
forms. FDE coverage is not proof of source-function identity or ownership.
Objdump's nearest exported-symbol labels are not recovered function names.

### Local paths: observations versus interpretation

1. The small extent first calls the slot annotated `ioctl` at `0x4ee3915`.
   A return value of -1 branches to an `__errno_location` import call. Integer
   comparisons with `0x16` and `0x19` condition access to the weak getpid slot.
   At `0x4ee3945` a zero slot branches from `0x4ee394d` to `0x4ee3972`, storing
   the earlier packed value at `[rbx+8]`. A nonzero slot permits the indirect
   `pidfd_getpid` call at `0x4ee3955`; its -1/non--1 result splits error/value
   stores. This supports a local ioctl-first/optional-getpid interpretation,
   not successful execution or decoded Rust result types.
2. In the larger extent, `0x4ee76fa` checks the spawnp slot. A zero value skips
   the small helper call and reaches `0x4ee772b`; the other path calls
   `0x4ee38d0` at `0x4ee770d`, examines an output byte and branches. This is a
   local capability-probe relation, not proof of all callers or helper meaning.
3. State/precondition branches at `0x4ee8304` and `0x4ee8313` can select
   `0x4ee83af`, whose local path calls `posix_spawnp` at `0x4ee83e2`.
   The candidate pidfd path instead checks its weak slot at `0x4ee8320`.
   **A zero slot branches to `0x4ee8753`, not to posix_spawnp.** That local block
   calls an unresolved indirect helper, then jumps to the `ud2` at `0x4ee877b`
   if the helper returns. No unwind/nonreturn semantics are inferred.
4. The `pidfd_spawnp` call at `0x4ee834d` tests its integer return. Zero goes
   to `0x4ee8499`; nonzero constructs a value and calls unresolved helper
   `0x4edac10`. A result-byte check and field comparison with `0x26` can reach
   a store of 2 to byte `0x5788559`, then helper `0x4ef28f0` and exit through
   `0x4ee840d`. This is consistent with disabling a later optional path, but
   does **not** prove an ENOSYS interpretation, a same-call retry through
   posix_spawnp, or behavior on a particular host.

All 17 selected direct edges have exact target and fallthrough instruction
boundary checks. External direct helpers and indirect helpers are recorded as
coordinates/import annotations only; their bodies and semantic closure are not
established. Whole-program reachability and state initialization remain unknown.

## Implementation and controls

The producer and tests are independently authored, additive offline tooling.
No inferred can1357 source was copied; imported binary material retains its
original terms and is not relicensed by the repository's root MIT license.
A plain relocation/displacement scan alone would not establish instruction
boundaries; the additional FDE-start byte/decode comparison is why this packet
is narrower and stronger than treating arbitrary objdump windows as functions.
No Rust reconstruction, normalization masks or target equivalence is claimed.

The scoped file executes real-target production and compares its full report
with the committed evidence. Below-hash controls alter the actual relocation
slot, RIP displacement, branch displacement/condition, and decoded bytes;
validators reject them without relying on a top-level digest mismatch.
Supplementary synthetic tail controls exercise the last eligible starts for
6/7/8-byte forms and reject truncated encodings; these are not target proof.

## Observed results and remaining work

Implementation run: producer returned 5 candidates, instruction counts 57 and
1998, and 17 checked edges. The scoped unittest command ran 8 tests in 12.337s:
all passed (exit 0). The preceding current-base preflight passed `make doctor`
and `make verify`; those are historical implementation-machine observations,
not independent validation of this final tree. Required catalogue/reproduction,
full-suite and independent validation results must be reported separately.
No hosted CI, container result, target execution or runtime compatibility is
claimed. All component progress gates remain unchanged.

Next research question: what precise state initialization/updates select the
optional spawn path across all callers? That requires a separately bounded
helper/state study, not a whole-program conclusion from these local edges.
