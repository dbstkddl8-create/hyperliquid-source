# RE-014: conditional hardware fusion in the EMA numerator

- Component: foundation EMA arithmetic / release drift.
- Node94 SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
- Node115 SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Base revision: 6d727b9ea2ca4dc497c96a2de35cfba064e14dcc.
- Question: does the selected115 accumulation preserve94's separate product/add rounding, and which runtime paths are actually closed?
- Observation:94 separately multiplies sample by dt before adding the decayed numerator.115 passes the operands through a wrapper/resolver; two measured hardware leaves perform a fused product/add.
- Conditional result: binary64 round-to-nearest/ties-to-even gives a one-ULP numerator difference for the finite positive boundary operands below. This is not a live defect, whole-call reachability proof or claim about every115 path.

## Prior work and scope

PR56 already maps the94 update/accessor; PR95 maps its window guard. They are credited, not resubmitted. This packet binds the later capture's actual pointer chain and compares the local arithmetic. The two source-associated bodies have different surrounding guards; no whole-function/source-build equivalence is claimed.

| Release / role | Actual FDE, original ELF VAs, half-open | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| 94 update-associated body | 0x14791c0..0x1479329 | 361 | 75 |
| 115 update/window-associated body | 0x5a72580..0x5a728ce | 846 | 203 |
| 115 indirect-call wrapper | 0x63f0210..0x63f0221 | 17 | 7 |
| 115 three-operand fused leaf | 0x63f0680..0x63f0686 | 6 | 2 |
| 115 four-operand fused leaf | 0x63f0690..0x63f0697 | 7 | 2 |
| 115 cached resolver | 0x63f06a0..0x63f0711 | 113 | 27 |

Denominator: **six complete FDE bodies, 1,350 bytes / 316 native instructions**.
Original FDE/CIE bytes, offsets/body hashes, full unnormalized exports and independent GNU readelf confirmations are retained. A partial tail or next-index stride is not substituted for a full body.

Actual source Locations bind94 to /home/ubuntu/hl/code_Mainnet/base/src/ema_tracker.rs:42:13 (52-byte path),115 to base/src/ema_tracker.rs:41:13 (23 bytes). Relocations, metadata and LEAs are checked. These are source associations, not recovered original function names or full layouts.

## Local accumulation relation

Let a be sample, t the local dt, n/d previous numerator/denominator, e the local decay result, and RN binary64 rounding. Define c=RN(n*e). These are names for observed operands on a reached normal path, not complete time/exp/window contracts.

94 uses:
    
    0x147929f MULSD XMM2,XMM3       # RN(a*t)
    0x14792a3 MOVUPD XMM1,[RBX]    # prior n,d
    0x14792ab MULPD XMM0,XMM1      # rounded n*e,d*e
    0x14792b3 ADDPD XMM2,XMM0
    0x14792b7 MOVUPD [RBX],XMM2

Its local numerator is RN(RN(a*t)+c); denominator RN(t+RN(d*e)).

115 uses:
    
    0x5a72811 load n into XMM2
    0x5a72816 MULSD XMM2,XMM0      # c=RN(n*e)
    0x5a7281a MULSD XMM0,[R14+8]   # RN(d*e), saved
    0x5a72826 load a into XMM0
    0x5a7282c load t into XMM1
    0x5a72832 call slot0x64e0fd0
    0x5a72838 store returned numerator
    0x5a72843 ADD saved RN(d*e),t
    0x5a72849 store denominator at+8

For either measured hardware leaf its numerator is RN(a*t+c), with no separate rounding of a*t. The prior product c is still rounded separately; the denominator still uses separate multiplication/addition. The entire recurrence is not claimed fused.

Other time/window/decay guards, state stores and helpers remain unclosed. Timestamp stores can precede the numeric call; no transactional/unwind/whole-state guarantee or actual reachability of the witness operands is asserted.

## Runtime chain

Slot0x64e0fd0 is RELATIVE to0x63f0210. This wrapper is a genuine17-byte FDE, **not a PLT entry**: it loads the pointer at0x64ffe00, calls RAX, returns and retains the captured trailing UD2. The slot has a RELATIVE initializer to resolver0x63f06a0. On-disk zero bytes are not treated as the relocated runtime pointer.

The resolver reads u32 cache0x6728920. If bit31 is clear it calls0x63f0730 while preserving XMM0..2, sets bit31 and stores the returned word. On the already-initialized-bit path:

| Raw conditions | Selected target |
| --- | --- |
| bit6 set | 0x63f0680 |
| bit6 clear, bit7 set | 0x63f0690 |
| both clear | 0x63f0230 |

It stores the selected pointer back to0x64ffe00 and tail-jumps. Detector validity and CPU feature-bit meanings are not inferred.

The first leaf is VFMADD213SD XMM0,XMM1,XMM2; RET. The second is VFMADDSD XMM0,XMM0,XMM1,XMM2; RET. Their operand orders both give a*t+c. The [Intel SDM instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2c-manual.pdf#page=142) and [AMD manual43479 VFMADDSD](https://www.amd.com/content/dam/amd/en/documents/archived-tech-docs/programmer-references/43479.pdf#page=50) define combined multiplication/addition before final rounding. The witness assumes ordinary MXCSR rounding, finite normal operands and no unmasked exception.

Bounds-checked but **unmeasured/excluded**: detector0x63f0730..0x63f08d9 (425 bytes), fallback0x63f0230..0x63f0679 (1,097 bytes). No fallback numeric contract or real-machine selection is claimed. This is a conditional hardware-path result, not an assertion that every115 run differs. CPUID/XGETBV and captured leaves are never executed.

## Exact positive witness

Take a=10, binary64 t=0.1, n=2^-53, e=1, d=1. All are positive finite normal operands.

Exactly, a*t=1+2^-54. Its separate rounding is1. Adding2^-53 then reaches a midpoint, so ties-to-even returns1. Fusing instead rounds exact1+3*2^-54 to1+2^-52, one ULP above1.

| Result | Hex binary64 |
| --- | --- |
| 94 separate numerator | 0x1.0000000000000p+0 |
| 115 measured hardware numerator | 0x1.0000000000001p+0 |
| Both local denominators | 0x1.199999999999ap+0 |

The independent stdlib reference uses exact Fractions for the fused expression and distinct boxed binary64 operations for the old path. It models this arithmetic boundary, not a captured instruction stream or clock. It does not establish real history/time/exp/operand reachability. Exact-result controls where both formulas agree are included.

## Reproduce and controls

macOS arm64; Python3.12.14; GNU readelf/objdump2.47.20260726. From repo root with materialized captures and native GNU tools on PATH:

~~~sh
python3 -B tools/ema_fused_release_drift.py --output work/ema-fused-check
# Compare output with this packet except README/spec/manifest.
python3 -B -m unittest discover -s tests -p test_ema_fused_release_drift.py -v
make doctor verify catalogue-check
make reproduce
(cd research/work-items/RE-014-ema-fused-release-drift && shasum -a 256 -c MANIFEST.sha256)
~~~

Both full capture identities and the spec are authenticated before interpretation/output/native calls. GNU tools receive private byte-identical snapshots. Full byte coverage, counts and recorded instruction starts/calls/RIP operands are checked. Exports are unnormalized UTF-8/LF. Wrong-release, truncated and same-size modified inputs fail before output creation.

Six focused tests cover the rational one-ULP witness, exact-result controls, resolved-mask classes, raw dataflow and actual counterfactuals:

- 94 MULSD opcode59->ADDSD58 changes its local numerator formula.
- Hardware VFMADD213SD opcodeA9->VFMADD132SD99 changes a*t+c to a*c+t.
- 115 denominator offset8->0 selects n instead of d.
- Resolver TEST mask0x40->0x20 sends a bit6-only initialized word to unclosed fallback.

Each changed extracted relation is demonstrated before rejection. Additional controls attack low-double loads/stores, both hardware leaves, resolver preservation/decisions, direct/RIP displacements, real RELA addends, source Locations and all six FDE extents. These are equations, not a CPU emulator; modified captures are not run.

This adds a cross-release local arithmetic difference and its dispatch condition. Artifacts/imported source/pins and all component gates stay unchanged. New tools/docs are independently authored under root MIT; no unlicensed inferred implementation is copied. No captured binary/emulator, hardware detection, service, wallet/signing, chain action, hosted CI, Rust reconstruction or complete EMA/protocol/security equivalence is claimed.

Next: close fallback/detector and normal operand reachability before generalizing to every115 path or observable node output.

Observed safe focused results on the current base: six tests passed in32.447s; native output regenerated byte-for-byte. Full repository testing is held because the default suite includes concrete captured-instruction evaluators requiring separate execution scope. The aggregate attempt was interrupted and is not a full-suite PASS. These producer/focused checks use static parsing/disassembly and an independent rational formula, without executing captured instructions.

An aggregate local checkout containing two other independently prepared changes passed496 tests across13 reviewed static-only modules; that is integration evidence, not an exact-head full-suite result for this standalone change. Safe make checks passed on the aggregate checkout. The stopped full-suite attempt remains incomplete.
