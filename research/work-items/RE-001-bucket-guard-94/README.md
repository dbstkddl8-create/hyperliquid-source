# RE-001-bucket-guard-94: what one shared body behind 47 `base/src/bucket_guard.rs` Location references does

- Component ID: foundation (shared bucket-guard state; serde field tables name `bucket_guard`, `alert_bucket_guard`, `stakes_decay_bucket_guard`, `stage_reward_bucket_guard`, `distribute_reward_bucket_guard`, `prune_bucket_guard`, `reset_recent_oi_bucket_guard`, `ensure_order_bucket_guard` across components)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: base `15f79350`; reference files not used for this packet
- Claim status: observation (semantic labels below are marked as inference)
- Scope included: five Location structs, one shared update body, three reached helpers, 47 reference sites, GOT closure. Scope excluded: container element semantics behind the 0x260 stride, alert sink, threshold field decoding, serialization, any execution.

## Reproduce

```sh
python3 tools/bucket_guard_static.py --output research/work-items/RE-001-bucket-guard-94
python3 -m unittest tests.test_bucket_guard_static
```

Windows, Python 3.11.9, capstone 5.0.7 only (no binutils on PATH). The tool authenticates the binary against `provenance/artifacts.json` before reading. Two regenerations under different `PYTHONHASHSEED` and `TZ` produce byte-identical `records.json`.

## Evidence

Virtual addresses, file-backed reads, `.eh_frame` FDE bounds parsed in-repo (`fde_extents.eh_frame_records`), capstone 5.0.7 disassembly with byte records authoritative. Full machine-readable records in `records.json`; labeled bodies in `update-body.disasm.txt`, `line66-helper.disasm.txt`, `time-source.disasm.txt`, `container-index.disasm.txt`.

### Observations

- The file string `/home/ubuntu/hl/code_Mainnet/base/src/bucket_guard.rs` (53 bytes) sits at VA `0x1e2490`. Five `core::panic::Location` structs point at it through R_X86_64_RELATIVE addends: `0x5666b68` (line 66 col 84) and `0x569e0a0`/`0x56e9e20`/`0x5718b20`/`0x572e848`, four identical copies of line 118 col 21.
- Census over the whole `.text` (16,649,471 instructions): exactly 47 `lea` sites reference those five structs — 1 / 11 / 10 / 1 / 24. Every one of the 46 line-118 sites is followed within its instruction window by `call qword ptr [rip+…]` resolving through GOT slot `0x576efb0` → `0x14027b0`; the single line-66 site calls through GOT `0x576e048` → `0x157aa10` (panic formatting). Site addresses and containing FDEs are listed in `records.json`.
- The shared body `0x14027b0` (FDE `0x14027b0..0x1403c29`, 5,241 bytes):
  - Clock: `call [GOT 0x576e8a0]` → `0x151cba0`, which calls `0x4ee3800` with clockid 0, converts through `0x4ee3730`, and decomposes with 86400-second (0x15180) magic `0x1845c8a0ce512957` plus a civil-date range check and a call through GOT `0x576e890`. The first result dword is the per-call bucket key.
  - Bucket change (`cmp [rbx+0x240], ebp` at `0x14027e5`): zeroes two f64 at `+0x200` (`movupd` at `0x14027f1`), a qword at `+0x210`, a conditional slot at `+0x58`, a qword at `+0x50`, then stores the new key at `+0x240`, a full timestamp qword at `+0x244`, and a nanos dword at `+0x24c`.
  - A byte at `+0x25c` equal to 1 multiplies the integer weight (`rsi`) by 50 (`0x32` at `0x1402840`) as a checked multiply; overflow saturates to `u64::MAX` (`0x1403b1a`).
  - Negative amount: `ucomisd` against 0.0 (`0x140285e`); below zero panics with `assertion failed: self.0 >= 0.` (30 bytes at `0x219f59`) through GOT `0x576e108` → `0x157b7f0` with Location `0x566ae58` = `base/src/duration.rs:124:13`.
  - Saturating accumulators: u64 weight total `+0x200` (`add`/`cmovb` at `0x14028a5`..`0x14028be`), u64 count `+0x208`, f64 total `+0x210` += f64(weight)×amount, where the u64→f64 conversion uses the 2^52/2^84 constant pair at `0x202ea0`/`0x203e80`.
  - Two f64 sample buffers: A {capacity `+0x40`, base `+0x48`, index `+0x50` decremented with an add+`cmovae` wrap, count `+0x58` clamped to `+0x1f8`}, storing the raw amount (`movsd [rdx+rax*8]` at `0x1402943`); B {capacity `+0x60`, base `+0x68`, head `+0x70` incremented, count `+0x80`, integer total `+0x78`, f64 total `+0x88`}, storing at `0x14029b8`; growth through GOT `0x576e930` → `0x146a780` and GOT `0x576ec88` → `0x13eda00`; a running maximum at `+0x90` (`maxsd`).
  - Evaluation stage: when dword `+0x228` is set and the elapsed time since `+0x250` (subtraction through GOT `0x576e8c0` → `0x1447130`, the shared chrono Time-Sub helper) exceeds `1e-15` (constant `0x20b080`), buffer B is moved out (replaced by an empty allocation with dangling base 8), sorted (small path `0x13d50e0` under 21 elements, otherwise GOT `0x576ec00` → `0x13e9a40`), and the elements at index `floor(len×50/100)` and `floor(len×95/100)` are read, with the index computed as a magic multiply by `0x28f5c28f5c28f5c3` shifted right twice (division by 25 after a shift by 4 = 100; verified exact for 1..512, 1000, 4095, 4096, 100000). The buffer is released through GOT `0x576e010` → `0x54c8cb0`.
  - A `Result::unwrap` panic path at `0x1403adc` formats `called `Result::unwrap()` on an `Err` value` (43 bytes at `0x219daa`) through GOT `0x576e048` with Location `0x566aac8` = `base/src/time.rs:62:44`.
- The line-66 helper `0x13c8e10` (FDE `0x13c8e10..0x13c8f53`): checked multiply of two qwords (saturating), decomposition by magics `0x20c49ba5e353f7cf` (÷1000) and `0x31b5d43afe99ef` (÷1e6) into {key qword at `[rbx]`, micros dword at `[rbx+8]`}, and on the fallible date build `0x14509a0` returning Err it panics through GOT `0x576e048` with Location `0x5666b68` = `bucket_guard.rs:66:84`.
- The line-118 Location argument is loaded into `rdx` at all 46 sites, but the shared body never reads `rdx` before the first clobber (`0x14028af`); its own panic paths carry other Locations.
- Callers resolve the state pointer through a container index helper `0x2879470` (FDE `0x2879470..0x287960b`) whose fast path computes `base + index×0x260` (608-byte stride) and whose slow path consults a keyed structure with an `i64::MIN` sentinel at the first qword.

### Inferences (labels, not byte facts)

- "+0x25c ×50" reads as a surge or relaxed-capacity mode; the per-bucket reset plus saturating weight totals read as a rate allowance of 50 events per unit weight per bucket.
- The 50/95 index extractions over a sorted window read as median and P95 alert thresholds; `1e-15` reads as "any positive elapsed time", i.e. a cooldown gate.
- The four identical line-118 Location copies and the 11/10/1/24 caller clusters read as per-codegen-unit duplicates of one generic call context, not four distinct source functions.
- The date-derived first dword of the clock result reads as the bucket key; its exact granularity (day vs derived epoch) is not proven here.

## Implementation and comparison

Not yet implemented: no Rust reconstruction; this packet is static analysis only. No differential comparison, fixtures, or two-build result; the question answered is structural, not equivalence.

## Results and limitations

- 47/47 reference sites resolved to one shared body or the line-66 panic path; denominators: 5 Location structs, 47 sites, 15 verified relocation slots, 16 anchor controls, 5 constant pools, 4 FDE extents (from 121,299 parsed FDEs, count cross-checked against the retained inventory by `tools/fde_extents.py`).
- Mutation controls: single-byte flips at each anchor control, each constant pool byte, the file string, and Location struct fields all make `controls`/`locations` fail closed (9 tests, no skips).
- Unknown: the alert comparison sink after the median/P95 reads, the threshold fields' decoding, the container type and key behind the 0x260 stride, and why the passed line-118 Location is dead in this body. No gate claimed; no execution, networking, chain actions, signing, or Rust build.

Next question: what consumes the sorted-window comparison results — the callee or state written after `0x1402c90` — and which container type owns the 608-byte slots the 46 callers index into.
