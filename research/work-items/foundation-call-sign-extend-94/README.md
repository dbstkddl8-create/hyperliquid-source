# RE-001: what does the call-and-sign-extend window at 0x514ad90 compute?

- Component ID: `foundation`, one small window; its source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for the window's rule; inference for the
  container reading; unresolved for source names, types, the callee's
  semantics, and callers.
- Scope included and excluded: included are exactly the one FDE window
  `0x514ad90..0x514adc3`, its int3 padding, its FDE record, and a
  direct-caller census for it. Excluded are the preceding window at
  `0x514ad70` (delegating call with a plain qword store, bound in
  #1290, not claimed here), the following window at `0x514add0`
  (different protocol — pushes rbx, adds `0x8f0` to the field before
  its call, then sign-extends with `cltq` — not claimed here), all
  #115 addresses, target execution, and Rust reconstruction.

## Why this packet

The window pairs a call with a sign-extended field read, and neither
half alone states its rule: it passes `container + 0x700` as the
callee's first argument to `0x5334d60`, then stores
`sign_extend32(int32 at [container + 0x1440])` to `[rsi]`,
preserving `rbx` and `rbp` and returning 1. The callee's result is
not used — the stored value comes from the field read after the
call — so the call must be a side-effecting step (or a guard whose
result this window discards), and that ordering is part of the claim.
It is bound alone, as one bounded work item, because its protocol
(call + post-call sign-extended read) matches neither neighbor.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame record.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ad90 --stop-address=0x514add0 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so it
cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was verified
to equal the provenance digest for node #94 (`3b7179cd…c0459f`,
91,774,280 bytes) before any byte was read from it. The checker
therefore takes an optional `--binary` argument: without it, it
verifies the packet files against each other (retained disassembly
bytes, FDE record, padding, rule edges); with it, it additionally
verifies the target digest, the window bytes, the padding, the FDE
pc range, and the direct-caller scan against that binary. On a
checkout where the LFS artifact is materialized, run the binary form
with `--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_call_sign_extend.py \
    --check research/work-items/foundation-call-sign-extend-94/evidence.json
python3 tools/foundation_call_sign_extend.py \
    --check research/work-items/foundation-call-sign-extend-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_call_sign_extend -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; the checker resolves every VA through the ELF section headers
rather than assuming VA equals file offset. Boundaries are the FDE
pc range, validated below against the `.eh_frame` record.

Window `0x514ad90` (51 bytes, FDE `.eh_frame+0x0029a214`, range
`0x514ad90..0x514adc3`, SHA-256
`c0628168c21451d9fe786233f32a325f2a5ffef2b0b090f2eb73f93ca3740d6f`,
13 int3 padding bytes to the next FDE at `0x514add0`):
`endbr64; push %rbp; lea 0x700(%rdx),%rdi; mov %rsi,%rbp;
push %rbx; mov %rdx,%rbx; sub $0x8,%rsp; call 0x5334d60;
movslq 0x1440(%rbx),%rax; mov %rax,0x0(%rbp);
add $0x8,%rsp; mov $0x1,%eax; pop %rbx; pop %rbp; ret`.
Rule: call `0x5334d60` with first argument `container + 0x700`,
then out = sign_extend32(int32 at `[container + 0x1440]`);
return 1; `rbx` and `rbp` preserved, stack balanced.
Direct e8 callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container and its fields at
  `0x700` and `0x1440` are not established by these bytes.
- What the callee at `0x5334d60` does with `container + 0x700`,
  and whether its result matters elsewhere, is not established
  here — this window discards the callee's return value.
- The `0x514add0` window (different protocol) is a separate item
  and is deliberately not folded into this bind.
