# RE-001: what does node #94's field-positive call 0x514b0f0 with its callee 0x5228fe0 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about two target instruction windows and the
  composed behavior they implement; the source-level name of the object,
  the meaning of the +0x1100 field, and the identity of the other eleven
  direct callers of the callee remain inferences/unresolved.
- Scope included: the 33-byte entry FDE window 0x514b0f0..0x514b111, its
  12-byte callee FDE window 0x5228fe0..0x5228fec, the call site that joins
  them, the composed rule, both FDE records, both padding runs, and the
  full direct-e8 caller censuses for both windows.
- Scope excluded: the neighboring window 0x514b0d0 (a guarded field read
  with a different protocol — deliberately not folded in), what the
  +0x1100 field means, what calls the entry window (zero direct e8
  callers found; indirect reach is not established), the purpose of the
  callee's other eleven direct callers, and any wider family.

## Why this packet is one complete behavior, not a lone window

The entry window alone would be a fragment: it delegates its whole
decision to a call. The callee alone would be a fragment: a 12-byte
positive-test whose full return value is not even a clean 0/1 (see
below). Bound together, entry plus callee form one behavior that is
observable end to end: an input object base in rdx and an out pointer
in rsi go in, and a clean 0/1 flag plus a constant return of 1 come
out, with no unresolved step in between. That is the unit this packet
pins, and the checker verifies both windows, the call site, and the
composed rule — not one window's constants.

## The rule, exactly as the bytes state it

Entry (0x514b0f0): push rbx; rdi = rdx + 0x1100; rbx = rsi (the out
pointer); call 0x5228fe0; movzbl %al,%eax; [rbx] = rax; eax = 1;
pop rbx; ret. rbx is preserved, the stack is balanced (one push, one
pop, no rsp adjustment), and the return value is 1 on every path.

Callee (0x5228fe0): eax = int32 at [rdi]; test eax,eax; setg %al; ret.
The comparison is signed 32-bit: the field is read with a 32-bit mov
and tested as eax, so 0x80000000 counts as -2147483648, not as a large
positive.

Composed: out = 1 iff int32 at [rdx + 0x1100] > 0 (signed); otherwise
out = 0. Return value 1 always.

## The subtlety the entry's movzbl exists for

The callee's full rax is NOT a clean 0/1. Its mov loads the 32-bit
field zero-extended, and setg rewrites only the low byte, so the
callee returns (field & 0xFFFFFFFFFFFFFF00) | low, where low is 1 iff
the field is positive — for example field 0x12345678 yields callee rax
0x12345601, and field -1 yields 0xFFFFFF00. The entry's movzbl
%al,%eax after the call discards those upper bytes, which is exactly
what makes the composed output a clean 0/1. A model that claims the
callee itself returns 0/1 would be wrong; the tests pin this
distinction (callee full value vs. composed output) explicitly.

## Verbatim evidence note

The disassembly excerpts in entry.objdump.txt and callee.objdump.txt
are the unmodified output of GNU objdump 2.42 for the two FDE ranges
(the commands are under Reproduce below), including the int3 padding
lines that follow each ret up to the next FDE start. The instruction
entries in evidence.json copy the mnemonic, operands and raw bytes
from that output exactly — nothing paraphrased, shortened or
sanitized. In particular, `endbr64` is a genuine instruction present
in the target binary (the first instruction of both windows), not a
placeholder: it appears in objdump's own output as
`f3 0f 1e fa  endbr64`, and the checker verifies those four bytes at
both window starts against the digest-verified binary.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No cargo, rustc, git-lfs,
Ghidra or Java was used; GNU `--dwarf=frames` output supplies the
retained frame records.

The work binary used here is the materialized node #94 copy whose
SHA-256 matches provenance/artifacts.json
(`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`);
on a materialized checkout the same bytes live at
artifacts/node/94/hl-node. The excerpts were produced with:

```sh
objdump -d --start-address=0x514b0f0 --stop-address=0x514b120 work/hl-node-94.bin
objdump -d --start-address=0x5228fe0 --stop-address=0x5228ff0 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_positive_field_call.py --check research/work-items/foundation-positive-field-call-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_positive_field_call -v
```

## Evidence

- Entry FDE: offset 0x0029a428,
  pc=000000000514b0f0..000000000514b111, 33 body bytes, SHA-256
  `38b9441779d14b5be7b20fbcff4bf8538f94af204a932539554eeac8a7ad77cd`,
  15 int3 padding bytes to next FDE 0x514b120.
- Callee FDE: offset 0x002a47f0,
  pc=0000000005228fe0..0000000005228fec, 12 body bytes, SHA-256
  `b8cdd5de9fdda674bc2613a0f80c7dfde6b6f151bdecb6efd3f55c8aa06854f4`,
  4 int3 padding bytes to next FDE 0x5228ff0.
- Call site: 0x514b0ff, bytes `e8 dc de 0d 00`; 0x514b0ff + 5 +
  0x000dde dc = 0x5228fe0, the callee start exactly.
- Entry direct e8 callers: none in a full .text scan. This is a
  negative result about direct calls only; it does not claim the
  window is unreachable.
- Callee direct e8 callers (full .text scan, 12 sites): 0x4feb909,
  0x503594b, 0x503fa27, 0x504157f, 0x505c899, 0x505d8c0, 0x50e6cc5,
  0x50e6cfb, 0x50e7471, 0x50ee21d, 0x512bdf9, and this entry's own
  0x514b0ff. No caller purpose is claimed for any of them.
- Overlap check before building: repo code search for `514b0f0`
  returns 0 hits; for `5228fe0` it returns 1 hit, which is only a call
  site line inside another packet's caller disassembly
  (foundation-pointer-mark-walk-94, site 0x504157f) — not a claim on
  this entry window or on the composed behavior. No open WalkCrypto
  PR covers either window.

## Results and limitations

The checker passes in packet mode and in binary mode against the
digest-verified work binary; all unit tests pass, including boundary
edges (INT32_MIN, -1, 0, 1, 256, INT32_MAX), the callee-full-value
quirk, and corruption controls (mutated field offset, mutated call
target, mutated padding, mutated rule edge each fail). Repo-wide
`make catalogue-check` was not re-run: it fails on the pre-existing
LFS-pointer identity error before reaching this change, as recorded
for the preceding submissions; that failure is not a regression from
this PR.

Remaining unknowns, stated not buried: what the object at rdx is, what
the +0x1100 field represents, how the entry window is reached, and
whether the callee's other callers share this entry's object layout.
No Rust reconstruction is claimed; the Python model is a behavioral
model of the two windows only.

Next question: does any caller of the entry window, or any consumer
of the +0x1100 flag, share this object layout — and is the neighbor
0x514b0d0's guarded read (fields +0x1104/+0x1128) part of the same
object's protocol, or a different one?
