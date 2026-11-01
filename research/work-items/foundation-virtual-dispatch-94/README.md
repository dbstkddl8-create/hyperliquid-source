# RE-001: what does node #94's virtual-dispatch window 0x514b170 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about one target instruction window, the
  zero-returning function its guard compares against, and the GOT
  relocation record that resolves the guard value; the source-level
  name of the object, the meaning of the +0x788/+0x950/+0x30 fields,
  and the identity of the indirect callee on the slow path remain
  inferences/unresolved.
- Scope included: the 79-byte entry FDE window 0x514b170..0x514b1bf,
  its 7-byte guard-target FDE window 0x4fe8fe0..0x4fe8fe7, the GOT slot
  at 0x5777f18 and its R_X86_64_RELATIVE relocation (addend
  0x4fe8fe0), the rip-relative cmp that joins entry to slot, the
  indirect call on the slow path, both FDE records, both padding runs,
  and the full direct-e8 caller census for the entry window.
- Scope excluded: the neighboring window 0x514b120 (a 3-way selector
  store that returns 0 and uses no container chain — a different
  protocol, examined and deliberately not folded in), the neighbor
  0x514b160 (a tiny delete thunk: mov $0x28,%esi then jmp — different
  protocol), the following window 0x514b1c0 (unexamined), what calls
  the entry window (zero direct e8 callers found; indirect reach is
  not established), what the slow-path callee does beyond returning a
  byte, and any wider family.

## Why this packet is one complete behavior, not a lone window

The entry window alone would be a fragment if its guard were
unexplained: it compares a loaded slot against a GOT slot and either
stores 0 or calls the slot. This packet closes that gap instead of
leaving it as an unknown. The GOT slot's relocation record resolves at
load time to the function 0x4fe8fe0, and that function is itself a
retained FDE window whose whole body is endbr64, xor %eax,%eax, ret
— it returns 0. So the fast path stores exactly what the slow path
would store if it called the guard target (0, zero-extended from the
low byte), and the slow path is the general case: call whatever slot
the object actually carries and store its low byte. Both paths, the
guard's meaning, the call's arguments and the constant return of 1
are pinned; no step in between is unresolved. That is the unit this
packet pins, and the checker verifies the entry window, the guard
window, the relocation, the cmp arithmetic and the composed rule —
not one window's constants.

## The rule, exactly as the bytes state it

Entry (0x514b170): push rbx; rcx = [rdi+0x788] (container root, the
same first hop as the neighboring container windows); rbx = rsi (the
out pointer); rdi = [rcx+0x950]; rax = [rdi] (the field object's
head); rdx = [rax+0x28] (the slot); xor eax,eax; cmp the slot against
the qword at 0x5777f18; jne to the slow path at 0x514b1a8.

Fast path (slot equals the guard value): [rbx] = rax (0, set by the
xor before the cmp); eax = 1; pop rbx; ret.

Slow path: rsi = [rcx+0x30] + 0x40; call *%rdx with rdi = the field
object, rsi = that adjusted base, rdx = the slot value itself and rcx
= the container root; movzbl %al,%eax; [rbx] = rax; eax = 1; pop rbx;
ret. rbx is preserved, the stack is balanced (one push, one pop, no
rsp adjustment), and the return value is 1 on every path.

Composed: out = 0 without calling when the slot equals the
runtime-resolved guard target (load base + 0x4fe8fe0); otherwise out
= (indirect callee result) & 0xFF after calling the slot. Return
value 1 always.

## The subtlety: the GOT slot's file bytes are zero, but the guard value is not

The GOT slot at 0x5777f18 lies in .got, and its eight file bytes are
zero — because GOT slots are filled by the dynamic loader, not stored
in the file. Reading the file bytes as the guard value would wrongly
conclude the fast path triggers when the slot is null. The relocation
record says otherwise: `000005777f18 R_X86_64_RELATIVE 4fe8fe0`, so
at load time the slot holds the load base plus 0x4fe8fe0 — the address
of the zero-returning function. The checker re-derives this from the
binary's own .rela.dyn section (offset, type 8, addend), it does not
take the evidence file's word for it. The fast path is therefore an
elision of a known zero-returning implementation, not a null check:
when the object's slot already points at that function, calling it
would return 0 and the movzbl would store 0, so the window skips the
call and stores 0 directly.

## Verbatim evidence note

The disassembly excerpts in window.objdump.txt and guard.objdump.txt
are the unmodified output of GNU objdump 2.42 for the two FDE ranges
(the commands are under Reproduce below), including the int3 padding
lines that follow each ret up to the next FDE start. The instruction
entries in evidence.json copy the mnemonic, operands and raw bytes
from that output exactly — nothing paraphrased, shortened or
sanitized. In particular, `endbr64` is a genuine instruction present
in the target binary (the first instruction of both windows), not a
placeholder: it appears in objdump's own output as
`f3 0f 1e fa  endbr64`, and the checker verifies those four bytes at
both window starts against the digest-verified binary. The slow path's
`call *%rdx` is an indirect call through the loaded slot, not a
direct call: there is no direct-call target to pin, and none is
claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu) and GNU readelf
2.42 for the relocation line. The checker and tests use Python's
standard library only. No cargo, rustc, git-lfs, Ghidra or Java was
used; GNU `--dwarf=frames` output supplies the retained frame records.

The work binary used here is the materialized node #94 copy whose
SHA-256 matches provenance/artifacts.json
(`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`);
on a materialized checkout the same bytes live at
artifacts/node/94/hl-node. The excerpts were produced with:

```sh
objdump -d --start-address=0x514b170 --stop-address=0x514b1c0 work/hl-node-94.bin
objdump -d --start-address=0x4fe8fe0 --stop-address=0x4fe8ff0 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
readelf --relocs work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_virtual_dispatch.py --check research/work-items/foundation-virtual-dispatch-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_virtual_dispatch -v
```

## Evidence

- Entry FDE: offset 0x0029a46c,
  pc=000000000514b170..000000000514b1bf, 79 body bytes, SHA-256
  `25f0fc51a556800492f227c2944570e4696dc4455f8848bfcd00757f04cda670`,
  1 int3 padding byte to next FDE 0x514b1c0.
- Guard-target FDE: offset 0x0028e730,
  pc=0000000004fe8fe0..0000000004fe8fe7, 7 body bytes, SHA-256
  `da54cdf31d6cf58016d5e63168614635e075c90464289051c0ca415e5a897389`,
  9 int3 padding bytes to next FDE 0x4fe8ff0.
- Guard cmp: site 0x514b18f, bytes `48 3b 15 82 cd 62 00`;
  0x514b196 + 0x62cd82 = 0x5777f18, the GOT slot exactly.
- GOT slot: 0x5777f18 in .got; relocation R_X86_64_RELATIVE with
  addend 0x4fe8fe0, so the runtime guard value is load base +
  0x4fe8fe0. File bytes at the slot are zero (loader-filled), which
  is recorded, not mistaken for the guard value.
- Indirect call: site 0x514b1b0, bytes `ff d2`, through %rdx; no
  direct target exists or is claimed.
- Entry direct e8 callers: none in a full .text scan. This is a
  negative result about direct calls only; it does not claim the
  window is unreachable.
- Overlap check before building: repo code search for `514b170`
  returns 0 hits and for `4fe8fe0` returns 0 hits. No open WalkCrypto
  PR covers either window.

## Results and limitations

The checker passes in packet mode and in binary mode against the
digest-verified work binary; all unit tests pass, including both
paths end to end (fast path stores 0 without calling; slow path
stores the callee's low byte, with 0x1234 masked to 0x34), the
return-1 invariant, the guard target's zero return, the cmp
rip-relative arithmetic, the .rela.dyn relocation re-derivation, and
corruption controls (mutated cmp displacement, mutated guard sha,
mutated padding, mutated GOT addend and mutated rule edge each
fail). Repo-wide `make catalogue-check` was not re-run: it fails on
the pre-existing LFS-pointer identity error before reaching this
change, as recorded for the preceding submissions; that failure is
not a regression from this PR.

Remaining unknowns, stated not buried: what the object at rdi is,
what the +0x788/+0x950/+0x30 fields represent, what the slow-path
callee does beyond returning a byte, how the entry window is reached,
and whether other windows share this guard-target elision pattern. No
Rust reconstruction is claimed; the Python model is a behavioral
model of this dispatch window only.

Next question: does the guard-target elision pattern recur — do other
virtual-dispatch windows compare their slot against a
relocation-resolved zero-returning function — and is the neighbor
0x514b120's selector store part of the same object's protocol, or a
different one?
