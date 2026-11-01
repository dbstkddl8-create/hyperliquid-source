# foundation-accessor-pair-94: what do the two accessor windows flanking 0x514abb0 compute?

- Component: `foundation`, two small previously unclaimed windows; their
  source-level component is not established by this packet.
- Task: RE-001 (#94 function map).
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at branch time.
- Claim: observations about two target instruction windows; their
  source-level names and types remain inferences.
- Included: both FDE windows, their int3 padding, FDE records, the exact
  rule of each window, and a direct-caller scan (zero sites each).
- Excluded: the middle window `0x514abb0` (submitted separately as
  #1282, shown in no file here), all #115 addresses, target execution,
  Rust reconstruction, and any family census beyond the two windows.

## Why this packet

The two windows were first surfaced, unclaimed, as neighbors in the
merged `foundation-devirtualized-getter-94` packet (#1274): that packet's
README names `0x514ab90` as a 20-byte plain copy and `0x514abf0` as a
virtual call at vtable offset `0x478`, and states explicitly that no
neighbor is claimed anywhere in that packet. This packet claims only
those two windows, and verifies each rule independently from its own
retained bytes below — the neighbor description was a lead, not
evidence. Binding the pair together, rather than as two one-window
submissions, follows the grouping suggestion in the intake review of
#1282: the two windows share one container protocol (value stored to
`[rsi]`, return value always 1) and flank one already-bound window.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ab90 --stop-address=0x514abb0 work/hl-node-94.bin
objdump -d --start-address=0x514abf0 --stop-address=0x514ac20 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so it
cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was verified to
equal the provenance digest for node #94
(`3b7179cd…c0459f`, 91,774,280 bytes) before any byte was read from it.
The checker therefore takes an optional `--binary` argument: without it,
it verifies the packet files against each other (retained disassembly
bytes, FDE records, padding, rule edges); with it, it additionally
verifies the target digest, the window bytes, the padding, the FDE
pc ranges, and the direct-caller scan against that binary. On a checkout
where the LFS artifact is materialized, run the binary form with
`--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_accessor_pair.py --check research/work-items/foundation-accessor-pair-94/evidence.json
python3 tools/foundation_accessor_pair.py --check research/work-items/foundation-accessor-pair-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_accessor_pair -v
```

No target binary was executed. All analysis below is static byte evidence.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA -
`0x1000`; the retained `.eh_frame` has equal file offsets and VAs.
The FDE initial_location values in this CIE are pcrel sdata4: each
stored value is relative to its own field address, and the checker
recomputes the start VA from that field address.

### Window 1: plain copy, 0x514ab90

- `.eh_frame+0x0029a0ec` describes `[0x514ab90, 0x514aba4)`, 20 bytes.
  Complete linear decoding from that start gives the sequence below,
  ending exactly at the FDE endpoint (the `ret` at `0x514aba3`).
- Twelve `int3` bytes (`0xcc`) pad the window from `0x514aba4` to the
  next FDE start `0x514abb0`. The stride is **not** the FDE extent.
- The window SHA-256 over its 20 body bytes is
  `bbb048714562409fe34db24f12f4f5e0fb56c7cb08a23e8d61c96b976dde91db`.

| VA | Instruction | Role |
| --- | --- | --- |
| `0x514ab90` | `endbr64` | Entry |
| `0x514ab94` | `mov 0x1228(%rdx), %rax` | Field at container + 0x1228 |
| `0x514ab9b` | `mov %rax, (%rsi)` | Store to out |
| `0x514ab9e` | `mov $0x1, %eax` | Return 1 |
| `0x514aba3` | `ret` | Return |

- The rule, over container pointer (`rdx`) and out pointer (`rsi`),
  is: store the qword at `[rdx + 0x1228]` to `[rsi]` and return 1.
  No call, no check, no other store, no other register is read.
- Direct callers: none. A byte-pattern scan of `.text` finds exactly 0
  direct `e8` calls to this window. Register-indirect references, other
  pointer paths, prefixes, and data sections are not a complete xref
  census.

### Window 2: virtual call, 0x514abf0

- `.eh_frame+0x0029a114` describes `[0x514abf0, 0x514ac11)`, 33 bytes.
  Complete linear decoding from that start gives the sequence below,
  ending exactly at the FDE endpoint (the `ret` at `0x514ac10`).
- Fifteen `int3` bytes (`0xcc`) pad the window from `0x514ac11` to the
  next FDE start `0x514ac20`.
- The window SHA-256 over its 33 body bytes is
  `3b6503209cabccc85eb01b138691bf654d5cc1ecf6424f202cbb68a7f80eab95`.

| VA | Instruction | Role |
| --- | --- | --- |
| `0x514abf0` | `endbr64` | Entry |
| `0x514abf4` | `mov (%rdx), %rax` | Vtable pointer |
| `0x514abf7` | `push %rbx` | Preserve callee-saved rbx |
| `0x514abf8` | `mov %rdx, %rdi` | First call argument: container |
| `0x514abfb` | `mov %rsi, %rbx` | Save out pointer across the call |
| `0x514abfe` | `call *0x478(%rax)` | Virtual call, vtable offset 0x478 |
| `0x514ac04` | `movzbl %al, %eax` | Keep only the callee's low byte |
| `0x514ac07` | `mov %rax, (%rbx)` | Store zero-extended byte to out |
| `0x514ac0a` | `mov $0x1, %eax` | Return 1 |
| `0x514ac0f` | `pop %rbx` | Restore rbx |
| `0x514ac10` | `ret` | Return |

- The rule, over container pointer (`rdx`) and out pointer (`rsi`),
  is: call the function at `[vtable + 0x478]`, where vtable is the
  qword at `[rdx]`, with the registers the call instruction observes
  (`rdi` = container, `rsi` = out, `rdx` = container unchanged,
  `rcx` = entry rcx unchanged); store the callee return value's low
  byte, zero-extended, to `[rsi]`; restore `rbx`; return 1. The roles
  of the `rdx`/`rcx` call arguments are not established — only their
  values at the call are observed.
- Direct callers: none. A byte-pattern scan of `.text` finds exactly 0
  direct `e8` calls to this window, with the same census limits as above.

## Inferences

- Inferred labels: plain copy, virtual-call accessor. The rules are
  observed and proven above; only the labels are inferred.
- The shared container protocol (value stored to `[rsi]`, return value
  always 1) matches the neighboring `0x514abb0` window's protocol, but
  what the container is and what the field at offset `0x1228` or the
  virtual function at offset `0x478` represents is not established, so
  any such reading is an inference only.

## Unknowns

- The source-level names and types of both windows, their container,
  and the field/virtual function they touch.
- What calls these windows, beyond the direct-call scans above.
- The disassembly's nearest-symbol annotation carries a large offset and
  is not an identification of either window.

## Excluded

The middle window `0x514abb0` (PR #1282), the virtual-call target
itself (this packet binds only the call site, not the callee), all #115
addresses, target execution, Rust reconstruction, any family census,
and any progress gate. This packet requests no gate.
