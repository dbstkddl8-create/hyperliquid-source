# foundation-modulo-index-byte-94: what does the modulo-index-byte window compute?

- Component: `foundation`, one small previously unclaimed window; its source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: worktree HEAD `2993e46` (branch `codex/foundation-modulo-index-byte-94`).
- Reference pin: none. No reference label was used as a lead for this window; it was mined fresh from the small-band (20–100 byte) non-gate single-call slice after the big-band gate-singleton direct-call well ran dry, and it passed every guard on its own merits.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 57-byte FDE window, its seven int3 padding bytes, the single call edge to the 133-byte callee, the single incoming direct call edge, and the exact modulo-index-byte rule over the object field, the base pointer, the index, and the hash-input struct.
- Excluded: the callee implementation beyond its 133 retained bytes, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map small helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose modulo-index-byte rule reads directly from its own bytes: call a helper with a struct's two fields and a constant seed, reduce the result modulo a field of the object, and return the byte at the reduced index plus the caller's index. It is the eleventh packet from the calls category's single-call slice: like the earlier calls packets, its rule is stated over its inputs and the callee call, with the callee itself explicitly excluded. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, test, or doc in the tree mentions `0x538c820`, and a full-corpus byte comparison against every FDE body of 20 bytes or more finds no body sharing 60% or more of this window's bytes under either measure (max-length best 0.246 against `0x5432d40`, a 44-byte call + tail-jump forwarder with a different rule; 0.140 against the scaled-count window, the rest lower, none against the older claimed corpus); its mnemonic skeleton (`endbr64, push, mov, push, mov, push, mov, mov, mov, mov, call, movzx, xor, div, mov, add, movzx, pop, pop, pop, ret`) is a singleton among 31,898 single-call FDE windows (20–150 bytes), under both the raw and the ret-truncated skeleton. The window is not a member of a repeated-window population.

The min-length comparison is reported head-on rather than hidden: across the same full corpus with the same >=20-byte substance floor, there are zero hits at or above 0.60 — no >=20-byte body shares 60% or more of this window's shorter length. The 5-byte `endbr64; ret` stubs that produced min-length hits for earlier packets are below the floor and are not twins of a 57-byte window.

The neighbor question is also addressed head-on, not hidden. The adjacent FDEs (`0x538c7e0`, `0x538c800`, `0x538c860`, `0x538c880`) have unrelated skeletons, and the nearest full-corpus body, `0x5432d40` (0.246), is a call + tail-jump forwarder: it calls a helper, reloads three registers, and jumps elsewhere — no modulo, no indexed byte, no second index. The positional byte matches are the shared `endbr64; push; mov` prologue, not a shared rule. Only this one window is built; no neighbor is claimed anywhere in this packet.

The shared-callee question is addressed head-on as well. The callee at `0x5422e70` is called directly from 26 sites in `.text`, so it is a shared helper, not a private one — but that does not make this window a member of a population: no other small-band window shares this window's call-modulo-index shape (the other callers' containing FDEs are 133–3790 bytes with unrelated skeletons, and this window's skeleton is a singleton), and the callee's behavior is excluded from the rule in any case. The rule claims only the call edge and its three argument registers, never what the callee computes. Contrast the 15-window shared-callee population that killed a big-band candidate in #146: those windows shared one callee and one shape; this window shares only the callee.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_modulo_index_byte.py --check research/work-items/foundation-modulo-index-byte-94/evidence.json
python3 -m unittest tests.test_foundation_modulo_index_byte -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5422e70 --stop-address=0x5422f00 artifacts/node/94/hl-node
objdump -d --start-address=0x538c820 --stop-address=0x538c860 artifacts/node/94/hl-node
objdump -d --start-address=0x535be50 --stop-address=0x535c4ab artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the callee and the window including their padding. The `caller.objdump.txt` file retains disassembly of the caller's containing FDE, with the call instruction verified as an instruction start inside that FDE. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x002b379c` (this window), `0x002b37cc` (the next FDE, bounding the padding), `0x002ba114` (the callee), `0x002ba128` (the FDE after the callee), and `0x002b2078` (the caller FDE) — all five use CIE `0x00000000`, and the checker locks each record's own CIE rather than assuming one shared CIE. (Note the `objdump --dwarf=frames` line format: the third column is the FDE record's CIE-pointer delta, not its CIE — the CIE is the value after `cie=`.) The checker locks these raw FDE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x002b379c` describes `[0x538c820, 0x538c859)`, 57 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x538c858`).
- The unwind index stride to the next entry is 64 bytes, ending at `0x538c860`, only because seven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those seven padding bytes, and the checker locks the 57-byte body and the padding separately.
- A byte-pattern scan of `.text` finds exactly 1 direct `e8` call to the window, so a caller file is included and this packet has 8 files total. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: call, modulo by field, indexed byte return

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x538c820` | `endbr64` | Entry |
| `0x538c824` | `push r12` | Save callee-saved register |
| `0x538c826` | `mov r12, rdi` | Save the object pointer |
| `0x538c829` | `push rbp` | Save callee-saved register |
| `0x538c82a` | `mov rbp, rsi` | Save the base pointer |
| `0x538c82d` | `push rbx` | Save callee-saved register |
| `0x538c82e` | `mov rsi, [rcx + 8]` | Second hash-input field |
| `0x538c832` | `mov ebx, edx` | Save the index (zero-extended) |
| `0x538c834` | `mov edx, 0x18d` | Constant seed argument |
| `0x538c839` | `mov rdi, [rcx]` | First hash-input field |
| `0x538c83c` | `call 0x5422e70` | Call (behavior excluded) |
| `0x538c841` | `movzx ecx, word [r12]` | Divisor: word field of the object |
| `0x538c846` | `xor edx, edx` | Zero the high dividend half |
| `0x538c848` | `div ecx` | Unsigned divide edx:eax by the divisor |
| `0x538c84a` | `mov edx, edx` | Zero-extend the remainder |
| `0x538c84c` | `add rbp, rdx` | Base plus remainder |
| `0x538c84f` | `movzx eax, byte [rbp + rbx]` | Indexed byte, zero-extended |
| `0x538c854` | `pop rbx` | Epilogue |
| `0x538c855` | `pop rbp` | Epilogue |
| `0x538c856` | `pop r12` | Epilogue |
| `0x538c858` | `ret` | Return the byte |

- The rule, over object pointer (`rdi`), base pointer (`rsi`), index (`edx`, zero-extended to 64 bits), and hash-input struct (`rcx`), is: call `0x5422e70` with `rdi` = `[rcx]`, `rsi` = `[rcx + 8]`, `rdx` = `0x18d`; let h be the call's `eax` result and d be the word at `[rdi]` (zero-extended to 32 bits); return the byte at `[rsi + (h mod d) + idx]`, zero-extended to `rax`. The quotient of the division is discarded; only the remainder is used.
- The callee at `0x5422e70` IS an FDE start (133 bytes, `.eh_frame+0x002ba114`, CIE `0x00000000`, the same CIE as the window), and its 133 retained bytes are kept in the packet. Eleven `int3` bytes pad it to the next FDE at `0x5422f00`. The callee's behavior is excluded from the rule: the rule claims the call edge and its three argument registers only, never what the callee computes with the two fields and the seed, and never the callee's own control flow. The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.
- The window writes nothing: it stores nothing, and all three pushed registers are popped on the only path, so the stack is balanced.
- The divisor-zero limit is recorded, not executed: a word field of 0 makes the `div` fault (#DE, no quotient). Whether a zero field occurs in practice is not established.
- The single direct caller is `0x535bea9` (FDE `0x535be50..0x535c4ab`, CIE `0x00000000`), verified as an `e8` instruction start inside its containing FDE; it calls the window with `rdi` = `[caller_rdi + 0x170]`, `rsi` = `[caller_rdi + 0x30]`, `edx` = `[caller_rdi + 0x40]` + `[caller_rdi + 0x38]` * 4, `rcx` = `rsp + 0x30` (a stack struct whose first qword is `[caller_rsi]` and whose second qword is `[caller_rsi + 8]` - 8), and after the call it compares `al` to `0xfe` and to `0xff`. What the caller does with the byte is not established.

## Inferences

- Inferred label: modulo-index-byte helper. The rule is observed and proven above; only the label is inferred. The call-modulo-index shape reads as reducing a helper result into a table index, but what the object, the base, the index, and the hash-input struct are is not established, so that reading is an inference only.
- The single caller suggests a narrowly used helper, but what calls it and why is not established.

## Unknowns

- The source-level name and types of this window, its object, its base buffer, and its hash-input struct.
- What the callee computes with the two fields and the `0x18d` seed, and what the word field at object offset 0 means.
- Whether the divisor-zero fault edge is reachable in practice, and what the caller does with the returned byte.
- The disassembly's nearest-symbol annotation carries a large offset and is not an identification of this window.

## Excluded

The callee implementation beyond its 133 retained bytes, all #115 addresses, target execution, Rust reconstruction, any family census, and any progress gate. This packet requests no gate.
