# Foundation span-count helper (node #94)

A 43-byte single-call window at `0x53c7490` that calls `0x53c6e80` with
the object pointer, then stores a span-derived element count to
`[obj+0x80]`, and tail-jumps to `0x53c4ec0`. It is one small, directly
readable window: no branch, no loop, no flag test, no constant pool, and
no second call. The callee's behavior is excluded from the rule; only its
identity and extent are locked.

## Rule

Call `0x53c6e80` with the object pointer in `rdi`, then store
`((qword[obj+0x70] - qword[obj+0x68]) arithmetic-shifted right by 2, minus
1, truncated to 32 bits)` as a dword to `[obj+0x80]`, then tail-jump to
`0x53c4ec0` with `rdi` restored to the object pointer.

In other words: the window converts a byte span (`[obj+0x68]` to
`[obj+0x70]`) into an element count for 4-byte elements, minus one, and
writes it to the field at offset `0x80`. The subtraction is 64-bit, the
shift is arithmetic (`sar`), the subtract-one is 32-bit (`sub eax, 1`),
and the store is a 32-bit store.

## Window

| Field | Value |
| --- | --- |
| Start | `0x53c7490` |
| End (exclusive) | `0x53c74bb` |
| Size | 43 bytes |
| FDE section offset | `0x002b637c` |
| FDE CIE | `0x00000000` |
| Padding | 5 bytes `cc` (int3) to the next FDE at `0x53c74c0` |
| Body SHA-256 | `d6d0076b258295ea2a847fc828c285fa2c454ae8e0dd98cfde67ddeff5267274` |
| Target | node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` |
| Worktree HEAD | `2993e46` |

Instruction walk, in order:

| Address | Instruction | Role |
| --- | --- | --- |
| `0x53c7490` | `endbr64` | Entry marker |
| `0x53c7494` | `push rbx` | Save callee-saved register |
| `0x53c7495` | `mov rbx, rdi` | Keep the object pointer |
| `0x53c7498` | `call 0x53c6e80` | The single call; `rdi` is the object |
| `0x53c749d` | `mov rax, [rbx+0x70]` | Span end |
| `0x53c74a1` | `sub rax, [rbx+0x68]` | Span length in bytes (64-bit) |
| `0x53c74a5` | `mov rdi, rbx` | Restore the object pointer for the jump |
| `0x53c74a8` | `sar rax, 2` | Divide by 4 (arithmetic shift) |
| `0x53c74ac` | `sub eax, 1` | Minus one, 32-bit |
| `0x53c74af` | `mov [rbx+0x80], eax` | Store the count |
| `0x53c74b5` | `pop rbx` | Restore |
| `0x53c74b6` | `jmp 0x53c4ec0` | Tail jump; the window has no `ret` |

The window ends with a tail jump, not a `ret`, so its FDE range and
padding must not be described as ret-terminated. The jump target
`0x53c4ec0` is itself an FDE start (`0x53c4ec0..0x53c505c`, section
offset `0x002b61c8`, CIE `0x00000000`); its behavior is excluded, only
its identity is locked.

## Callee

| Field | Value |
| --- | --- |
| Start | `0x53c6e80` (an FDE start) |
| End (exclusive) | `0x53c746a` |
| Size | 1514 bytes |
| FDE section offset | `0x00657b9c` |
| FDE CIE | `0x006205d0` (different from the window's own CIE; each record is locked under its own CIE) |
| Padding | 6 bytes `cc` to the next FDE at `0x53c7470` |
| Body SHA-256 | `7ee3238311d0cf6d44f02bc40edda937ecdc6aca4fe32ab140e269dc2b628935` |

The callee is called from three direct sites: this window (`0x53c7498`),
the 32-byte neighbor `0x53c7470` (`0x53c7478`), and one site inside the
393-byte window `0x53c74c0` (`0x53c74ee`, preceded by `xor eax, eax` and
followed by unrelated loads). The three containers have different shapes
and different rules, so the shared callee is not a shared rule: the
neighbor stores the constant `0` to the same `[rbx+0x80]` field and
tail-jumps to the same target, and the 393-byte window's call sits inside
a much larger body. The neighbor is the closest relative and is treated
head-on below, not hidden: it resets the field this window computes.
Because the callee is 1514 bytes, its body is locked by length, SHA-256
and padding rather than by locking every one of its instructions; that
locks its identity and extent, which is all the rule uses.

## Neighbors

| FDE start | Size | Relation |
| --- | --- | --- |
| `0x53c6e80` | 1514 bytes | The callee (above) |
| `0x53c7470` | 32 bytes | Reset sibling: same callee, same `[rbx+0x80]` field, same tail target, but stores constant `0` with no arithmetic and no span load |
| `0x53c74c0` | 393 bytes | Next FDE after the window; contains the third callee call site |
| `0x53c7650` | 52 bytes | Following FDE; unrelated |

## Incoming calls

A byte-pattern scan of `.text` for direct `e8` calls to `0x53c7490`
finds exactly zero sites, so this packet has seven files (no
`caller.objdump.txt`). Register-indirect references, other pointer paths,
prefixes, and data sections are not a complete xref census, so the claim
is scoped to direct `e8` calls, not to all possible references.

## Rule edges

| Span start | Span end | Model | Stored |
| --- | --- | --- | --- |
| `0x1000` | `0x1100` | 0x100 bytes / 4 = 64, minus 1 | `0x3f` |
| `0x2000` | `0x2010` | 0x10 bytes / 4 = 4, minus 1 | `0x3` |
| `0x3000` | `0x3000` | Empty span: 0 - 1 wraps | `0xffffffff` |
| `0x2000` | `0x1ffc` | Negative span -4: `sar` gives -1, minus 1 wraps | `0xfffffffe` |

The edges supply the fields after the callee returns. They are model checks
on the recorded arithmetic, not executions of the target binary. The low two bits of the byte span are discarded by
the shift, so spans differing only in those bits map to the same count.

## Rejected candidates

| Address | Reason |
| --- | --- |
| `0x53a7fa0` (22 bytes) | Thin counter-increment wrapper (`endbr64 push mov call add pop ret`, callee `0x539d900` 24 bytes, adds 1 to `dword [rbx+0x25c]`). Skeleton singleton and low twin scores, but a bare +1 wrapper with no other computation is too thin for a standalone packet, so it stays unclaimed behind this window. |

## Limits

- The callee's behavior and the tail-jump target's behavior are excluded;
  only their identities and extents are locked. The rule therefore says
  what the window computes and where it goes, not what either endpoint
  does with the object.
- The shift is arithmetic on 64 bits and the subtract is 32-bit, so an
  empty span wraps to `0xffffffff` and a negative span wraps through the
  sign extension; both are recorded as edges, not as faults.
- The window has no `ret`: control leaves by tail jump. The count store
  is the only directly modeled local write; the callee and tail target
  may have additional effects that are not modeled here.
- Nearest-symbol annotations from the disassembler carry large offsets
  and are not identifications; no symbol name is claimed.
- The zero-caller claim covers direct `e8` calls in `.text` only.

## Checker and tests

Reproduce from the repository root:

```
python3 tools/foundation_span_count.py \
  --check research/work-items/foundation-span-count-94/evidence.json
python3 -m unittest tests.test_foundation_span_count -v
```

The checker re-derives the window body, its padding, and all five
FDE offset/CIE/PC associations from the authenticated binary. Each association
must also match a single retained frame record. It checks the callee body and padding, the call and tail-jump
encodings, the span-count rule on its edges, and the zero-caller scan
from target bytes. The unit tests run the checker on the real evidence
plus corruption controls: each control mutates one recorded fact (body
hash, padding, target digest, call target, jump target, FDE offsets,
callee hash/extent/padding, caller list, edge values, store field, and
substituted existing FDE offsets or CIEs) and
must make the checker fail.

## Bounded contribution

The window contains one call, a span-to-count conversion, one direct local
store, and a tail jump. The recorded arithmetic uses the object fields after
the callee returns. Callee and tail-target effects are outside this model.
No corpus-wide similarity or uniqueness claim is established by this packet,
and no component-completion or reconstructed-byte identity credit is requested.

## Files

- `README.md` (this file)
- `evidence.json`
- `window.objdump.txt` (GNU disassembly of the callee and the window,
  including their padding)
- `frames.txt` (FDE excerpts for the window, the next FDE, the callee,
  the FDE after the callee, and the tail-jump target)
- `MANIFEST.sha256`
- `tools/foundation_span_count.py`
- `tests/test_foundation_span_count.py`
