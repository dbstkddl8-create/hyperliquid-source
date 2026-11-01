# RE-001: node #94 string construction from a C string

- Task: RE-001 (node #94 function map).
- Bounded question: what does the FDE function at `0x514b6d0` do with
  its two arguments, and how does the resulting string object differ
  between short and long inputs?
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. No #115 or visor claim.
- Repository base: upstream `main` at `3324e503`.

## Answer

The function constructs a `std::string` (C++11 layout) from a C
string. Its arguments are `rdi` = the destination object and `rsi`
= the input pointer. The object layout it uses is: pointer at
`+0x0`, length at `+0x8`, and a union at `+0x10` holding either
the heap capacity or the 16-byte small-string buffer.

- The pointer field is first set to the object's own buffer
  (`object + 0x10`).
- A null input throws `logic_error` with the string at `0x7e0c18`:
  `basic_string: construction from null is not valid`. The throw
  happens after the pointer store, but construction fails, so no
  post-throw object state is claimed.
- Otherwise the length is `strlen` of the input, i.e. the bytes up
  to the first NUL.
- Length at most 15 (small-string case): the pointer field stays
  the object's own buffer, the length field is the length, the
  content is copied (a single-byte copy for length 1, `memcpy`
  otherwise), and a NUL terminator is stored at `buffer + length`.
- Length above 15 (heap case): `_M_create` is called with the
  destination, a capacity slot holding the length, and old
  capacity 0. The pointer field becomes the returned buffer, the
  capacity field becomes the slot value, and the length field
  becomes the same slot value. For old capacity 0 the callee
  leaves the slot equal to the requested length (its doubling
  and clamping arms only rewrite the slot for a nonzero old
  capacity or an overflowing request), so capacity and length
  are both the input length here. The content is copied by
  `memcpy` and a NUL terminator is stored at `buffer + length`.
- A stack canary is loaded from `fs:0x28` into `rsp + 0x8` on
  entry and checked on both return paths; a mismatch calls
  `__stack_chk_fail`.

This function has no `endbr64` (it starts with a push); the
`nopw`/`nopl` bytes in it are genuine alignment padding, and the
disassembly excerpts are verbatim objdump output. The
nearest-symbol annotation objdump prints for this address is
not a claimed source-level symbol name: the function is
identified by its behaviour and by its PLT callees, not by that
annotation.

## Reproduce

Requirements: Linux, Python 3.10+, GNU binutils (`objdump`).
The binary path below is the digest-verified work copy; pass
`--binary` with that path on checkouts where
`artifacts/node/94/hl-node` is still an LFS pointer.

```sh
python3 research/work-items/RE-001-string-ctor-cstr-94/verify.py --binary work/hl-node-94.bin
python3 research/work-items/RE-001-string-ctor-cstr-94/export_excerpts.py --binary work/hl-node-94.bin
python3 tools/foundation_string_ctor_cstr.py --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_string_ctor_cstr -v
```

Recorded tools: Python 3.12.3 and GNU binutils 2.42 on Ubuntu
24.04. The disassembly command is `objdump -d` with its default
AT&T syntax; start/stop addresses are ELF virtual addresses,
with no rebasing or syntax overrides. Different binutils
versions can render text differently; the byte/hash records
are also retained.

## Exact ranges and attribution

| Observed role | ELF VA, half-open | Bytes |
| --- | --- | ---: |
| Constructor | `0x514b6d0..0x514b7b3` | 227 |
| int3 padding | `0x514b7b3..0x514b7b4` | 1 |
| Next FDE | `0x514b7b4..0x514b7da` | 38 |
| Throw string | `0x7e0c18..0x7e0c4a` | 50 |

The constructor's FDE record is at `.eh_frame` offset `0x0029a608`
(length `0x38`, CIE offset `0x00000000`). The bytes after the
`int3` at `0x514b7b3` belong to the next FDE and are not part
of this item.

## Callees

| PLT stub | Symbol | Role |
| --- | --- | --- |
| `0x5660120` | `strlen` | Input length |
| `0x56604d0` | `basic_string::_M_create` | Heap allocation (length > 15) |
| `0x5660100` | `memcpy` | Content copy |
| `0x5660430` | `__stack_chk_fail` | Canary-mismatch arm |
| `0x56604e0` | `__throw_logic_error` | Null-input arm |

GOT slots in the file hold lazy-binding resolver entries, not
resolved addresses; the checker records them as file bytes and
resolves the symbols through `.rela.plt` instead.

## Callers

A full `.text` direct-`e8` scan finds 117 call sites in 4
enclosing FDE functions:

| Enclosing function | Sites |
| --- | ---: |
| `0x514eb90..0x514ed1b` | 2 |
| `0x51560b0..0x5157a19` | 4 |
| `0x5159180..0x515994f` | 1 |
| `0x515b750..0x515f78b` | 110 |

Three sites were spot-checked for the constructor protocol
(destination object in `rdi`, C-string literal address in
`rsi`): `0x514ec8c`, `0x5156106`, `0x515b7e2`. The remaining
114 sites are census-only: they are direct calls to this
function, but their argument setup was not individually read.
Call-anchored excerpts (each starting exactly at its call
site) are in `callers.objdump.txt`.

## Deliberately not folded in

- The preceding FDE at `0x514b690` (recursive destructor,
  bound by the prior work item) and the following FDE at
  `0x514b7b4` (unexamined, different protocol).
- The neighbouring string move-assign at `0x514b4f0` (prior
  work item): a different operation on an existing string,
  not construction from a C string.

## Unknowns and limits

- No source-level symbol name is claimed for this function.
- `_M_create` behaviour for old capacities other than 0, and
  for lengths above its length-error limit, is external-callee
  behaviour not exercised by this window and is not modelled.
- Allocation-failure behaviour is not modelled.
- The identity or purpose of the four enclosing caller
  functions is not claimed beyond their FDE ranges.
- `make doctor` fails on this VM (no Rust/Ghidra), as expected;
  the repo-wide `catalogue-check` has a pre-existing
  LFS-pointer identity failure unrelated to this change, and
  is stated honestly rather than claimed as passing.
