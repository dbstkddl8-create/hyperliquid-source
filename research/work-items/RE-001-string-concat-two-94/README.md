# RE-001: bind node #94 two-piece string concat 0x514bbb0

Task ID: RE-001. Bounded question: what does the whole FDE function at
0x514bbb0 do with its five arguments, and what observable behaviour
(including failure) does it pin end to end?

## Answer

The function builds a fresh `std::string` from two (pointer, length)
pieces and returns it. Signature, in argument-register order:

```
string* concat_two(string* out, const char* p1, size_t len1,
                   const char* p2, size_t len2)  // returns out
```

Steps, all verified against the digest-pinned binary
(SHA-256 `3b7179cd…c0459f`, see records.json):

1. Initialise `out` as an empty SSO string: pointer field = `out+0x10`
   (its own inline buffer), length field = 0, first SSO byte = 0.
2. Call `basic_string::reserve(len1 + len2 mod 2^64)` — the total is
   computed by the `lea` at 0x514bbb9 before the call at 0x514bbde.
   Reserve is a capacity hint only: on any path that reaches both
   appends successfully, `len1 + len2 <= max_size < 2^63`, so the
   wrapped total never differs from the true total there.
3. Append `(p1, len1)` via `_M_append` (call at 0x514bbff), unless
   `len1 > max_size - 0`, in which case it throws
   `length_error("basic_string::append")` (arm at 0x514bc31).
4. Append `(p2, len2)` via `_M_append` (call at 0x514bc20), unless
   `len2 > max_size - len1`, in which case it throws the same error
   (arm at 0x514bc3d).
5. Return `out` in `rax`. All pushed registers (rbx, rbp, r12–r14)
   are restored; there is no stack canary in this function.

`max_size` is `0x3fffffffffffffff` (2^62 - 1), read from the
`movabs` immediates at 0x514bbe3 and 0x514bc04.

## Failure and cleanup

Both throw arms load the same `.rodata` string at 0x1f822d
(bytes verified: `basic_string::append`, NUL-terminated) and call
`__throw_length_error` (PLT 0x56604a0). The landing pad at
0x514bc49 (`endbr64` is a genuine instruction here, not a
placeholder — it is the landing-pad entry emitted by the compiler)
saves the exception object and jumps to the shared cleanup stub at
0x514bb95, which calls `_M_dispose(out)` and then `_Unwind_Resume`.
That stub is shared with the neighbouring dispose function
0x514bb10 (bound by PR #1339); it is cited here, not re-claimed.

## Callers

Byte-level scan of `.text` for direct `e8` calls to 0x514bbb0
finds exactly 62 sites, all inside the single enclosing function
0x515b750..0x515f78b (FDE 0x00634d78). Two sites were spot-checked
for the full argument protocol; the rest are census-only:

- 0x515cb7b: out = global 0x578b960, p1/len1 from the global pair
  at 0x578b980/0x578b988, p2 = `.rodata` literal 0x1f2944, len2 = 9.
- 0x515dbb1: out = global 0x578afa0, p1 = `[r13+0x0]`,
  len1 = `[r13+0x8]` (a pointer/length pair), p2 = `.rodata`
  literal 0x1de121, len2 = 9.

The enclosing function itself is not modelled here; it is the same
large string-building function that holds the 110 string-ctor call
sites bound by PR #1329, which is consistent with a table of
constructed messages but is not claimed beyond the census.

## Deliberately not claimed

- The source-level name of this helper (objdump's nearest-symbol
  annotation is a libstdc++ symbol plus an offset, not a name).
- The contents of the two `.rodata` literals at the spot-checked
  sites beyond their addresses and the second length (9).
- The following FDE at 0x514bc60 (unexamined) and the preceding
  dispose function (PR #1339) — neighbours, not part of this item.
- SSO-vs-heap behaviour of `reserve`/`_M_append` themselves: those
  are libstdc++ callees, modelled only as the capacity hint and the
  append contract this function relies on.

## Observations vs inferences

Observations (bytes, targets, censuses) are in records.json and are
re-checked by verify.py and by tools/foundation_string_concat_two.py.
Inferences, with reasoning: the five-argument protocol follows from
the register saves (rsi→r14, rdx→rbp, rcx→r13, r8→r12) plus the two
append call setups; the "two-piece concat" reading follows from
reserve(total) + append + append + return-out; the shared-stub
reading follows from the landing-pad jump into 0x514bb95 and that
stub's dispose-then-resume shape.

## Reproduction

Excerpts were produced with (run from the repository root):

```
objdump -d --start-address=0x514bbb0 --stop-address=0x514bc60 work/hl-node-94.bin
objdump -d --start-address=0x514bb95 --stop-address=0x514bbb0 work/hl-node-94.bin
objdump -d --start-address=<site-0x40> --stop-address=<site+5> work/hl-node-94.bin  # per call site
objdump -d --start-address=<plt> --stop-address=<plt+0x10> work/hl-node-94.bin      # per PLT stub
```

or, equivalently, `python3 research/work-items/RE-001-string-concat-two-94/export_excerpts.py --binary work/hl-node-94.bin`.
Verify with `python3 research/work-items/RE-001-string-concat-two-94/verify.py --binary work/hl-node-94.bin`
and the model tests in tests/test_foundation_string_concat_two.py.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make doctor` fails (expected) and the repo-wide `make catalogue-check`
pre-existing LFS-pointer identity failure is not re-run here; it is
not a regression from this change. All claims above rest on the
digest-verified work binary, not on the LFS-pointer artifact path.
