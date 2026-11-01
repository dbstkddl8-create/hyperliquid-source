# RE-001: what does node #94's bounded byte compare 0x514b340 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about one target function, its memcmp
  arm, its saturating length-difference arm and its 7 direct
  callers; the source-level type of the compared objects (the
  callers pass (pointer, length) pairs taken from +0x20/+0x28
  fields) and the callers' wider logic remain inferences /
  unresolved.
- Scope included: the whole 78-byte FDE function
  0x514b340..0x514b38e, its memcmp PLT call, its length-difference
  saturation logic, and all 7 direct-e8 call sites in 4 enclosing
  functions.
- Scope excluded: the memcmp implementation itself (a libc PLT
  import, not node code), the enclosing caller functions' wider
  logic (only their call sites and the immediately following
  sign test are recorded), and the following window 0x514b390
  (a different, larger function, not examined here).

## Why this packet is one complete behavior, not a lone window

The function is a whole comparator, pinned end to end: it takes
two (pointer, length) pairs, compares the shared prefix with
memcmp, and — only when the prefix is equal — returns the
saturating int32 length difference. Both outcomes are observable
in the bytes (the memcmp-result return and the clamped-difference
return), and the behavior is actually used: 7 genuine direct call
sites in 4 enclosing functions pass (pointer, length) pairs and
then test the sign of the result (test/js/jns, or shr $0x1f to
extract the sign bit). This is not a fragment delegating its
meaning elsewhere: the only callee is libc memcmp, whose contract
is the prefix comparison itself.

## The rule, exactly as the bytes state it

Arguments: rdi = first pointer, rsi = first length, rdx = second
pointer, rcx = second length. Preserved registers rbp/rbx, stack
balanced (push/push/sub $0x8, then add $0x8/pop/pop), int return.

1. Length selection (0x514b352 `cmp %rcx,%rbx`, 0x514b355
   `cmovbe %rbx,%rdx`): rdx starts as rcx (second length) and is
   replaced by rbx (first length) exactly when first <= second
   unsigned, so rdx = min(first_length, second_length) as
   unsigned 64-bit values. At the same time rsi is set to rdx's
   original value (second pointer) and rdx's original value is
   overwritten, so the memcmp call receives (first pointer,
   second pointer, min length).
2. Prefix comparison (0x514b359 `test %rdx,%rdx`, 0x514b35c `je`,
   0x514b35e `call memcmp@plt`, 0x514b363 `test %eax,%eax`,
   0x514b365 `jne`): when the compared length is zero, memcmp is
   skipped and the length arm runs; otherwise memcmp runs over
   exactly min length, and a nonzero memcmp result is returned
   immediately — the length difference is never consulted when
   the prefix already differs.
3. Length difference (0x514b367 `sub %rbp,%rbx`, i.e.
   first_length - second_length as a 64-bit value):
   - 0x514b36a loads 0x7fffffff, 0x514b36f/0x514b376 compare and
     `jg` to the return: a difference above INT32_MAX returns
     INT32_MAX (2147483647).
   - 0x514b378/0x514b37f/0x514b384 compare against INT32_MIN and
     `cmovge %ebx,%eax`: a difference at or above INT32_MIN
     returns its low 32 bits (which, inside the int32 range, is
     the difference itself); a difference below INT32_MIN returns
     INT32_MIN (-2147483648, stored as 0x80000000).
   So the length arm returns first_length - second_length
   saturated to [-2147483648, 2147483647].

Composed rule: `compare(a, b) = memcmp(a, b, min(len a, len b))`
when that is nonzero (or when min length is zero, the length arm
below); otherwise `saturate_i32(len a - len b)`. In particular:
equal inputs return 0; a strict prefix returns a nonzero value
whose sign is the sign of the length difference; inputs differing
inside the shared prefix return memcmp's byte difference
(first differing bytes compared as unsigned bytes).

## Callers (all 7 direct-e8 sites, full .text scan)

- 0x515352c, 0x5153564, 0x51535aa, 0x51535e5 — enclosing function
  0x5153490..0x5153643. Each site passes (pointer, length) pairs
  with the length in the second register of the pair; the sites
  at 0x515352c and 0x51535e5 are followed by `test %eax,%eax`
  with a sign branch (js / jns), and 0x51535aa's site is
  followed by `test %eax,%eax` with a jns branch. One site
  (0x51535e5) passes its operands in the opposite order
  (rdi/rsi from r13/r14, rdx/rcx from a node's +0x20/+0x28),
  which flips the sign — recorded as observed, not normalized.
- 0x51537b9 — enclosing function 0x5153650..0x515383b; followed
  by `shr $0x1f,%eax`, extracting the result's sign bit.
- 0x5153a49 — enclosing function 0x51538a0..0x5153a6e; followed
  by `shr $0x1f,%eax`, extracting the result's sign bit.
- 0x5159629 — enclosing function 0x5159180..0x515994f; followed
  by `test %eax,%eax` with a js branch.
- In every site the first pair's pointer/length come from a
  node's +0x20/+0x28 fields (or from registers holding such a
  pair); the callers' wider ordering logic is not claimed.

## Observations, inferences, unknowns (kept separate)

- Observed: the function never reads or writes through either
  pointer beyond the memcmp call, never stores a result, and
  always returns an int; its only side effect is the memcmp call.
- Observed: all 7 callers branch on the sign of the returned int,
  never on its magnitude alone — consistent with a comparator
  used for ordering, but the ordering domain is not pinned.
- Inference (not claimed as fact): the (pointer, length) pairs
  look like string views, and the function looks like a
  string-view comparison; the bytes alone do not name the type,
  so the packet claims only the byte-level rule.
- Unknown: the source-level type and name of this comparator,
  the identity of the compared objects, and the callers' wider
  logic.

## Verbatim evidence note

The disassembly excerpt in window.objdump.txt (the whole
function) and the per-site excerpts in callers.objdump.txt are
the unmodified output of GNU objdump 2.42 for those ranges (the
commands are under Reproduce). The instruction entries in
evidence.json copy the mnemonic, operands and raw bytes from
that output exactly — nothing paraphrased, shortened or
sanitized. This function has no endbr64: its first instruction
is `push %rbp`, not a landing pad, and no endbr64 is claimed
for it. Where earlier packets recorded `endbr64`, that is
likewise the genuine instruction present in those windows'
objdump output (`f3 0f 1e fa`), not a placeholder — but this
packet stands on its own bytes, and its checker re-derives
every byte from the binary rather than trusting the evidence
file. One caller excerpt contains a `nopw` alignment
instruction, recorded with its full bytes exactly as objdump
prints it.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No cargo, rustc,
git-lfs, Ghidra or Java was used; GNU `--dwarf=frames` output
supplies the retained frame records.

The work binary used here is the materialized node #94 copy whose
SHA-256 matches provenance/artifacts.json
(`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`);
on a materialized checkout the same bytes live at
artifacts/node/94/hl-node. The excerpts were produced with:

```sh
objdump -d --start-address=0x514b340 --stop-address=0x514b38e work/hl-node-94.bin
objdump -d --start-address=0x5153490 --stop-address=0x5153643 work/hl-node-94.bin
objdump -d --start-address=0x5153650 --stop-address=0x515383b work/hl-node-94.bin
objdump -d --start-address=0x51538a0 --stop-address=0x5153a6e work/hl-node-94.bin
objdump -d --start-address=0x5159180 --stop-address=0x515994f work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_bounded_compare.py \
  --check research/work-items/foundation-bounded-compare-94/evidence.json \
  --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_bounded_compare -v
```

Environment limits, stated honestly: `make catalogue-check`
fails on this checkout for the pre-existing LFS-pointer identity
reason ("Byte coverage target identity differs") before reaching
this item's files; that failure is not a regression from this
change, and the item's own checker and tests are the verification
that runs here. Rust and Ghidra are unavailable on this VM
(expected); no Rust component is claimed.
