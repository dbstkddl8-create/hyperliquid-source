# RE-001: what does node #94's compaction-stats consumer 0x514d770 do?

- Component: `foundation`, bounded RE-001 function-map work.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503` at submission time.
- Claim status: observations about one target function, the map it
  reads, the 13 map::at calls and 7 inlined successor searches
  inside it, and the row it formats; the source-level container
  type, the meaning of the stored strings and the identity of the
  first column remain inferences/unresolved.
- Scope included: the whole 1388-byte FDE function
  0x514d770..0x514dcdc, its 13 direct map::at calls, its 7
  inlined successor searches, its three snprintf format strings,
  its dash separator, its shared throw tail, and its 2 direct
  callers in 0x51560b0..0x5157a19.
- Scope excluded: the map::at window itself (bound in #1314 — this
  item binds its consumer, not the window again), the two caller
  functions' wider logic (only their call sites and name-argument
  setup are recorded), what the 20 strings mean, and which key, if
  any, the first row column stands for.

## Why this packet is one complete behavior, not a lone window

The function is a whole row builder, pinned end to end: it takes
a buffer (rdi), a name (rsi) and a struct pointer (rdx), and
appends three writes to the buffer — a header, a 21-column row
and a dash separator. Every column's provenance is pinned: the
first column is the caller's `[r15]` string, and the other twenty
are the value+0x20 string fields (node+0x48) of map keys 1 and
3..21, each read through a named mechanism (13 exact map::at
calls, 7 inlined successor searches), each with its key setup,
its value load and its stack slot recorded. Any missing key
throws `out_of_range("map::at")` through the shared tail, so the
row is all-or-nothing. The function is not speculative: it has 2
genuine direct callers, both passing their name argument from a
+0x8 field, and the map it reads is the same global map at
0x578bf20 that #1314's window searches.

## The rule, exactly as the bytes state it

Arguments: rdi = output buffer (kept in rbx), rsi = name string
(kept in r9 for the header), rdx = struct pointer (kept in r15).
Stack frame 0xc8, stack canary checked on both exits, preserved
registers r15/r14/r13/r12/rbp/rbx, void return.

1. Header snprintf (0x514d7b5, `__snprintf_chk@plt`, format at
   0x1e6dc3): `"\n** Compaction Stats [%s] **\n"` with the name.
   Length in ebp, clamped to 0x7d0 (2000) by `cmp`/`cmovg` at
   0x514d7c6/0x514d7c8.
2. Map reads. The map base is r12 = 0x578bf20 (lea at
   0x514d7e2); the root is [r12+0x10], the header sentinel is
   r12+0x8. Each map::at call passes its key in edi and returns
   node+0x28; the consumer then loads [return+0x20] (node+0x48)
   and stores it. Each inlined block walks the same tree from
   the root with `jle` (key <= sought goes right, the opposite
   branch sense from map::at's `jl`), records the smallest key
   strictly greater than sought, and throws unless that key
   equals sought+1 (`cmpl $sought+1; jg` to the throw tail).
   Both mechanisms therefore pin exact keys; the inlined ones
   are lower_bound(sought+1) plus an equality check, not a
   fuzzy range read.

   Map::at keys (call site, key, stack slot): 0x514d7cb → 21 →
   (%rsp); 0x514d7dd → 20 → 0x8(%rsp); 0x514d8ce → 17 →
   0x18(%rsp); 0x514d94e → 15 → 0x28(%rsp); 0x514d961 → 14 →
   0x30(%rsp); 0x514d974 → 13 → 0x38(%rsp); 0x514d987 → 12 →
   0x40(%rsp); 0x514d99a → 11 → 0x48(%rsp); 0x514d9ad → 10 →
   0x50(%rsp); 0x514d9c0 → 9 → 0x58(%rsp); 0x514daa1 → 6 → r8,
   later 0x70(%rsp); 0x514db62 → 3 → 0x60(%rsp); 0x514db75 → 1
   → pushed as 0x20(%r9).

   Inlined successor keys (sought → required key, store):
   18 → 19 → 0x78(%rsp); 17 → 18 → 0x10(%rsp); 15 → 16 →
   0x20(%rsp); 7 → 8 → 0x80(%rsp); 6 → 7 → %r13; 4 → 5 →
   0x88(%rsp); 3 → 4 → 0x68(%rsp).

   Union: keys 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
   16, 17, 18, 19, 20, 21. Key 2 is never looked up anywhere in
   this function.
3. Row snprintf (0x514dc14, format at 0x7d4ce0): 21 `%s`
   columns. The first variadic argument is r9 = [r15] (loaded
   at 0x514dc11); the twenty stack arguments, in calling order
   (reverse push order), are the key fields for keys 1, 3, 4,
   …, 21 in ascending order. So the row is
   `[r15], key1, key3, key4, …, key21`.
4. Separator: `_M_construct` (0x514dc46) builds a temporary
   string of (second snprintf's full return) copies of 0x2d
   ('-'); the third snprintf (0x514dc82, format `"%s\n"` at
   0x1e4810) appends it plus a newline, starting at
   min(header_len + row_len, 2000) with the remaining budget;
   `_M_dispose` (0x514dc8a) frees the temporary.
5. Failure: every inline block's sentinel check and over-range
   check jumps to 0x514dcb8, which loads rdi = 0x1efeee
   (`"map::at"`) and calls the throw PLT stub 0x5660710 — the
   same string and stub #1314's window uses. A missing key
   anywhere aborts the row; there is no partial row.

## Observations, inferences, unknowns (kept separate)

- Observed: the function reads node+0x48 for every key and
  passes each field to `%s`, so each value+0x20 field holds a
  string pointer at runtime. The value type is therefore at
  least 0x28 bytes with a string field at +0x20.
- Observed: both direct callers (0x515611d, 0x5156afb, same
  enclosing function 0x51560b0..0x5157a19) set the name
  argument (rsi) from `[rax+0x8]` immediately before the call.
- Inference (not claimed as fact): the 21-column layout with
  exactly one non-map column is consistent with the columns
  being keyed 1..21 with key 2's value supplied by the caller
  — but the bytes do not say which key, if any, the first
  column stands for, so it is recorded as `[r15]`, not as
  key 2.
- Inference: why 13 lookups go through the map::at call while 7
  are inlined is not visible in the bytes (likely an inlining
  decision in the original build); the packet claims only the
  behavioral equivalence, which the tests pin.
- Unknown: the source-level container type, the meaning of the
  twenty strings, and the callers' wider logic.

## Verbatim evidence note

The disassembly excerpts in consumer.objdump.txt (the whole
function) and callers.objdump.txt (both call sites) are the
unmodified output of GNU objdump 2.42 for those ranges (the
commands are under Reproduce). The instruction entries in
evidence.json copy the mnemonic, operands and raw bytes from
that output exactly — nothing paraphrased, shortened or
sanitized. In particular, alignment instructions such as `nopl`
and `nopw` are recorded with their full bytes exactly as
objdump prints them; the checker verifies those bytes against
the digest-verified binary, and the excerpt check requires every
recorded mnemonic to appear in the excerpt. This function has
no endbr64: its first instruction is `push %r15`, not a landing
pad, and no endbr64 is claimed for it. Where earlier packets
recorded `endbr64`, that is likewise the genuine instruction
present in those windows' objdump output (`f3 0f 1e fa`), not a
placeholder — but this packet stands on its own bytes, and its
checker re-derives every byte from the binary rather than
trusting the evidence file.

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
objdump -d --start-address=0x514d770 --stop-address=0x514dcdc work/hl-node-94.bin
objdump -d --start-address=0x5156100 --stop-address=0x5156130 work/hl-node-94.bin
objdump -d --start-address=0x5156ae0 --stop-address=0x5156b10 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Then, from the repository root:

```sh
python3 tools/foundation_compaction_stats.py \
  --check research/work-items/foundation-compaction-stats-94/evidence.json \
  --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_compaction_stats -v
```

Environment limits, stated honestly: `make catalogue-check`
fails on this checkout for the pre-existing LFS-pointer identity
reason ("Byte coverage target identity differs") before reaching
this item's files; that failure is not a regression from this
change, and the item's own checker and tests are the verification
that runs here. Rust and Ghidra are unavailable on this VM
(expected); no Rust component is claimed.
