# foundation-decimal-index-replace-94: what does the 0x514b390 window do?

- Component: `foundation`, a decimal-index replace window in the
  node #94 function map (RE-001: decode FDE ranges and validate
  entrypoints with digest-bound records).
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `3324e503`.
- Bounded question: given a decimal input, a container, and a
  target string, when does the function at `0x514b390` rewrite the
  string, and with what?
- Claim: observations about one target function, its decimal-parser
  callee, its `%d` format string, its threshold and table reads, and
  its caller censuses. Container/table naming below is an inference
  from the offsets the bytes use, not a source-level fact.
- Included: the 246-byte FDE entry function with its 10 padding
  bytes, the complete parse/threshold/format/replace rule, the
  151-byte parser callee with its 9 padding bytes, the format
  string, all five direct PLT call targets, and both caller
  censuses.
- Excluded: the source-level identity of the container, of the
  object at `[container + 0x788]`, and of the table at
  `[inner + 0xad8]`; what the table entries represent beyond two
  qwords whose difference divided by 8 is formatted; and any claim
  about the other nine parser call sites beyond their census.

## Why this packet

The function map needs bounded, digest-bound entries for the
functions that turn user-facing decimal input into a rewritten
string. This window is a complete behavior, not a fragment: an
entry function plus the parser callee that decides whether the
input is usable plus the format and replace arms that decide the
observable output plus the threshold and table reads that decide
which value is formatted. It is deliberately distinguished from
its neighbours: `0x514b340` (bounded byte compare, previous
cycle, a different protocol) and `0x514b490` (object-keyed
map::at, previous cycle, a different protocol). The following
FDE at `0x514b490` is the map::at function, not part of this item.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker
and tests use Python's standard library only. No Ghidra, Java, or
REA provider was used: `make doctor` reports Rust and Ghidra
unavailable (expected on this VM, exit 1), and `make rea-doctor`
reports the pinned REA package absent. No target binary, captured
service, networked node, or chain operation was executed. All
analysis below is static byte evidence from the digest-verified
work copy `work/hl-node-94.bin`.

```sh
python3 tools/foundation_decimal_index_replace.py --check research/work-items/foundation-decimal-index-replace-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_decimal_index_replace -v
```

Raw exports were generated with:

```sh
objdump -d --start-address=0x514b390 --stop-address=0x514b490 work/hl-node-94.bin
objdump -d --start-address=0x54307c0 --stop-address=0x5430860 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

The `entry.objdump.txt` file retains complete disassembly of the
entry function including its 10 padding `int3` bytes. The
`parser.objdump.txt` file retains the parser function including
its 9 padding `int3` bytes to the next FDE at `0x5430860`. The
`frames.txt` file retains the entry and parser FDE lines.
`evidence.json` was generated programmatically from the objdump
output and the binary bytes, and the checker re-derives every
claim from the binary. `MANIFEST.sha256` covers
`entry.objdump.txt`, `parser.objdump.txt`, `frames.txt`,
`evidence.json`, and this README, and the checker verifies those
hashes.

## Verbatim-evidence note, stated head-on

Every mnemonic, operand, and instruction byte in `evidence.json`
is copied exactly as GNU objdump emitted it, and the checker
verifies each recorded mnemonic against its own line in the
excerpts and each recorded instruction byte against the binary.
The `endbr64` at `0x514b390` and at `0x54307c0` is a genuine
instruction present in the target binary, not a placeholder, and
the `nopl` bytes at `0x514b419`, `0x54307eb`, `0x543083d`, and
`0x5430843` are genuine compiler alignment NOPs, not
placeholders. The `int3` bytes after each function are padding to
the next FDE, not code.

## Observations

All addresses below are ELF VAs. Section mappings used: `.text`
file offset = VA - `0x1000`; `.rodata` file offset = VA
(all re-derived from the PT_LOAD program headers by the checker,
not assumed).

### Entry, FDE extent, and padding

- `.eh_frame+0x0029a534` describes `[0x514b390, 0x514b486)`,
  246 bytes. Complete linear decoding from that start gives the
  61 instructions in `evidence.json`, ending exactly at the FDE
  endpoint (the last body instruction is the `call` to
  `__stack_chk_fail` at `0x514b481` on the canary-failure path;
  the normal return is at `0x514b418`).
- Ten `int3` bytes follow: the next FDE starts exactly at
  `0x514b490`.
- The function preserves `r13`, `r12`, `rbp`, and `rbx`, uses a
  0x98-byte frame, and is protected by a stack canary: `fs:0x28`
  is saved at `rsp+0x88` on entry and checked before every
  return, with `__stack_chk_fail@plt` (`0x5660430`) on mismatch.
- The objdump nearest-symbol label is stripped-binary arithmetic,
  not a claim about the function's source name.

### The entry rule, in order

Arguments as the bytes use them: `rdi` = container, `rsi` =
target string, `rdx` = input pointer, `rcx` = input length.

1. Parse. A stack parse state is built from `(rdx, rcx)` at
   `rsp`/`rsp+0x8`, with the parsed-value slot at `rsp+0x18`,
   and the parser at `0x54307c0` is called. Before the call,
   `inner = [[container + 0x788] + 0x30]` is loaded into `r13`
   (it is only used later, in step 4).
2. Failure arms. If the parser returns 0, the entry returns 0.
   If any input remains unconsumed (`[rsp+0x8] != 0`), the
   entry returns 0. In both cases the target string is untouched.
3. Threshold. Otherwise the low 32 bits of the parsed value are
   compared, signed, against the dword at `[container + 0x778]`
   (`cmp 0x778(%rbp),%eax`, `jl` to the format branch). If the
   parsed low32 is not strictly less than the threshold, the
   entry returns 0.
4. Format and replace. Otherwise the parsed value is
   sign-extended (`cltq`), `base = [inner + 0xad8]` is loaded,
   and the entry at index `i` (24 bytes at `base + 24*i`) gives
   `count = (signed64([base + 24*i + 8] - [base + 24*i])) >> 3`.
   That count is formatted with `"%d"` (at `0x1f6ff2`) by
   `__snprintf_chk@plt` (`0x56605f0`) into a 100-byte stack
   buffer, its length is taken by `strlen@plt` (`0x5660120`),
   and `basic_string::_M_replace@plt` (`0x5660450`) replaces
   the target string's whole contents (position 0, length
   `[string + 0x8]`) with the buffer. The entry returns 1.

### The parser at 0x54307c0, in full

- `.eh_frame+0x002badc0` describes `[0x54307c0, 0x5430857)`,
  151 bytes; 9 `int3` bytes follow to the next FDE at
  `0x5430860`.
- State: pointer at `[state]`, remaining length at `[state+8]`;
  the parsed value is written to the out pointer (second
  argument, saved in `r11`).
- Empty input returns 0 with out = 0.
- Digits accumulate as `value = value * 10 + digit`, with an
  exact UINT64_MAX bound: the constant `0x1999999999999999`
  (`UINT64_MAX // 10`) is compared before each accumulation, and
  at exactly that value a digit above 5 overflows. Overflow
  returns 0 and leaves the out slot untouched (no store on that
  path); the state is not advanced past the overflowing digit.
- A non-digit stops the parse: it returns 1 with the value so
  far if at least one digit was read, else 0 with out = 0. The
  state still points at the non-digit, so the caller sees the
  remainder.
- Reaching the end of the input returns 1 with the value. After
  each consumed digit the state pointer and remaining length are
  updated, so a fully consumed input has remaining length 0.

### Caller censuses and unknowns

- A full `.text` direct-`e8` scan finds zero call sites to the
  entry `0x514b390`: no caller is claimed for it.
- The same scan finds exactly 10 direct-`e8` call sites to the
  parser `0x54307c0`: `0x514b3d4` (this entry), `0x514cc4e`,
  `0x514dd13`, `0x514ebcf`, `0x5154289`, `0x529ec1f`,
  `0x529ecd0`, `0x529ee36`, `0x529eea8`, `0x529f127`. The other
  nine are a census only; their own protocols are not claimed.
- Unknowns, kept separate from observations: the source-level
  names of the container, the inner object, and the table; what
  the table entries represent; and the behaviour for a negative
  parsed index, which passes a non-negative threshold (signed
  32-bit compare) and would read 24-byte entries before the
  table base. The model raises for that edge rather than
  inventing a table value for it.
