# Conditional shell-argument NUL admission

This manual argument uses the authenticated instructions, data, FDEs and
relocations in `observed/`. It does not execute or interpret captured
instructions. The complete relevant converter, finalizer, appender and
constructor FDEs are retained. Only the three stated control windows of the
large spawn FDE are claimed; its complete FDE record fixes their provenance.

## Domain and storage conditions

Let the converter's input be a stable byte sequence `B` at RSI = `p`, with
RDX = `n`, where `0 <= n <= 2^63 - 2`. For nonempty input, all bytes
`[p,p+n)` are readable, address arithmetic does not wrap, and the sequence
does not change during the argument. Output storage at RDI has at least 32
writable bytes and does not alias the input, allocations or live stack.
Ordinary x86-64 little-endian integer/branch semantics and call preservation
are assumed. There is no concurrent, signal-handler or imported-call mutation
of the live input/object outside the stores described here.

The internal allocation call `0x7e4b60 -> 0x70bf30` must return non-null,
disjoint storage of at least the requested length. The unique imported
`memcpy` binding at `0x7e4b68` must perform an ordinary copy and return normally.
These are external storage/call conditions, not recovered allocator behavior.
All other opaque calls on the selected caller path must return normally and
preserve live storage and callee-saved registers. In particular, the earlier
argv growth must preserve its initialized entries and unrelated command
fields. Its lower helper `0x6760d0`, internal reallocator `0x710ea0` and internal
cleanup callee `0x714530` are not proved allocator/deallocator implementations.

The bound on `n` deliberately excludes the converter's signed-capacity
failure branch and wrapped large unsigned lengths. This is not a result for
arbitrary 64-bit lengths, allocation failure, invalid/aliased pointers,
unwinding, or an interposed import with different behavior.

## Allocation and short scan

`0x2bf111..0x2bf11d` makes R14 = `n+1` and rejects its sign bit. The domain
above keeps R14 in `[1,2^63-1]`. R15 retains `n`, R13 retains `p`, and RBX
retains the output address. The allocation call at `0x2bf129` receives R14.
Its non-null result becomes R12. For `n=0`, `0x2bf13e` goes directly to the
finalizer; no input byte or `memcpy` is used. For `n>0`, `0x2bf144..0x2bf14d`
copies exactly `n` input bytes into R12 before searching the **original** R13
input. Stability is necessary to relate the eventual copy and search result.

For `1 <= n <= 15`, `0x2bf159..0x2bf174` starts RCX at zero, reads `B[RCX]`,
and branches to the error stores on equality with zero. Otherwise RCX advances
by one until it equals `n`. Thus the first zero, if any, is returned as RCX;
the no-zero path reaches `0x2bf210`. The loop reads no byte at index `n`.

## The two-word zero detector

For `n >= 16`, define `a = ((p+7) & ~7) - p`, so `0 <= a <= 7`. The input
address domain makes this rounding non-wrapping. If `a>0`, the scalar prefix
`0x2bf1d2..0x2bf1ee` checks exactly indices `[0,a)` in increasing order,
returning the first zero if present. If `a=0`, the prefix is empty.

The loop at `0x2bf1a0` is entered only for an offset `i <= n-16`. It reads
two little-endian words `w0 = B[i..i+8)` and `w1 = B[i+8..i+16)`; both are
inside the input. The actual immediate bytes bind

```text
A = 0x0101010101010100
H = 0x8080808080808080
M(w) = (((A - w) mod 2^64) | w) & H
```

The subtraction/OR/AND instructions `0x2bf1aa..0x2bf1bf` produce
`M(w0) & M(w1)`; the second explicit `& H` is unnecessary because the first
operand has already been masked. `0x2bf1c2` compares the result with H.

The needed word lemma is **`M(w) == H` exactly when every byte of w is
nonzero**. This is a statement about all 64-bit words, proved by ordinary
base-256 subtraction, not by sampling words:

* The low byte of A is zero, with incoming borrow zero. For input byte `b`,
  the subtraction digit is `(-b) mod 256`. If `b=0`, the digit and `b` both
  have high bit zero. If `1 <= b <= 127`, the digit has high bit one. If
  `128 <= b <= 255`, `b` itself has high bit one. For every nonzero `b`,
  subtraction also sends borrow one to the next byte.
* Before the first zero, each higher byte has minuend one and incoming borrow
  one. Its digit is again `(-b) mod 256`. Every nonzero byte therefore
  contributes high bit one and preserves borrow one.
* If there is a first zero at any byte position, that position's digit is
  zero by the same calculation. Its OR high bit is zero. Borrow behavior at
  subsequent positions cannot change that already computed lower byte.

Consequently all nonzero bytes yield H, and any first zero yields a missing
high bit. This does not claim that **every** missing high bit identifies a
zero byte: later borrow changes can affect later bits. The code needs only
the whole-word equality, and obtains the exact index with a scalar scan.
The conjunction of the two masks equals H iff both words have no zero.

`check_algebra.py` binds A/H from the authenticated capture and checks all
256 byte values in the two incoming-borrow states used above (512 finite
digit transitions). It also demonstrates that changing A's low byte from
zero to one breaks the stated word property for a word of eight `0x01`
bytes. These checks support the small algebra lemma; the word induction and
the mapping to the target's instructions remain the argument here.

## First index, tail, and bounds

At entry to each two-word iteration, every earlier input byte has been
checked nonzero: initially by the scalar prefix, subsequently by the word
lemma. Equality with H advances RAX by 16 at `0x2bf1c7`. The next iteration
is permitted only by unsigned `RAX <= n-16` at `0x2bf1cb..0x2bf1ce`.
Thus no word read crosses `p+n`. The advanced offset is at most `n`; it cannot
wrap under the admitted length bound.

If a block contains zero, `0x2bf1c5` leaves RAX at the **start of that
block**, then reaches `0x2bf20b`. If fewer than 16 bytes remain after the
prefix or a successful block, the same tail entry receives the first
unchecked offset. The scalar loop `0x2bf200..0x2bf20e` checks successive bytes
until a zero or index `n`. For a suspect block, it rescans from the block's
start rather than guessing an index from a word mask. Because all preceding
bytes are nonzero, its first zero is the minimum zero index of the entire
input. `0x2bf23d` copies this index from RAX to RCX before the error stores.
If no zero is found, the loop reaches the finalizer. These cases cover empty,
short, all eight input alignments, word-loop and scalar-tail paths in-domain.

## Raw converter result and finalizer specialization

If `k = min { j < n : B[j] == 0 }` exists, `0x2bf240..0x2bf24b` stores these
four 64-bit words in the result and returns through `0x2bf24f`:

| Offset | Stored value |
| --- | --- |
| +0 | `n+1` |
| +8 | allocated copy pointer R12 |
| +16 | `n` |
| +24 | exact first zero index `k` |

The copy contains the original `n` bytes. No extra terminator was appended
on this branch, and the allocation's last byte is not asserted initialized.

When no zero exists, `0x2bf210..0x2bf220` supplies the finalizer with capacity
`n+1`, allocation pointer and initialized length `n`. In `0x2bea00`, capacity
differs from length, so `0x2bea1f` stores zero at allocation + `n`. Increment
at `0x2bea23` makes length equal capacity; `0x2bea29` selects `0x2bea44`.
Neither the grow nor shrink/reallocation branch is selected, including for
`n=0`. RAX returns the unchanged pointer and RDX returns `n+1`.

`0x2bf226..0x2bf238` stores pointer at result +8, `n+1` at +16 and raw tag
`0x8000000000000000` at +0. Result +24 is not written on this success path.
The allocation therefore contains `B` followed by a single appended zero;
no earlier zero exists. This recovers the result projection for this input
domain, not a nominal Rust type or every use of the general finalizer.

## Appender projection and sticky flag

`0x67f2a6` calls the converter. `0x67f2b4..0x67f2ba` negates the returned
first word and tests signed overflow. Only `0x8000000000000000` overflows
64-bit negation. In the stated domain every error word `n+1` is positive,
so it selects `0x67f2c1`; success selects `0x67f2bc`.

Success preserves the converted pointer in R12 and does not clear or set the
command byte at +0xc0. Error stores byte one at command +0xc0, then requests
18 bytes. `0x67f2db..0x67f2e5` copies sixteen bytes from `0x6ade7` and stores
little-endian word `0x003e` at +16. The resulting bytes are exactly
`<string-with-nul>` followed by zero. The helper then passes the earlier
allocated copy and its positive capacity to the internal cleanup slot
`0x7e4b80 -> 0x714530`. Normal return, preservation of the command and of the
substitute allocation are conditions; allocator lifetime correctness is not
proved merely by naming this call. The first-zero index is not forwarded by
the appender.

Both branches join `0x67f2fe`. For valid old argv length `m>=1`, the selected
pointer replaces argv[m-1] at `0x67f30f`. If `m==capacity`, a growth call occurs
before the new null is stored. Its prefix/field preservation remains an
explicit condition. Then null is stored at argv[m] and length becomes `m+1`.
The error branch thus completes an ordinary append of substitute bytes and
leaves a sticky byte flag; it does not directly return the original NUL error.

## Fixed shell caller and the call-free spawn rejection

This application begins on #1266's normal prepared-output path at
`0x3d9117`, with S defined as the stable pointer/length output already chosen
by the shell helper. Its exact format/preparation content is not needed here.
The constructor gets the seven bytes `/bin/sh`; the loop then invokes the
appender for `-c` and S, in that order. Those calls and the subsequent direct
call at `0x3d9192 -> 0x66f280` use the same command object W. The complete
shell-helper FDE is retained for this existing caller context.

The fixed program and `-c` contain no zero. Program conversion takes the
constructor's success path: `0x67f4c4` zeros R15D, `0x67f504` saves that
value and `0x67f62a..0x67f62d` writes its low byte to W+0xc0. Constructor
stores `0x67f5ef` and `0x67f5f7` also zero W+0x70 and the word W+0x78.
No other constructor path is being asserted. The pointer-array capacity and
length are both two when construction returns.

The `-c` append initially needs growth. As in #1266, normal growth must yield
capacity four, preserve the existing entries and the unrelated command
fields, and return normally; its lower allocator is not closed here.
After that append, length is three, capacity is four and the NUL flag remains
zero. S is the second append and therefore needs no further argv growth.
Under the stated allocation/cleanup conditions its flag is zero iff S has
no embedded zero, and one iff S has an embedded zero. In the latter case
argv[2] holds the substitute, not S. No arbitrary existing-command or
environment mutation is part of this state premise.

At spawn entry, `0x66f2aa` reads W+0x78 = 0 and `0x66f2ae` reads W+0x70 = 0.
`setne; or; cmp 1` at `0x66f2b5..0x66f2ba` therefore yields inequality and
`0x66f2c1` branches directly to `0x66f3e3`, bypassing the alternate
environment-preparation path. RBX was initialized to raw `INT64_MIN` at
`0x66f2a0`. `0x66f3e3` copies it to stack slot rbp-0x120.

For S containing zero, the test at `0x66f3ea` sees W+0xc0 = 1. The selected
instructions `0x66f3f7..0x66f408` write QWORD `0x7dbfd0` to result +8,
DWORD 1 to result +0 and jump to `0x6702f2`. The descriptor's unique RELATIVE
binding is `0x7dbfd0 -> 0xbe3c8`; its following raw words are 31 and 20.
The bound 31 bytes are `nul byte found in provided data`. No nominal error
enum is inferred from raw 20, and result bytes +4..+7 are not specified.

At `0x6702f2`, the saved sentinel equals unchanged RBX. Equality skips the
cleanup call at `0x670302` and reaches the return epilogue at `0x670307`.
There is **no callee invocation anywhere on this selected path through
0x66f280**, from entry to its return at `0x670318`. Consequently this fixed
state produces the stated local error result before any spawn-backend call.
This does not assert that the earlier preparation/appender had no effects.
The shell helper's following DWORD-1 gate goes to its existing opaque spawn
error construction; that later result and its eventual return are unproved.

For zero-free S, the same check takes `0x67021f`, beyond the selected windows.
It passes this local NUL rejection gate; actual spawning, argument consumption,
host shell identity and command success remain unproved. The separate
environment-conversion flag store/test elsewhere in the full spawn FDE is
not covered by the fixed no-environment path above. This is not a universal
theorem for all command objects or all spawn errors.

## Evidence and claim boundary

Native decoding agrees on byte partitions; full-file authentication and
corruption controls establish the records' identity/integrity. The finite
algebra check establishes its documented mathematical transitions. Neither
automatically proves the manual semantics. Existing FDEs and caller records
are reused evidence, not new recovered-function or whole-component credit.
No captured target, instruction evaluator, emulator, shell child, process
backend or target network runs. No acceptance gate or Rust reconstruction is
claimed. Allocation, failure/unwind paths, actual S production and global
supervision policy retain their stated boundaries.
