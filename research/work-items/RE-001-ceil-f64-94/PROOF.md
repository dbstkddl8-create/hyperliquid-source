# Scalar result of the node94 ceiling leaf

This is a static argument for the low 64 bits of XMM0 on ordinary return from
ELF VA `[0x565f670, 0x565f6e7)`. It assumes the captured instructions and the two
mapped constants are intact, and that RET has a valid return address. It does
not execute the target, prove the caller, or identify the original source.

Let `b` be the input low word of XMM0, `s = b >> 63`, and
`E = (b >> 52) & 0x7ff`. A finite normal binary64 number has magnitude
`(2^52 + fraction) * 2^(E - 1075)`. Subnormals have magnitude
`fraction * 2^-1074`.

The complete 30-instruction listing has five conditional edges and three
returns. Every conditional destination is an instruction boundary inside the
119-byte FDE. There are no calls or unconditional jumps in this leaf. The only
explicit memory reads load the constants listed below; RET reads the return
word. The instructions perform integer arithmetic and bit moves, with no
floating-point arithmetic or comparisons.

## Large magnitudes and exceptional encodings

At `0x565f682`, `cmp ecx,0x432` followed by unsigned `ja` returns at
`0x565f6cd` when `E > 1074`. XMM0 has not been written on this path.

For `1075 <= E <= 2046`, the finite value is already an integer because the
unbiased exponent is at least 52. For `E = 2047`, the same path returns infinity
or NaN without changing any low-word bit. In particular, it preserves both NaN
signs, every payload, and the signaling/quiet bit. This is a bit-preservation
observation, not a claim that a host language's `ceil` has the same NaN policy.

## Magnitudes below one

The unsigned `jbe` at `0x565f690` selects `E <= 1022`. All these values are
finite and have magnitude below one. `test rax,rax` at `0x565f6ce` then has
three outcomes:

| Input | Selected path | Output low word |
| --- | --- | --- |
| Sign bit set, including negative zero/subnormals | `js 0x565f6de` | `0x8000000000000000` from VA `0x20a910` |
| All bits zero | `je 0x565f6cd` | unchanged positive zero |
| Positive nonzero | load at `0x565f6d5` | `0x3ff0000000000000` from VA `0x20a730` |

Thus positive values below one become +1, negative values above -1 become
-0, and both input zero signs are preserved. No subnormal floating-point
operation occurs, so the scalar result does not depend on denormal handling or
the rounding-control bits in MXCSR.

## Normal finite values with fractional bits

The remaining exponent range is `1023 <= E <= 1074`. Let `e = E - 1023`, so
`0 <= e <= 51`, and let `m = 2^(52-e) - 1`.

`add ecx,0xfffffc01` computes `e` modulo 2^32. The shift of
`0x000fffffffffffff` at `0x565f6a2` then produces `m`. Since `e` is between
0 and 51, hardware masking of the shift count has no effect.

If `b & m == 0`, the `je` at `0x565f6a8` returns the original XMM0: the value
already has no fractional bits. Otherwise:

1. `cmovs rdx,rsi` at `0x565f6b1`, with RSI zero, chooses addend zero for
   negative inputs and `m` for positive inputs.
2. Arithmetic right shift of `0xfff0000000000000` by `e` gives `~m` in
   64 bits. The sign-filled leading ones preserve the sign and exponent.
3. `add rdx,rax; and rsi,rdx; movq xmm0,rsi` returns
   `(b + (s == 0 ? m : 0)) & ~m`.

For negative inputs, clearing the fractional bits reduces the magnitude to
its integer part, which rounds the negative value toward positive infinity.
For positive inputs with a nonzero fractional field, adding `m` carries into
the least retained bit; clearing the fractional field rounds to the next
integer. A carry out of the significand increments the exponent correctly.
The largest admitted exponent is 1074, so such a carry can reach 1075 but
cannot reach infinity or the sign bit. Already-integral values are unchanged
by this equation as well: adding `m` to a zero fractional field causes no
carry. This justifies the compact equation used in `verify.py`.

These three exponent partitions cover all 2^64 possible input bit patterns.
The finite scalar result is mathematical ceiling with the stated zero-sign
policy. Exceptional results are the unchanged input bits. This argument does
not establish an ABI beyond the scalar word, upper XMM lanes, original symbol
name, compiler provenance, callers' input domains, or whole-node equivalence.

## Independent numerical check and limits

The verifier separately decodes each finite test input as an exact integer
times a power of two. Integer numerator/denominator division computes ceiling,
then an exact integer-to-binary64 encoder produces the expected result. It
uses neither host floating-point rounding nor the leaf's fractional-bit mask.
The exceptional-bit and signed-zero policies come from the paths above; they
are not independent mathematical evidence for those policies.

The 33,066-case corpus includes both signs of every exponent field, selected
significand edges, exponent-dependent mask edges, and 4,096 deterministic
SHA-256-derived bit patterns. It is sampled corroboration of the argument,
not an exhaustive execution test. Four deliberately incorrect equations
produce 405, 8,226, 9 and 10 mismatches respectively. No CPU interpreter,
captured instruction execution or differential runtime harness is used.
