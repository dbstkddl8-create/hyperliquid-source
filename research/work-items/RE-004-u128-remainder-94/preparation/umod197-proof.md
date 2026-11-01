# Unsigned remainder197 independent pre-source native theorem

Target node#94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
full 197-byte FDE VA `0x565f7f0..0x565f8b5`, 68 retained GNU rows. Basis at
freeze is the actual native row listing `../umod197.objdump`, actual selected
FDE `../umod197-frame.json`, and selected RELATIVE relocation
`../umod197-relocations.json`. No proposed new arithmetic Rust/source design
was read before freezing this mathematical authority. This is a semantic
theorem for unsigned inputs, not native execution or a new byte-identity claim.

Let B=2^64, numerator n=a+B*b, divisor d=l+B*h, with limbs in [0,B). Scope
requires d>0. The entry limbs are RDI=a, RSI=b, RDX=l, RCX=h. The output limbs
RAX+ B*RDX represent n mod d. Signed inputs are outside this theorem.

If h=0, l>0. When b<l, one unsigned DIV64 computes n mod l: its high dividend
limb is strictly smaller than divisor, so its quotient fits64. When b>=l,
the first DIV computes b mod l; it uses DIV32 precisely when (b OR l)<2^32,
otherwise DIV64 with zero high dividend. Both quotients fit their widths.
A second DIV64 then computes ((b mod l)*B+a) mod l; its high dividend limb
is below l, so no quotient overflow occurs. The returned high remainder limb
is zero. These are exactly the branches f876..f8b4.

If h>0, put k=floor(log2 h) and s=k+1 (1<=s<=64). Instructions f7f8..f81a
form D=floor(d/2^s), with 2^63<=D<B. The s=64 arm explicitly selects h,
accounting for x86 masked shift counts. Instructions f81e..f82c divide
floor(n/2) by D. This DIV64 is defined because its high dividend limb is
floor(b/2)<2^63<=D, hence quotient fits64. Shifting that quotient by k gives
q0=floor(n/(D*2^s)). Put A=D*2^s<=d and e=d-A<2^s. Then q0>=q=floor(n/d).

Moreover q0<=q+1. For s>=2, the difference of real quotients is
n/A - n/d = n*e/(A*d) < 2^(2-s) <=1, using n<B^2 and A,d>=B*2^(s-1).
For s=1, e is 0 or1; if e=1 then A>=B and d=A+1, so
n*e/(A*d)<B^2/(B*(B+1))<1. Thus in all cases the floor quotients differ
by at most one. The saturating subtract at f83a..f83e produces
t=max(q0-1,0), which is either q or q-1 (or zero when q=0).

The multiplication f842..f84f forms t*d in128bits. Since 0<=t<=q and
t*d<=n<B^2, the product fits128 and the low-word/cross-product instruction
sequence suffices. The subtract f852..f855 produces the exact nonnegative
r'=n-t*d with r'<2*d. The unsigned limb comparison and conditional divisor
selection f858..f865 choose d exactly if r'>=d, otherwise zero. One final
subtraction f869..f86c yields a value in [0,d), congruent to n modulo d.
It is therefore uniquely n mod d. All DIVs on d>0 have proven nonzero
divisors and bounded quotients; no unexamined arithmetic-fault arm remains.

For d=0 the h=0,b>=l path necessarily reaches a zero divisor in DIV32 or
DIV64, producing a hardware divide fault. No normal return, signal handling
or surrounding exception behavior is claimed. The safe API takes NonZeroU128
and excludes this input by contract. No fabricated zero remainder is supplied.

The independent corpus computes expectations solely with Python big-integer
divmod and validates n=q*d+r and 0<=r<d. It covers every divisor bit boundary,
all64 normalization shifts, both high-limb correction outcomes, all three
low-limb division branches, near quotient multiples, maximum/zero numerators
and10,000 deterministic hash samples. Native mathematical partition labels
are retained only in authority metadata; the actual driver receives only an
opaque case ID and raw128-bit n,d hex words. It cannot read the expected
remainder or native branch labels. No native instruction evaluator runs.

The theorem does not identify the original compiler or prove a new Rust
machine-code match, whole-object identity, native ABI register padding,
unwinding, caller effects or full-node behavior. Complete upstream notices
remain attached to any imported licensed compiled evidence; new independent
Rust, proof and mathematical tooling use the project MIT license.
