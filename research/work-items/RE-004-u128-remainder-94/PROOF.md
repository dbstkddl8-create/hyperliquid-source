# Complete nonzero-divisor remainder contract, node94

Target is Linux x86-64 node94, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
The actual selected FDE is [0x565f7f0,0x565f8b5), 197 bytes, body SHA-256
12f5828bd833666b6023e761036da32c29aeb7d1e7eedbb93d734f730f391e26.
Every row below refers to this complete byte-grounded GNU disassembly. This
is a mathematical transfer proof, not execution, emulation or a CPU/PC model.
The official __umodti3 artifact name is corroboration, not a numerical premise.

## Contract and environment

Set B=2^64 and entry n=a+B*b=RDI+B*RSI, d=l+B*h=RDX+B*RCX.
All words are unsigned64, 0<=n<B^2 and 0<d<B^2. On either normal local RET,
RAX+B*RDX is the unique remainder n mod d in [0,d).

Assume ordinary x86-64 instruction semantics, immutable mapped code, no
asynchronous register/code changes and a valid ordinary return state: at entry
RSP=S, [S,S+8) contains a usable return address, and the return operation does
not wrap or corrupt code. There are no calls, loops, stack saves, explicit
memory loads/stores or RIP-relative data references in these rows; only RET
accesses memory. This numerical API does not reconstruct original ABI/types,
physical clobbers, arbitrary fault/unwind states or caller meaning/units.

0x565f7f0 saves l in R8. TEST RCX,RCX/JE selects disjoint h>0 and h=0,
exhausting every nonzero d. d=0 is excluded: native h=l=0 ultimately reaches
hardware DIV-by-zero, whose surrounding signal/exception handling is unproved.

## h=0, the complete single-word divisor family

Here l>0. CMP RSI,R8 / JAE at 0x565f876..879 partitions b<l and b>=l.

When b<l, MOV RAX,RDI and MOV RDX,RSI form RDX:RAX=n. DIV R8 at
0x565f881 has nonzero divisor and high numerator b<l, so quotient fits64.
Its RDX result is exactly n mod l. JMP joins 0x565f8a9.

When b>=l, OR RAX,R8 / SHR32 / JE at 0x565f886..890 tests both b,l<2^32.
If either has nonzero upper32, MOV RAX,RSI / XOR EDX,EDX / DIV R8
at0x565f892..897 divides the single word b by l with zero high numerator.
The quotient fits64 because b<B,l>=1, and its remainder rh satisfies0<=rh<l.
Otherwise MOV EAX,ESI / XOR EDX,EDX / DIV R8D at0x565f89c..8a0 performs
32-bit division: both b,l<2^32,l>0, so quotient fits32. EDX/RAX writes
zero-extend, giving the same exact rh. The two paths meet at0x565f8a3,
load a into RAX, then DIV R8 divides rh*B+a safely because rh<l.
Writing b=qh*l+rh proves n=(qh*B)*l+(rh*B+a); therefore its RDX remainder
is n mod l. No quotient or high-digit output is needed or claimed.

At0x565f8a9..8b4 XOR ESI,ESI; MOV RDI,RDX; MOV RAX,RDI; MOV RDX,RSI
return zero highword and the remainder in lowword. The result fits64 because
it is below l<B. This covers both h=0 division widths and their endpoints.

## h>0: normalization and quotient-estimate bound

BSR R9,RCX at0x565f7f8 is defined. Put s=floor(log2 h) in[0,63], e=s+1
in[1,64]. MOV EDX,R9D / XOR EDX,63 produces63-s; MOV AL,64 / SUB AL,DL
produces e exactly in AL. Other EAX bits do not matter: CL's masked count and
TEST AL,64 are used before RAX is fully overwritten with b.

MOV RDX,R8; MOV R10,RCX; MOV ECX,EAX; SHRD RDX,R10,CL; MOV R11,R10;
SHR R11,CL; TEST AL,64; CMOVE R11,RDX at0x565f806..81a construct
M=floor(d/2^e). For e<64, CMOVE selects (l>>e)|(h<<(64-e)); for e=64,
x86 shift counts mask to0 and CMOVE does not select unchanged l, leaving h.
Thus the endpoint e=64 is exact, with2^63<=M<B throughout.

MOV RAX,RSI; SHLD RAX,RDI,63; MOV RDX,RSI; SHR RDX,1 at0x565f81e..829
construct floor(n/2) as RDX:RAX, including the cross-word joined bit. DIV R11
at0x565f82c is safe because high numerator b>>1<2^63<=M. Its quotient is
t=floor(floor(n/2)/M)=floor(n/(2M))<B. MOV RDX,RAX; MOV ECX,R9D;
SHR RDX,CL at0x565f82f..835 produces Qhat=floor(n/(M*2^(s+1))). Count s
is always0..63, including s=0 after the separate e=64 endpoint handling.

Put D'=M*2^e and delta=d-D'. Then D'>=2^(64+s),0<=delta<=2^(s+1)-1,
and D'<=d. If delta=0 the real ratio difference is0. Otherwise:

    0 <= n/D' - n/d = n*delta/(D'*d)
      < (2^(s+1)-1)/2^(2s) <= 1.

For s=0 the last bound is1; for s>=1, s+1<=2s. Strictness follows n<2^128.
Taking floors establishes Qhat in{q,q+1}, where q=floor(n/d). XOR ECX,ECX;
SUB RDX,1; CMOVB RDX,RCX at0x565f838..83e produce q0=max(Qhat-1,0).
Consequently0<=q0<=q<=q0+1. As d>=B, q<B; also q0*d<=n<B^2.

## Exact multiply-back and remainder correction

At0x565f842..84f, MOV R9,R10 / IMUL R9,RDX forms low64 h*q0;
MOV RAX,R8 / MUL RDX gives full l*q0; ADD RDX,R9 forms the highword of
q0*d. IMUL's low64 bits equal the unsigned low product bits and its overflow
flags are unused. The mathematical q0*d fits128 as proved above, so no needed
product bits are lost. SUB RDI,RAX; SBB RSI,RDX at0x565f852..855 give exact
r0=n-q0*d>=0. Since q-q0 in{0,1}, r0 equals r or d+r, where r=n-q*d and
0<=r<d. Thus0<=r0<2*d and r0<=n<B^2, even when2*d needs129 bits.

CMP RDI,R8; MOV RAX,RSI; SBB RAX,R10 at0x565f858..85e compares r0 with d
using the lowword subtraction borrow followed by highword SBB. CF is exactly
r0<d; MOV does not alter flags. CMOVB R10,RCX and CMOVB R8,RCX at
0x565f861..865 replace BOTH divisor words with zero exactly when r0<d;
RCX is still all-zero from0x565f838 and both CMOVs preserve CF.
SUB RDI,R8; SBB RSI,R10 at0x565f869..86c therefore leave r0 unchanged
when r0<d, or subtract d once when r0>=d. These give exactly r in both cases.
The subtraction is nonnegative and fits128. MOV RAX,RDI; MOV RDX,RSI;
RET at0x565f86f..875 return r. No later instruction changes either word.

These disjoint paths cover every n and every nonzero d. All DIV widths,
normalization count endpoints, multiply bounds and borrow decisions are closed.
There are exactly two normal returns,0x565f875 and0x565f8b4.

## Independent source design before Rust

Proposed safe value API: remainder(n:u128, divisor:NonZeroU128)->u128.
Use a128-step high-prefix remainder loop with no division/remainder operator,
no dependency on the target compiler builtin and no need to compute a quotient.
Starting r=0, consume each input bit from127 down to0. Replace r with
2*r+bit; if r>=d subtract d. Maintain the consumed prefix p=q*d+r with
0<=r<d. Since2*r+bit<2*d, one subtraction restores the invariant. Before each
step the consumed prefix has at most127bits, so r<=p<2^127; hence2*r+bit<B^2
and the u128 shift/OR loses no needed bit. At step128, p=n, and uniqueness of
Euclidean remainder proves returned r=n mod d. The loop runs128 steps for all
inputs and needs no table, calls, allocation, unsafe code or captured artifact.

The research compiler must be audited after building to exclude DIV/REM IR,
DIV machine instructions and runtime division/remainder helper dependencies.
O0/O3 production clients consume inputs only; expectations must be frozen from
independently authored integer/native branch equations before Rust exists.
A finite corpus and compiled semantic mutants supplement, not replace, the
full-domain proofs above. Own reproducible rlib bytes are not target identity.
