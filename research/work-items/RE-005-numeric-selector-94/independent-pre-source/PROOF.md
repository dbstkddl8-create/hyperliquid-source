# Independent selector scalar and request proof

This fresh proof concerns node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
ELF VA `0x14f7660..0x14f774b`, 235 bytes and 63 native rows. Its basis is the
actual full raw listing and records accepted in1128, freshly read at immutable
main3324e50333042b391312515e542279ca21f63dc8. The recorded body SHA256 is
`a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf`.
Fresh root authentication of the restored captured target is still required.
No old lost temporary result is treated as fresh. This document and its scalar
corpus were authored before reading new selector Rust; they import no repository
module and execute neither captured code nor a PC/register/opcode interpreter.

## Domain and observed projection

Take an unsigned64 input n and a valid caller context F whose DWORD at F+16 is
available. The input QWORD, context, scratch, tables, code and live save/return
areas are valid, nonwrapping and suitably separated. Exclude arbitrary raw
aliases, invalid pointers, faults, unwind and concurrent mutation. The sink
returns normally and respects the ordinary call preservation contract used by
the selector. This proves a bounded argument projection, not its original ABI.

Let B be selector-entry-frame SP+4 after the observed prologue. Native code has
20 available scratch bytes starting at B. Initializing them is a safe source
choice that makes untouched bytes observable; no claim is made that target
stack bytes had a particular initial value. The API's u64 flags parameter is
also chosen: native selection reads a DWORD, so high32 input bits must be inert.

At766a the actual load is DWORD(F+16). At766d/7672 bit25 is tested and branches
to lower hex. Only if clear do7674/7679 test bit26 and select upper hex. Thus
lower wins when both are set, upper applies only with bit25 clear, and decimal
applies with both clear. Every other flag bit is irrelevant to the observed
local selection. This is a theorem over all DWORD values, not finite sampling.

## Hexadecimal spelling and buffer interval

The authenticated table at208620 is ASCII0123456789abcdef and the table203830
is ASCII0123456789ABCDEF. Each actual hex loop stores one selected table byte
for n modulo16, then continues precisely when the old unsigned value exceeds15.
For an abstract scalar decomposition n=16q+r,0<=r<16, the next value is q.
Repeated decomposition therefore terminates in k=1 for n=0 and otherwise
the unique k satisfying16^(k-1)<=n<16^k. Since n<2^64=16^16,1<=k<=16.
The byte sequence reversed from those remainders is the unique canonical base16
spelling, with no leading zero except n=0. This is integer induction on n,
not instruction execution or an emulator model.

The initial native store at SP+19 is B+15. Subsequent stores descend once per
remaining digit, so exactly the interval[B+16-k,B+16) is written. Thus the
B-relative start is16-k and end is16, including for zero. All bytes below start
and all four bytes B+16..B+20 remain unchanged. The native adjustment at771e/7722
produces the same first-digit address; negation at7726 gives k. At7729/7730
the literal bytes3078 at252bed are forwarded with length2, in BOTH hex modes.
In particular upper hex still forwards lowercase x. No physical rendering of
that prefix is proved here.

## Decimal dependency

The decimal arm passes the actual n, B and capacity20 to1570470. Accepted1128
contains the full444-byte/114-row raw body and an all-u64 scalar proof for that
normal-call domain. Its theorem is: D(0)=1;1<=D(n)<=20; exactly[B+20-D(n),B+20)
contains canonical unsigned decimal spelling; the return is20-D(n); earlier
bytes are untouched. The selector uses that returned start at7693..769a to
forward pointer B+start and length20-start. End is20, distinct from hex's16.
The prefix length is0 at76ab; its native raw pointer word is1 and is not a safe
pointer identity requirement for the chosen empty slice representation.

The safe source must genuinely link the accepted independently authored
capacity20 Rust dependency unchanged. A new substitute, stub or copied target
bytes would not satisfy this dependency requirement. No other capacity or
opaque guard behavior is covered by the accepted C20 theorem.

## Opaque callback bridge and return

Both arms restore the original context value from saved RBX into RDI before
the shared call773d. ESI is1 in both arms, so the raw sign argument is1. The
shared slot576e2d8 has accepted relocation addend15723b0. No conditional local
path bypasses or repeats that one call in this domain. Its normal lowAL result
passes through addSP/popRBX/popR14/RET, none of which changes AL. Hence every
one of256 possible low-byte statuses is forwarded unchanged. Sink effects,
hidden result registers, full G, fill/padding/sign interpretation and rendering
remain outside this projection.

The chosen source exposes a single supplied FnOnce sink with the same borrowed
caller-owned context. Context identity and sink mutation should also be checked
in a real Rust unit: numeric context labels alone do not establish object
identity. Start/end are chosen B-relative observation metadata; native code
forwards a digit pointer and length. Raw pointer identity/private ABI is excluded.

## Fresh independent corpus and denominator

The8,892 complete input tuples are all distinct, excluding the caseID when
checking uniqueness. The numeric-boundary family has722 distinct unsigned64
values and2,888 rows over all four selection combinations. The complete status
Cartesian family has5*4*256=5,120 rows. Every one of62 other u64 flag bits is
toggled with three values and four modes:744 probes plus12 baseline rows.
The128 additional rows use four explicit marker patterns. Numeric duplicates
across families are intentional; complete input tuples remain distinct.

The input-only client receives ID,n,flags,20 initial bytes,context label,status.
The separate expectation source uses Python integer str/format and the proved
buffer endpoints to predict all20 final bytes, spans, selected prefix, digits,
rawsign1, unchanged context label, one call and raw status. The source does not
receive expected answers. Finite corroboration complements the scalar proof;
it is not a full-node, ABI, target-machine-byte or component-gate qualification.
