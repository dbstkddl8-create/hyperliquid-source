# Conditional argument: descriptor wait and its caller

This argument concerns the captured visor with SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
All addresses are linked ELF virtual addresses. The input was authenticated
before native decoding. No captured instructions were executed or emulated.

The complete FDE ranges are:

| Role | Extent | Bytes |
| --- | --- | ---: |
| Descriptor-wait helper | `0x671e30..0x671fe4` | 436 |
| Existing wait-wrapper context | `0x67f160..0x67f290` | 304 |
| Tagged-error cleanup | `0x65f260..0x65f32e` | 206 |

`observed/records.json` and the corresponding
`observed/{descriptor-wait,wait-wrapper,error-drop}.objdump.txt` files retain
the byte, FDE, relocation and instruction evidence. The wrapper is a revisited
dependency, not a newly recovered function or additional coverage claim.

## Domain and external assumptions

The argument describes ordinary local call/return paths with valid x86-64
SysV call state. The result destination has at least sixteen writable bytes.
The wrapper's input state has at least sixteen readable/writable bytes. These
regions, the active stack/return records, imported-function storage and the
immutable image do not alias in a way that changes live inputs or control data.
Each stack allocation and aligned vector store is valid. Imported calls return
normally and preserve the ABI's callee-saved registers and unrelated live
storage. These are explicit premises, not consequences of a call returning.

For the imported wait operation, its 128-byte output buffer remains readable;
for the fallback ioctl, its 64-byte buffer remains readable. The pointer
returned by the imported errno accessor remains valid for the subsequent
reads, including the read after ioctl. Relevant writes by those imports must
obey their external ABI. `ABI.md` qualifies conventional Linux names for the
observed constants and fields; the raw local conclusions below do not establish
the deployed kernel, libc, symbol interposition, descriptor lifetime or process
state. A non-`-1` imported return is called a success branch only because that
is how these instructions select it.

Exceptions, asynchronous mutation, invalid storage, allocator behavior and
general heap-error cleanup are outside this argument. In particular, the
callee bound by slot `0x7e4c00` is opaque: neither its return nor its
non-return is assumed when describing the normal output cases.

## 1. Initial imported call and buffers

Let `O` be the original RDI result pointer, `fd` the original ESI value, and
`flags` the original EDX value. At `0x671e42..0x671e47`, the helper preserves
`flags` in ECX, `fd` in R14D and `O` in RBX. ESI still holds `fd`.

Eight sixteen-byte zero stores at `0x671e4d..0x671e7e` initialize the complete
buffer `B = RBP-0x100`, extent 128. At `0x671e85..0x671e91` the call arguments
are `(EDI=3, ESI=fd, RDX=B, ECX=flags)`. The unique GLOB_DAT relocation at
`0x7e7d80` names `waitid`. This is one local imported call; it is not evidence
that the import itself makes only one kernel operation.

The DWORD comparison at `0x671e97` distinguishes return `0xffffffff` from
every other value. Only the former takes the errno path at `0x671edb`.

## 2. Non-error result, no event and six status cases

On a non-`-1` return, `0x671e9c` tests DWORD `B+0x10`. If it is zero, the
route `0x671f51..0x671fb5` writes DWORD `O+4=0` and DWORD `O+0=0`, then
returns through `0x671fbb..0x671fca`. It does **not** initialize `O+8`.
The absent payload must not be compared or reported as a fabricated zero.

Otherwise DWORD `B+8` is loaded into ECX and decremented modulo 2^32 at
`0x671eaf`. The unsigned comparison at `0x671eb1..0x671eb4` admits exactly
the original values 1 through 6. All other values branch to `0x671fcb`.
For admitted values, EAX receives the raw DWORD `s = B+0x18`.

The six table entries beginning at `0xbcdf8` are signed 32-bit displacements
relative to that table base, as specified by `movsxd`/`add`/`jmp` at
`0x671ec7..0x671ece`. Their decoded destinations and resulting DWORD status
are:

| Raw `B+8` | Entry bytes | Destination | Status stored at `O+8` |
| ---: | --- | --- | --- |
| 1 | `a1 51 5b 00` | `0x671f99` | `(s & 0xff) << 8` |
| 2 | `ae 51 5b 00` | `0x671fa6` | `s` unchanged |
| 3 | `9a 51 5b 00` | `0x671f92` | `s \| 0x80` |
| 4 | `d8 50 5b 00` | `0x671ed0` | `((s & 0xff) << 8) \| 0x7f` |
| 5 | `d8 50 5b 00` | `0x671ed0` | `((s & 0xff) << 8) \| 0x7f` |
| 6 | `a9 51 5b 00` | `0x671fa1` | `0xffff` |

Case 1 shifts EAX and then zero-extends AX at `0x671f9c`. Cases 4 and 5
shift EAX and OR `0x7f` before the same sixteen-bit truncation. Cases 2 and 3
have **no** additional low-byte or low-seven-bit mask. All six reach
`0x671fa6`, which writes DWORD `O+4=1`; `0x671fb2` writes the selected status
to `O+8`; `0x671fb5` writes DWORD `O+0=0`.

The out-of-range code route supplies data addresses `0xbe5bf` and `0x7dc210`
and the numeric ESI value `0xab` before calling slot `0x7e4c00 -> 0x49ae00`
at `0x671fde`. It supplies no normal result-store path in the retained FDE.
This identifies an exceptional handoff, without claiming the callee's full
formatting ABI, unwind behavior, or what happens if it returns past this range.

## 3. Error packing and the one fallback condition

The call at `0x671edb` uses the unique GLOB_DAT slot `0x7e5900`, named
`__errno_location`. Let `e` be the DWORD read from its returned pointer at
`0x671ee1`. The zero-extending R15D load, 64-bit shift and OR construct

`P(e) = (uint64(uint32(e)) << 32) | 2`.

The comparison at `0x671eef` permits the fallback **only when e=10**.
Every other error, including e=4, follows `0x671f5a..0x671f64`: QWORD
`O+8=P(e)` and DWORD `O+0=1` are stored, then the helper returns. `O+4`
is not written on this route. There is no local loop back to `waitid`.

For e=10, the original packed word is retained in R15 and local `RBP-0x28`.
The errno pointer is retained in R12. The 64-byte ioctl buffer
`I = RBP-0x78` is initialized as QWORD `I+0=8` followed by 56 zero bytes:
three sixteen-byte stores cover `I+8..I+56`, and the QWORD store at
`0x671f0a` covers `I+56..I+64`.

At `0x671f1a..0x671f28`, the imported `ioctl` call bound by GLOB_DAT slot
`0x7e70c8` receives `(EDI=fd, ESI=0xc040ff0b, RDX=I)`; EAX is cleared for
the variadic calling convention. The request and input mask are observed
constants. Only the ABI qualification assigns them Linux interface names.

### Fallback success

If the ioctl return is not `-1`, `0x671f33..0x671f43` copies DWORD `I+60`
unchanged to `O+8` and writes QWORD `0x0000000100000000` to `O+0`. Thus the
DWORD result tag is zero and the DWORD presence field is one. This path does
not use the six-case status translation and does not test a returned mask
before reading that field.

The original packed e=10 word at `RBP-0x28` is then passed by address to
`0x65f260` at `0x671f4a`. The low-tag argument in section 4 establishes why
this cleanup returns without reaching any heap callback on this route.

### Fallback failure preserves the original error

If ioctl returns `-1`, `0x671f66` reads the current DWORD errno from the
previously retained pointer. Call it `e2`. Instructions through `0x671f7a`
construct `P(e2)` at `RBP-0x30` and a local DWORD tag 1 at `RBP-0x38`.
However, the actual output stores at `0x671f81..0x671f85` write the original
R15 value, **P(10)**, to `O+8`, and DWORD tag 1 to `O+0`. The newly packed
ioctl error `P(e2)` is only passed by address to cleanup at `0x671f8b`.

Consequently, under the stated ordinary-return/storage premises, a failed
fallback retains the original numeric error 10, whatever the second error
was. It does not replace the result with the ioctl errno or retry either
import locally. `O+4` remains untouched on this error branch.

## 4. Cleanup of these packed words is a proved leaf path

The complete cleanup FDE is `0x65f260..0x65f32e`. At `0x65f26b` it reads
the QWORD addressed by RDI, computes its low two bits in ECX and compares
the unsigned DWORD `(tag-2)` against 2. Tags 2 and 3 branch directly to
the restore/return sequence at `0x65f280`; tag 0 reaches that same sequence
through the zero test. Only tag 1 enters the pointer/callback path.

Every `P(e)` above has tag 2, including the original and fallback error words
and the wrapper's interrupted-PID-wait word. The caller explicitly stores
each such word in valid local storage before passing its address. For this
domain the cleanup has no imported/indirect call, no heap access and no
result-region write: it reads that local word and restores its own frame.
This closes the specific cleanup dependency without assigning behavior to
the retained heap-tag path, its indirect callees or the unwind path.

## 5. Wrapper composition and cache writes

Let `C` be the wrapper's original RSI state pointer and `R` its original RDI
result pointer. The wrapper preserves them in R14 and RBX respectively.

- At `0x67f177`, DWORD `C+0=1` selects the cached route: load DWORD `C+4`,
  store it to `R+4`, write DWORD `R+0=0`, and return. No wait import is
  called on this route.
- Otherwise DWORD `C+0xc` supplies the descriptor. Its `0xffffffff`
  sentinel selects the PID lane. Every other value reaches the descriptor
  call at `0x67f197`, with result storage `RBP-0x40` and numeric flags 4.
- `0x67f19c` tests the descriptor result's **byte** tag. On its nonzero
  route, the QWORD payload is copied to `R+8` and DWORD `R+0=1` is stored.
  No cache write or local retry occurs. The helper above only constructs
  DWORD tags 0 and 1 on its normal result paths, so the byte test distinguishes
  those paths without reading an uninitialized tag byte.
- On tag zero, `0x67f24e` tests the result's **byte** presence field. For
  the helper's present value 1, `0x67f254..0x67f267` loads the status,
  writes DWORD `C+0=1`, DWORD `C+4=status`, DWORD `R+4=status`, and DWORD
  `R+0=0`. Descriptor bytes `C+0xc` and PID bytes `C+8` are unchanged.
- For presence zero, the wrapper instead reaches `0x67f277..0x67f28a`,
  passing `0xbe47b`, `0x7dc078` and numeric `0xa9` to the same opaque
  `0x49ae00` target. It does not consume the absent, uninitialized status
  or produce a normal success/cache result inside its retained FDE.

These observations do not declare the no-event route unreachable merely
because this caller passes flags 4. Such a claim requires additional external
wait semantics. The exceptional callee's behavior remains outside the proof.

## 6. Descriptor/PID interruption asymmetry

The PID lane at `0x67f1ba..0x67f1ce` calls imported `waitpid` through slot
`0x7e7df8`, with PID `C+8`, a zero-initialized status DWORD, and flags zero.
If it returns `-1`, the wrapper reads errno and packs it using the same
`P(e)` rule. Its comparison at `0x67f209` singles out numeric error 4.
That route cleans the tag-2 word and calls `waitpid` again at `0x67f220`.
Repeated `-1` results cycle through `0x67f1f0`; error 4 can keep this local
loop repeating, while another error is returned through `0x67f26b`.

In contrast, when the descriptor lane's imported `waitid` returns `-1`
with numeric errno 4, section 3 proves it returns `P(4)` immediately; the
wrapper's descriptor-error route propagates it unchanged. Under the ABI's
identification of 4 as EINTR, these two local lanes therefore handle that
returned interruption differently. The existing termination packet's outer
retry loop is a separate layer. This argument does not claim how an imported
libc routine internally restarts a kernel operation, or a global retry bound.

On a non-`-1` PID return, `0x67f228..0x67f239` caches its status and writes
the same normal wrapper result shape. This additional context establishes
the comparison; it is not a new PID-wait reconstruction claim.

## Boundaries of the conclusion

This is a conditional static argument about local instructions, result stores,
table destinations and uniquely bound imports. Decoder agreement and capture
corruption checks support the evidence, not complete runtime equivalence.
The packet does not execute a wait, ioctl, signal, captured binary, emulator
or child process. It establishes neither process termination nor descriptor
availability, Linux version, wall-clock behavior, overall supervisor policy,
complete panic/unwind behavior or a recovered nominal Rust result type.
No Rust reconstruction, matched-code credit or completed component gate is
claimed.
