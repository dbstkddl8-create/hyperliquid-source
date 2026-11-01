# External ABI qualification

The captured instructions establish numeric arguments, byte offsets and result
stores. The following names qualify those observations against **Linux v6.15**,
commit `0ff41df1cb268fc69e703a08a57ee14ae967d0ca`. Exact source-file SHA-256 and
Git blob identities are in [ABI-SOURCES.json](ABI-SOURCES.json). These public
UAPI headers carry `GPL-2.0 WITH Linux-syscall-note`; they were read as external
evidence and are not copied into the new MIT-authored scripts.

This is an ABI comparison, not proof of the original compiler's headers, the
deployed kernel/libc version, symbol interposition or successful process waits.
In particular, earlier kernels may not supply the same optional information.

## waitid arguments and returned fields

[linux/wait.h](https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/include/uapi/linux/wait.h)
assigns `P_PIDFD=3`, `WEXITED=4`, `WNOHANG=1`, `WSTOPPED=2` and
`WCONTINUED=8`. The helper passes its flags argument unchanged to the imported
`waitid`; the studied wrapper supplies 4. Thus this caller requests the exited
case without WNOHANG. The full helper still has six status-code arms. Their
presence does not prove all arms are reachable from this caller on an ordinary
kernel.

[asm-generic/siginfo.h](https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/include/uapi/asm-generic/siginfo.h)
defines a 128-byte `siginfo_t`, its three leading int fields, and the child
payload. The [x86 header](https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/arch/x86/include/uapi/asm/siginfo.h)
includes that generic layout and applies special overrides only for x32.
Under the ordinary Linux x86-64 LP64 layout, the child union starts at offset
16 because of its eight-byte alignment. The observed offsets consequently map
as follows:

| Offset | Header field | Local use |
| ---: | --- | --- |
| 8 | `si_code` | Six-entry selector after a bounds check |
| 16 | `si_pid` | Zero selects the absent-event result |
| 24 | `si_status` | Input to the selected status conversion |

The header assigns `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`, `CLD_TRAPPED`,
`CLD_STOPPED`, and `CLD_CONTINUED` the respective values 1 through 6. The
conversion table in [PROOF.md](PROOF.md) is derived from the captured bytes;
these names do not replace that proof or impose extra masks on its raw inputs.

## Error constants

[asm-generic/errno-base.h](https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/include/uapi/asm-generic/errno-base.h)
defines `EINTR=4` and `ECHILD=10`. These identify the wrapper's PID retry
comparison and the descriptor helper's fallback comparison respectively.
The original error is retained when the fallback fails; the code does not
return the second errno. This is an observed local policy, not a claim about
why any particular kernel produced either error.

## The 64-byte pidfd information request

[linux/pidfd.h](https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/include/uapi/linux/pidfd.h)
defines `PIDFD_INFO_EXIT=1<<3`, the version-0 structure size 64, and
`PIDFD_GET_INFO` as a read/write ioctl with type `0xff` and number 11.
The v6.15 structure has two u64 fields followed by twelve 32-bit fields;
its final `exit_code` is at offset 60. This matches the observed input mask
8 and the raw DWORD load at buffer+60.

The [generic ioctl encoding](https://github.com/torvalds/linux/blob/0ff41df1cb268fc69e703a08a57ee14ae967d0ca/include/uapi/asm-generic/ioctl.h)
uses eight number bits, eight type bits, fourteen size bits and two direction
bits. Read/write direction is 3. For this 64-byte interface:

`(3 << 30) | (64 << 16) | (0xff << 8) | 11 = 0xc040ff0b`.

This is the literal passed by the captured helper. The source pin matters:
v6.13 still called the final word spare storage, while v6.16 extends the
structure with coredump fields. Neither a guessed current structure size nor
an older field name should silently replace this 64-byte request.

The header distinguishes requested fields from fields actually filled using
the returned mask. The local success branch reads buffer+60 without a mask
test. Accordingly this packet proves a raw field copy, conditional on the
imported result; it does not independently establish that the field contains
a valid process exit status on every host or kernel. No live ioctl or process
operation was invoked to test the interface.
