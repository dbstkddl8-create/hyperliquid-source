# RE-013: Visor descriptor-wait result and cache contract

The existing [termination-retry](../RE-013-visor-child-termination-retry/README.md)
and [shell-command](../RE-013-visor-shell-command/README.md) packets leave the
descriptor-wait callee at `0x671e30` opaque. This packet resolves its bounded
local contract and composes it with the existing wait wrapper. A reconstruction
must preserve the status translation, error selection and cache behavior below.

- Component/task: `visor` / RE-013; static research, no progress gate requested.
- Baseline: `d3af75257a396c85d20857f421c370ddb8cb40e5` on `main`.
- Target: separate captured Visor, 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Coordinates: linked ELF virtual addresses, with file offsets recorded from
  file-backed PT_LOAD mappings. No guessed loader base.
- The seven repository submodule pins remain unchanged. No inferred unlicensed
  reference implementation was read or copied for this packet.

## Result

| Path | Byte-backed conclusion |
| --- | --- |
| Initial call | The helper calls the uniquely relocated `waitid` import with type 3, the supplied descriptor, a zeroed 128-byte buffer and the supplied options. The wrapper supplies options 4. |
| Present event | A six-entry relative jump table translates raw event codes 1..6 and their raw status word into the returned DWORD. The complete table and exact truncations are in PROOF.md. |
| Absent event | Zero at buffer+16 returns tag 0 and presence 0. The absent payload is not initialized. The wrapper routes absence to an opaque exceptional callee rather than caching it. |
| Ordinary wait error | Errno other than 10 is packed and returned immediately, including numeric 4. The descriptor lane does not locally retry this error. |
| Fallback | Errno 10 selects one `ioctl(fd, 0xc040ff0b, buffer)` with input mask 8. A non-error result copies DWORD buffer+60 unchanged. A failed ioctl returns the **original** packed errno 10 and drops the second packed errno. |
| Cleanup | All error words used on these paths have low tag 2. Their cleanup takes a proved leaf return without entering the retained heap/callback path. |
| Cache | The wrapper copies present status into its state, marks that state cached, and returns status. A later cached call bypasses both wait paths. Error results do not update the cache. |
| PID comparison | The wrapper's separate `waitpid` lane internally retries numeric error 4. This differs from the descriptor lane's propagation of the same numeric error. The outer supervisor retry policy remains separate. |

[PROOF.md](PROOF.md) gives every local condition, result-store offset, jump-table
entry and relevant branch/call address. It distinguishes untouched fields from
zero and keeps opaque exceptional paths out of the normal-return theorem.
[ABI.md](ABI.md) qualifies type 3 as P_PIDFD, options 4 as WEXITED, numeric
errors 4/10 as EINTR/ECHILD, and the fallback as the Linux v6.15 64-byte
PIDFD_GET_INFO interface. The binary facts do not establish the deployed ABI
or actual process behavior.

## Evidence scope

| Complete FDE range | Bytes | Instruction rows |
| --- | ---: | ---: |
| `0x671e30..0x671fe4` descriptor helper | 436 | 104 |
| `0x67f160..0x67f290` existing wrapper context | 304 | 84 |
| `0x65f260..0x65f32e` cleanup context | 206 | 68 |
| Total retained scope | 946 | 256 |

The wrapper and cleanup provide dependency context. These are not three new
recovered source functions or 946 bytes of matching reconstructed code. The
full ranges include paths whose behavior remains opaque; only the conditional
contract described above is established. All component gates remain false.

`observed/` preserves complete GNU instruction listings and CIE/FDE records,
five uniquely decoded relocation bindings, the six-entry table and the exact
input/body hashes. The repository's existing FDE parser and GNU readelf agree
on all three ranges. `llvm/` preserves independent Apple LLVM exports: all
256 instruction boundaries and 946 instruction bytes agree with GNU, with no
operand or address masks. This checks decoder partitioning, not semantics.

## Reproduce

The retained environment is macOS arm64, Python 3.14.3, GNU binutils
2.47.20260726, and Apple LLVM 21.0.0. Exact native-text reproduction requires
these provider versions; the paths below may be replaced by equivalent local
installations. Repository setup authenticates the original captures and source
pins. The collector also checks the complete target identity before parsing or
invoking either native reader. Native readers receive a private chmod-0400 copy
named `visor.elf`; the target is never launched.

From the repository root, with GNU binutils first on PATH:

```sh
packet=research/work-items/RE-013-visor-descriptor-wait
python3 -B "$packet/collect.py" --output work/visor-descriptor-new
diff -ru "$packet/observed" work/visor-descriptor-new
python3 -B "$packet/verify.py"
python3 -O -B "$packet/verify.py"
python3 -B "$packet/crosscheck.py" \
  --llvm-objdump /Library/Developer/CommandLineTools/usr/bin/llvm-objdump \
  --output work/visor-descriptor-llvm-new
diff -ru "$packet/llvm" work/visor-descriptor-llvm-new
```

Use new output directories. The verifier regenerates all eight GNU/JSON files
twice and rejects sixteen corruptions or invalid operations: three malformed
captures before native parsing, changed table/callee/frame/branch/instruction
records, missing/raw exports, decoder byte mismatch, decoder gaps, and
overwriting existing output, and three wrong/incomplete LLVM-comparison scopes.
It checks evidence integrity; it is not a target
instruction evaluator or a substitute for reviewing the conditional argument.

`VALIDATION.json` records actual commands and outcomes. Root static checks are
`make doctor`, `make verify`, `make catalogue-check`, and `make reproduce`.
The applicable existing tests are `test_elf_index.py`, `test_fde_extents.py`,
and `test_visor_lifecycle.py`, plus this packet's normal/optimized verifier.

Unrestricted `make test` is omitted because its discovery includes captured-
instruction evaluators, for example `tests/test_kind5_reader.py` calling
`tools/kind5_reader.py`'s Machine. This requires separate execution authority.
The publication commit uses `[skip ci]` to avoid starting that same unrestricted
suite in `.github/workflows/verify.yml`. No full-suite or hosted-CI pass is
claimed. This follows the existing static Visor packets' validation boundary.

## Limits and next question

No captured execution, emulation, live process wait/ioctl, signal, child launch,
target networking or chain action occurred. The proof assumes valid nonaliasing
storage and ordinary imported-call ABI behavior. Kernel availability, returned
optional-field validity, descriptor lifetime, interposition, complete heap/error
formatting and panic/unwind behavior remain unproved. No nominal Rust type,
Rust implementation, rebuilt-byte identity or whole-supervisor claim is made.

New scripts and prose are independently authored under the root MIT terms.
Native exports retain the captured artifact's upstream rights. The task-local
collector uses existing MIT ELF/FDE parsers and the repository's established
non-executable snapshot/export pattern; no general tooling change is proposed.

Next: relate this qualified result contract to the enclosing async lifecycle's
full state transitions, separately establishing which failures return to the
existing outer retry loop and which exceptional paths terminate that flow.
