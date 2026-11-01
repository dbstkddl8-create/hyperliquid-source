# RE-013: Visor shell argument first-NUL admission

The accepted [shell-command packet](https://github.com/lalalune/hyperliquid-source/pull/1266)
established the fixed `/bin/sh`, `-c`, S construction only when S converted
successfully. Its proof explicitly excluded the long scan and interior-NUL
branch. This packet replaces that conversion assumption with a conditional
byte-level result: for stable, valid input of length `0 <= n <= 2^63 - 2`,
the converter finds the **first** zero byte or returns a terminated copy when
none exists, under the stated allocation and copy conditions.

On the same fixed caller path, a zero-containing S causes the argument
appender to store a sticky flag and append `<string-with-nul>` instead. The
constructed command's empty environment fields then select a path through
the spawn routine that returns raw error tag 1 and its bound NUL diagnostic
without invoking a callee inside that routine. The prior `-c` argv-growth
contract remains conditional. This is a local admission/error result, not a
claim that zero-free input successfully spawns or that the shell helper's
eventual error value has been recovered.

## Identity, novelty and scope

- Component/task: separate visor supervisor / RE-013; no acceptance gate.
- Source base: `d3af75257a396c85d20857f421c370ddb8cb40e5`.
- Capture: 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- All addresses are ELF virtual addresses; mappings are uniquely file-backed
  `PT_LOAD` spans. Complete input identity is required before native parsing.
- Converter/finalizer/appender core: **845 bytes / 249 instruction rows** in
  three already-exported FDEs. The new contribution is the missing semantic
  closure, not a new function census or byte-recovery credit.
- Retained native exports total **4,666 bytes / 1,076 rows**: six complete
  FDE bodies and three selected windows (152 bytes) of the 9,849-byte spawn
  FDE. Seven complete FDE/CIE records bind the scope. The full spawn body's
  hash/extent is retained for provenance; its unexported behavior is unproved.
- No dependency on the unmerged descriptor-wait packet. Formatter/prepared
  payload work in [PR #1345](https://github.com/lalalune/hyperliquid-source/pull/1345)
  is separate; its exact output need not be assumed or re-derived here.

| Boundary | Newly qualified statement |
| --- | --- |
| `0x2bf100..0x2bf27a` | Scalar prefix, two-word skipping and scalar tail return the minimum zero index; no in-domain read crosses the input length. |
| Constants at `0x2bf18e`, `0x2bf198` | The base-256 borrow lemma proves the captured mask equality iff both scanned words contain no zero. The mask is not itself an exact zero-position mask. |
| Result stores at `0x2bf226..0x2bf24b` | Success writes raw tag `INT64_MIN`, terminated-copy pointer and length `n+1`; error writes capacity `n+1`, copy pointer, length `n` and first zero index. |
| `0x2bea00..0x2beae1` | The converter's capacity `n+1` selects an append-one-zero path without finalizer grow or shrink. Other finalizer inputs remain unproved. |
| `0x67f290..0x67f382` | Error stores command byte +0xc0 = 1, substitutes 18 bound bytes and does not forward the zero index. Successful conversion leaves the flag unchanged. |
| Fixed constructor and caller | `/bin/sh` and `-c` leave the flag clear; constructor fields +0x70/+0x78 are zero. Subject to the first append's growth contract, S uses spare capacity. |
| `0x66f280`, `0x66f3e3`, `0x6702f2` windows | Those fixed fields bypass environment preparation. A set flag writes error tag 1 and diagnostic descriptor, skips cleanup by equal sentinel and returns without an internal callee invocation. |

[PROOF.md](PROOF.md) supplies the address-bound argument, full input/storage
domain, first-index invariant, raw result layouts and exceptional boundaries.
The actual code is the evidence; upstream source resemblance is not used as
independent validation or proof of original source identity.

## Reproduce the evidence checks

Use GNU `objdump`/`readelf` and LLVM `llvm-objdump`. The retained recipe used
GNU binutils `2.47.20260726`, Apple LLVM `21.0.0` and the Python version in
`VALIDATION.json` on macOS. Set `GNU_OBJDUMP`, `GNU_READELF` and
`LLVM_OBJDUMP` to the installed providers if they are not on PATH. Different
native provider renderings may regenerate different text; they are not an
exact retained-recipe pass.

```sh
packet=research/work-items/RE-013-visor-shell-nul-admission
python3 -B "$packet/survey.py" --binary artifacts/visor/captured/hl-visor --output work/visor-nul-new
diff -ru "$packet/observed" work/visor-nul-new
python3 -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -O -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -B "$packet/crosscheck_llvm.py" --binary artifacts/visor/captured/hl-visor --output work/visor-nul-llvm-new
diff -ru "$packet/llvm" work/visor-nul-llvm-new
python3 -B "$packet/check_algebra.py" --binary artifacts/visor/captured/hl-visor
python3 -O -B "$packet/check_algebra.py" --binary artifacts/visor/captured/hl-visor
```

Use fresh output directories. `survey.py` makes a private, non-executable
authenticated snapshot, retains GNU raw FDE/CIE/instruction records and
binds thirteen unique relocations, two direct calls and seven data windows.
Every selected instruction byte is checked against its mapped input span.
`crosscheck_llvm.py` compares all selected GNU/LLVM instruction byte
partitions, not just printed mnemonics.

Actual local results in `validation/` and [VALIDATION.json](VALIDATION.json):

- Two complete GNU regenerations agree with all 20 retained record files in
  normal and optimized Python modes. Three wrong captures and six corrupted
  retained records are refused; existing output is preserved. The changed
  capture specifically alters the zero-scan subtraction constant.
- GNU/LLVM agree on all 1,076 instruction byte partitions / 4,666 selected
  bytes. Decoder agreement is not a semantic-equivalence result.
- The algebra check binds the two actual immediates, checks 512 finite
  digit transitions and rejects the stated wrong-constant theorem using a
  concrete all-nonzero witness. Normal and optimized receipts are identical.
  It performs integer mathematics, not instruction evaluation or emulation.

Review corrected the initial mutation control's VA/file-offset confusion:
VA `0x2bf198` maps to file offset `0x2be198`. Final receipts record both
coordinates. The earlier identity-only refusal receipts/logs are preserved
as `initial-verify*`, with their limitation recorded in `VALIDATION.json`.

The standalone exporter/checking scripts adapt the repository's MIT
#1266 packet pattern, with this packet's scope and records; tooling novelty
is not claimed. No inferred unlicensed source was read or copied. New prose
and code use the repository MIT terms; captured native records retain their
upstream rights. The scripts import only this packet's `survey.py` and the
Python standard library, so no unmerged packet is a dependency.

## Limits

No captured process, emulator, captured-instruction evaluator, real shell
command, child process backend, target network or broad `make test` runs.
No hosted CI pass, Rust reconstruction, security finding, component gate or
global supervision policy is claimed. The private snapshot is data for native
decoders, never a program to invoke.

Allocation and ordinary `memcpy` behavior, nonaliasing/stability, prior argv
growth and normal opaque cleanup return remain explicit premises. Input
overflow, allocation failures, unwind, arbitrary environment mutation, exact
prepared S production and behavior beyond the zero-free admission edge are
unclosed. The stronger local NUL-error conclusion does not imply that earlier
preparation or later error formatting has no effects.
