# RE-013: Visor formatter requests and repeated path argument

The accepted [shell-command packet](https://github.com/lalalune/hyperliquid-source/pull/1266) left its formatted operand `S` opaque. This packet follows the actual allocation formatter, compact-data driver, two callbacks and string sink for that same captured visor. On the selected successful path, the driver issues the default requests

```text
"(" , command[0] , ") > " , prepared[1] , " 2>&1 && rm " , prepared[1]
```

The last operand is an explicit reuse of argument **1**, rather than a third argument. Both callbacks select the unchanged-byte string path with options `0x60000020`, zero width and zero precision. Subject to the storage conditions in [PROOF.md](PROOF.md), their concatenation is

```text
(C) > T 2>&1 && rm T
```

Here `C` is the command object's byte payload and `T` is the prepared object's payload after the opaque preparation calls. For the fixed termination caller, `C` is the sixteen admitted bytes `pkill run-client` and option byte 0 selects this default stream. This is a **conditional byte-construction statement**, not a claim that the shell command ran, that its effects succeeded, or that the temporary filename is recovered. The internal allocation/reallocation callees are not treated as imported libc functions or proved storage-preserving.

## Identity and bounded scope

- Task/component: RE-013 / separate visor supervisor; static research, no acceptance gate requested.
- Analysis base: `3324e50333042b391312515e542279ca21f63dc8`; final submission qualification: `d3af75257a396c85d20857f421c370ddb8cb40e5`.
- Captured visor: 8,305,392 bytes, SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Addresses are ELF virtual addresses, resolved through unique file-backed `PT_LOAD` mappings; no inferred source was copied.
- The caller/helper FDEs are retained context from #1266, not newly recovered function credit. Eight further FDEs cover the formatter/sink chain. The ten selected FDEs total **6,488 bytes / 1,583 instruction rows**, including that retained caller/helper context. These are export denominators, not new recovered-function credit or whole-component coverage.

## What the bytes establish

| Boundary | Observation |
| --- | --- |
| `0x7e4c20 -> 0x2bebb0` | The allocation formatter preserves its stream and argument-array words, prepares `(capacity,pointer,length)` storage, and calls `0x7e4c28 -> 0x49a480` with writer data `0x7a8840`. A nonzero format result goes to an opaque error path. |
| Driver `0x49a480` | A positive byte emits that many following literal bytes. `0xc0` selects the next argument. `0xc8` reads a little-endian explicit argument index; after successful callback return, the next index becomes selected index + 1. The admitted streams use only these cases and a zero terminator. |
| Default data `0x7a9a8` | Literal lengths 1, 4 and 12 interleave argument indices 0, 1, 1. The final `0xc8 01 00` reuses index 1. |
| Quiet data `0x6bf04` | Requests `"("`, command argument 0 and `") > /dev/null 2>&1"`. This is the helper's nonzero-option branch; the fixed termination caller supplies zero and does not select it. |
| Temporary data `0x688d6` | Requests `"shell_rs_out/"` followed by a callback payload. Opaque `0x3a1780` subsequently constructs the prepared object. This does not prove that its later payload `T` equals the raw temporary-format output. |
| Callbacks `0x3d8230`, `0x3d7320` | The command callback dereferences the supplied object pointer; the prepared callback uses its supplied object directly. Both load payload pointer/length at object offsets +8/+16 and tail-jump through `0x7e4c50 -> 0x499ae0`. |
| Handler `0x499ae0` | The admitted default options have mask `0x18000000` clear. The selected edge sends the original pointer/length directly to the writer at vtable offset +24. Character counting, width padding and precision truncation are on other paths. |
| Writer `0x7a8858 -> 0x2bf090` | With enough spare capacity it copies the supplied bytes through uniquely imported `memcpy`, appends at the old length and increases length. On insufficient capacity it first calls `0x2bd9a0 -> 0x2be970`; prefix preservation across its internal allocator call remains an explicit condition. |

The [manual static argument](PROOF.md) separates the ordered sink requests from the stronger conditional constructed-string conclusion. It also describes the early preparation return, callback error exits and unresolved domains.

## Reproduce

With GNU binutils 2.42 and LLVM 18.1.3, from the repository root:

```sh
packet=research/work-items/RE-013-visor-format-requests
python3 -B "$packet/survey.py" --binary artifacts/visor/captured/hl-visor --output work/visor-format-new
diff -ru "$packet/observed" work/visor-format-new
python3 -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -O -B "$packet/verify.py" --binary artifacts/visor/captured/hl-visor
python3 -B "$packet/crosscheck_llvm.py" --binary artifacts/visor/captured/hl-visor --output work/visor-format-llvm-new
diff -ru "$packet/llvm" work/visor-format-llvm-new
```

Use new output paths. These programs authenticate the full capture before native parsing, retain complete GNU FDE/CIE/instruction records, bind data/relocations and compare every selected GNU/LLVM instruction byte partition. The small format-data parser emits symbolic literal/argument records for the three admitted streams; it does not interpret x86 instructions or invoke a target callback. The mapping from target instructions to these data events is the manual argument, not a semantic proof supplied by decoder agreement.

`verify.py` performs two complete native regenerations, rejects three wrong captures, refuses seven corrupted retained records and preserves an existing output directory. Normal and optimized Python runs must produce the same receipt. These are evidence-integrity controls, not proof of runtime behavior. Source/command hashes and actual outcomes are recorded in `VALIDATION.json` and `validation/`.

The native-export/checking pattern adapts this author's MIT scripts from #1266; tooling novelty is not claimed. GNU/LLVM outputs retain the captured artifact's upstream rights. New authored code/prose uses the repository's MIT terms.

## Limits

No captured execution, machine-instruction evaluator, emulation, real shell/child command, target networking, Rust implementation or component-gate change. Root tooling success and native decoder agreement do not prove target equivalence. The allocator implementation at `0x710ea0`, initial allocator at `0x70bf30`, preparation helpers, temporary payload, readback/deletion behavior, spawn consumer, error/unwind and global process policy remain unclosed. The previous packet's argv-conversion/growth conditions remain separate.

The next question is the preparation object's payload and lifetime, including whether and under what conditions it equals the earlier temporary-format output. Do not infer filesystem behavior or command success from the recovered template.
