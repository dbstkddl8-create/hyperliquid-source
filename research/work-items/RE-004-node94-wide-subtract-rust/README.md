# Node94 four-word subtract: independently authored Rust numeric projection

This advances the existing static-only foundation packet from merged PR #1037
to a compiled, independently authored safe Rust value implementation. It does
not re-claim the earlier mapping, add a compared-byte denominator, or advance a
component completion gate. No `COMPONENTS` entries or existing gates change.

## Admitted capture and semantic boundary

The complete pinned node94 capture is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The 81-byte leaf at ELF VA `0x32d8310..0x32d8361` has body SHA-256
`877ae8e82fbe663ff6986a1276c3c4efef2adc4075e32449220c0a8a0b10bcac`.
The existing foundation verifier freshly admits the complete digest, exact body,
CIE/FDE records, adjacent FDE/padding, and direct callers `0x32994ed` and
`0x3299579`. There are no relocation slots naming this leaf.
The freshly retained [bounded objdump](preparation/native.objdump.txt) gives
the exact instruction order, rather than extrapolating from an address label.

The low three words use SUB followed by SBB. MOV and SETB preserve flags.
Before the top-word SUB, SETB CL saves the incoming borrow. SETB DL then saves
the top SUB borrow after the final RDX-based operand read. ADD CL,FF restores
CF exactly when the incoming borrow was one; SBB RAX,0 subtracts that bit.
The two top borrows are ORed and masked to one bit. The resulting numeric
projection is unsigned 256-bit wrapping subtraction plus an underflow flag.

This claim is conditional on valid, noninterfering input/output memory in the
captured routine. The original rewrites the left operand and unconditionally
copies its difference to the output, then writes the borrow byte. The new safe
value API deliberately excludes that pointer ABI, left mutation, copy order,
partial aliasing, fault behavior, physical RAX return, register clobbers and
caller meaning. It does not establish captured dynamic equivalence, reconstruct
the surrounding component, or identify the original source/compiler.

## Frozen oracle, independent review and compiled controls

[contract.py](contract.py) was frozen before Rust authoring. Its instruction
equations are separate from the whole-Python-u256 subtraction used for expected
fixture values. [ORACLE-FREEZE.json](preparation/ORACLE-FREEZE.json) binds the
contract hash, target facts and 1,352 synthetic cases. Fixture SHA-256 is
`fbf9fe22ae97979f5585e9e42ff8239d57ae0767cc8fb16ff2a55a6251ab5dda`.
An independent context reviewed the locked instruction semantics and contract
before authoring; the [review record](preparation/PRE-RUST-REVIEW.json) records
that ordering. Corpus generation includes whole-word edges, equal operands,
long borrow chains and deterministic synthetic full-width values. The seed is
only fixture generation, not a benchmark or evaluation claim.

Z3 4.15.4 reports UNSAT for any disagreement between the admitted instruction
equations and whole-u256 subtraction across all 512 input bits. Replacing the
top borrow OR by AND or dropping the incoming top borrow yields SAT, with
counterexamples retained. This is a proof of the stated equations, not execution
or formal verification of an x86 decoder, ABI or compiler.

The [qualifier](../../../tools/wide_subtract_rust.py) authenticates the target
again, checks the frozen oracle and freshly regenerates the cases before each
qualification. Pinned Rust 1.94.1 compiles the own `no_std`, unsafe-forbidden
library and a separately linked client at O0 and O3 with overflow checks enabled.
The client receives case identifiers and eight inputs, never expected outputs.
The qualifier checks that emitted LLVM IR contains the own function body.

| Actual compiled variant | Cases | Mismatches | Rust test exit |
|---|---:|---:|---:|
| Production O0 | 1,352 | 0 | 0 |
| Production O3 | 1,352 | 0 | 0 |
| Drop incoming borrow | 1,352 | 930 | 101 |
| Borrow AND instead of OR | 1,352 | 997 | 101 |
| Invert returned borrow | 1,352 | 1,352 | 101 |

All linked clients, including mutants, return normally with exit zero; semantic
comparison detects the mutants. The independently compiled fixture tests also
reject them. Exact commands, stdin hashes, stdout/stderr and exits are retained
in [RAW-LOGS.json.gz](observed/RAW-LOGS.json.gz), with source/compiler/artifact
hashes and fresh proof results in [RESULT.json](observed/RESULT.json). Artifact
hashes bind that run; they are not a cross-path reproducible-build claim.

## Reproduce and limits

Install optional `z3-solver==4.15.4.0` in a Python research environment. The Rust
component has no registry dependencies. Use a fresh result directory.

```sh
python3 tools/wide_subtract_rust.py --binary artifacts/node/94/hl-node \
  --rustc /path/to/verified/rustc-1.94.1 --output work/new-wide-subtract-run
python3 -m unittest discover -s tests -p test_wide_subtract_rust_contract.py -v
make doctor verify test catalogue-check
make reproduce
```

The four focused Python controls pass with pinned Z3. `make doctor verify
catalogue-check` and `make reproduce` pass on the fully materialized pinned
inputs and seven ordinary pinned submodule checkouts. The first setup attempt
refused a still-unmaterialized `visor.dis.txt` LFS pointer; after materializing
the existing pinned file, the unmodified verifier admitted its hash. That was a
setup failure, not a product fix or a weakened verifier.

The complete 902-module suite was **not run on this branch**. A separate run
on the sibling limb-fold branch exercises the same 901 pre-existing flat test
modules; the [source-equivalence record](observed/COMMON-TEST-SOURCES.json)
records byte equality for all 1,501 tracked tests/tools files. This accounting
does not claim a complete-suite pass: the sibling run was interrupted at the
user's choice after 74 modules started and 73 completed, with runner exit 130.
This branch received no independent complete-suite run.

Public command logs normalize only personal output-directory, repository and
home prefixes to `$WORK`, `$REPO` and `$HOME`; numeric outputs, exits and other
fields are unchanged. Original private streams are retained only in ignored
local storage. The qualifier writes both its private local stream and the
path-normalized public copy; no private stream file is part of this packet.
Optional captured-emulation packages and opt-ins remain
absent/unset; only our new Rust and symbolic/static analysis execute. The target
is always read as data, never launched, transplanted or emulated. New source and
docs use MIT; target/disassembly retain upstream ownership. No can1357
implementation was copied. Every full component gate remains false.
