# RE-004: node94 mixed-state divide-by-61 projection in Rust

- Component: foundation, one bounded arithmetic leaf.
- Base: `3324e50333042b391312515e542279ca21f63dc8`.
- Capture: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- FDE: ELF VA `[0x5553fe0, 0x5554037)`, 87 bytes, body SHA-256
  `2d3a7ad0a25a65878c65f27945a74dfc670194c179e682d00381f9de76c17b02`.

## New result and static basis

The existing `foundation-multiply-mix-div61-94` packet binds this function,
its frame/padding, three retained direct calls, division constants and a
64-byte table at VA `0x801180`. It has no compiled Rust implementation.
This packet adds independently authored, unsafe-free `no_std` Rust and an
independently linked client for its numeric state/output/return values.

The fresh admission check authenticates the complete capture and reuses the
existing target-bound structural checker. The table hash is
`d341ee9eb5bcac5295da356e55211983aa3c25c6f9b0c9862d35e156cf0f2ec5`.
The retained calls are `0x555585d`, `0x5556412` and `0x5556f7e`; these are not
a complete indirect-xref census. Full straight-line disassembly is retained
in `preparation/native.objdump.txt`.

With `C=0x5851f42d4c957f2d` and `D=0x14057b7ef767814f`, the value rule is:

```text
updated = (C * old_state + D) mod 2^64
index = updated >> 58
product = (table[index] * sign_extend_i32(field)) mod 2^64
stored = low32(unsigned(product) / 61)
native_return_value = 1
```

The native signed field is read before the updated state is stored. The
subsequent multiplication retains its low 64 bits, but division treats that
product as unsigned. Thus a negative field is not signed division and cannot
be replaced by zero extension. Only the quotient's low 32 bits are stored.
The table's purpose and the callers' larger meaning remain unknown.

The safe Rust function returns `(updated, stored, native_return_value)`. It
does not reproduce pointer layout, physical result registers, overlapping
state/output memory, store order, faults or volatile/concurrent accesses.
No original machine code is transplanted or executed. New code/docs use MIT;
extracted target data and existing evidence retain their upstream terms.
No unlicensed inferred implementation was used to author this Rust code.

RE-001 supplies the bounded static mapping. RE-002 supplies only the research
compiler pin, not the unknown original target compiler. This static work makes
no RE-003 execution claim and requests no complete component gate.

## Expectations before Rust and division reasoning

`contract.py` separately expresses the register-order multiply-high tail and
the whole-integer unsigned division rule. Before Rust existed, it froze their
agreed expectations and source hash in `preparation/ORACLE-FREEZE.json`.
The 3,136 cases include the lower and upper state edges of all 64 table
buckets, signed-field boundaries, values around 61 and a fixed random corpus.
State preimages are constructed with the inverse of the odd multiplier, so
table coverage is deliberate rather than assumed from random sampling.

For `m=0x0c9714fbcda3ac11`, the native tail computes
`h=floor(x*m/2^64)` and `q=(h+floor((x-h)/2)) >> 5` for unsigned `x`.
Since `h<=x` and the sum is at most `x`, neither intermediate wraps. Therefore
`q=floor(x*(2^64+m)/2^70)`. The exact constants satisfy
`61*(2^64+m)=2^70+13`. The positive correction to `x/61` is less than `1/61`
because `13*(2^64-1)<2^70`, so it cannot advance its integer quotient.
The packet checks these integer identities. This is an algebraic argument
for the division tail, not a formal verification of Rust, decoding or compiler.

The full numeric program comparison remains sampled; no all-input Rust or
whole-binary equivalence is claimed. The chronology record is self-reported,
not independent peer review. Qualification authenticates the target again,
checks the frozen source/data hashes and regenerates every case exactly.

## Actual compiled results

Rust 1.94.1 / LLVM 21.1.8, edition 2021, overflow checks enabled. There are no
package dependencies, invented Cargo workspace or dependency lockfile.
Production clients receive only case IDs, state and raw field bits. Expected
answers are confined to separately compiled `cfg(test)` fixtures.

| Actual compiled variant | Cases | Mismatches | Rust fixture exit |
| --- | ---: | ---: | ---: |
| Production O0 | 3,136 | 0 | 0 |
| Production O3 | 3,136 | 0 | 0 |
| Zero-extend field instead of sign extension | 3,136 | 1,231 | 101 |
| Divide by 60 instead of 61 | 3,136 | 2,529 | 101 |
| Shift table index by 59 instead of 58 | 3,136 | 2,738 | 101 |

All linked clients, including mutants, exit normally with status zero.
Result comparison detects wrong semantics, and the independent test builds
also reject each mutant. Emitted LLVM IR must contain the actual production
entry definition. Artifact and source hashes identify the observed builds;
they do not claim original code identity or byte reproducibility across paths.

`observed/RESULT.json` contains the complete counts, compiler identity, source
bindings and IR entry. `observed/RAW-LOGS.json.gz` contains commands, stdin
hashes, streams and exits. Public logs normalize only local path prefixes to
`$WORK`, `$REPO` and `$HOME`; unmodified streams remain in ignored local work.

## Reproduce and limits

Materialize pinned LFS inputs and all seven pinned submodules through the
normal repository setup. Native tools used: Python 3.12.3, GNU objdump 2.42,
Git LFS 3.4.1 and ripgrep 14.1.0.

```sh
python3 tools/mix_div61_rust.py --binary artifacts/node/94/hl-node \
  --rustc /path/to/rustc-1.94.1 --output work/new-div61-run
python3 -m unittest discover -s tests -p test_mix_div61_rust_contract.py -v
make doctor verify catalogue-check
make reproduce
make test
```

Three focused Python checks pass, including a target-table byte corruption
that reaches the structural checker without relying on the complete capture
hash. `make doctor verify catalogue-check` and `make reproduce` pass. Doctor
reports analysis ready and exact rebuild not ready.

**The complete suite was not run on this branch.** The sibling #1310 attempt
started 8 of 907 modules, completed 7 and was interrupted with runner exit130;
it is not a complete-suite pass. The 1,511 common tracked tests/tools files
have equal contents, but that equality establishes no behavior pass for this
branch. `observed/GLOBAL-TEST-STATUS.json` records the exact limitation.
Hosted CI, containers and Ghidra were not run. Unicorn is absent and captured
emulation opt-ins are unset; only new Rust and static analysis execute.

All full-scope component gates remain false. Next: independent review of the
value contract and reconstruction of caller-owned memory/ABI constraints
before considering any wider implementation or comparison claim.
