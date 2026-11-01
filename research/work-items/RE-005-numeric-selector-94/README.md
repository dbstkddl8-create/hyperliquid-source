# RE-005: node94 unsigned numeric selector request

- Component: foundation/serialization diagnostic numeric primitive.
- Target: node94, 91,774,280 bytes, SHA256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `3324e50333042b391312515e542279ca21f63dc8`, tree
  `39b14bf47f373aea75ac42f4ce6a030db1040dba`; seven original imports remain pinned.
- Primary: complete ELF VA `0x14f7660..0x14f774b`, 235 bytes/63 native rows,
  body SHA256 `a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf`.
- Real unchanged Rust dependency: `src/node94-integer-digit-span/lib.rs`,
  SHA256 `51fbf04c59f82f4654bfcd9d1946e5a9792f13079a339dc0e675c1fd86472d83`,
  accepted PR1128's capacity20 decimal theorem over the separate complete
  444-byte/114-row body `0x1570470..0x157062c`.

The bounded question is whether independently authored Rust can reproduce the
selector's unsigned scalar spelling, B-relative digit interval and one opaque
sink request/normal-return low byte, while genuinely building and linking the
accepted decimal component. This is new implementation of an established
native relation. The base has no `src/node94-numeric-selector` implementation;
there is no claim of a pre-existing production defect.

## Observations, inference and chosen interface

Accepted PR1128 contains every raw native row for both bodies, FDE/CIE bounds,
descriptor and sink RELATIVE relocations, decimal pair table and both hex tables.
Fresh independent native replay in this session reauthenticated the complete
target and selected exact body/data/relocation records. The new runner repeats
the accepted static admission against one immutable full target bytes object.
These are static parses and bounded GNU disassembly, without captured execution
or instruction evaluation. The accepted producer's old
`Rust_hex_or_flags_implementation: false` field describes its original decimal
packet scope; it does not evaluate the new source here.

The low DWORD's bit25 selects lower hex before bit26 can select upper hex;
both clear selects decimal. With B=post-prologue SP+4, hex stores and digits end
at B+16, while decimal ends at B+20. Zero has one digit. Both hex arms forward
the literal lowercase `0x`; decimal forwards raw pointer word1 and length0.
The sink receives raw sign1 and the original context exactly once. The observed
normal-return epilogue preserves the sink's lowAL without normalization.

The selected safe API takes initialized B[20], a separate u64 flags snapshot,
the input u64 and a borrowed generic context with one supplied `FnOnce` sink.
An empty safe slice projects the decimal zero-length prefix. Start/end are
chosen observation metadata; native passes a digit pointer/length. All20 output
bytes are compared so untouched prefix and hex's final4 bytes remain observable.
The mathematical scalar/request proof is `independent-pre-source/PROOF.md`.

## Independent chronology and denominator

The former uncommitted implementation/corpus were lost. They were not recovered
and none of their validation is reused as current. The fresh peer sealed
`independent-pre-source/FREEZE.json` at 2026-11-01T16:02:20.318812+00:00 before
this new Rust was authored. Seal SHA256:
`c43062c57d80907c3710ac18788f43c33359218a230ed6dd877163fef2ab994c`.
At that time target restoration was still pending, which the original seal
honestly records; later native revalidation is separate evidence.

The fresh denominator is 8,892 distinct complete input tuples, excluding IDs,
and 722 distinct u64 values across the full corpus. This was independently
measured from the immutable input TSV, not inferred from a base-value list.
There are 2,888 numeric boundary/sample rows; 5,120 rows cover all256 statuses
for five values and four selector combinations; 744 probes toggle each of62
other u64 flag bits relative to12 retained baselines; 128 marker cases check
untouched storage. High32 source flags are a convenience beyond native DWORD.

The independent oracle uses Python integer `str`/`format` and the proved scalar
endpoints. It imports no repository module, reads no new Rust, and performs no
PC/register/opcode execution. Production receives only `inputs.tsv` and emits
raw observations. Expected TSV SHA256 is
`23927ea2bddffcb7a29e75e7aef91ad94e949654519273dab5e1d167b602a9aa`;
input SHA256 is `fe077a7eb6d40ac36ee5b1f3c46dcf0941c5e766fddbfb66403f9ca39ce77b12`.
To regenerate corpus bytes, copy `freeze.py` to a new temporary directory and
run it there; preserve the original timestamped seal and proof unchanged.

## Build and comparison

Source: `src/node94-numeric-selector/{lib.rs,input_only_driver.rs}`. Direct
rustc builds use no registry, fake Cargo workspace, lockfile or substitute
dependency. `tools/numeric_selector_rust.py` addresses the concrete validation
gap: the existing decimal-only runner cannot build/link this selector, expose
one opaque callback, or compare its full numeric request transcript. This is
a task-specific runner accompanying the implementation, not a tooling claim.

The intended replay command, from this repository, is:

```sh
python3 -B tools/numeric_selector_rust.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json \
  --output work/numeric-selector-first --controls
```

The official research Rust1.94.1 provider is a research choice, not recovered
target compiler provenance. Its admitted audit is
`56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6`.
The runner verifies all103 actual payload files and full actual tracked inputs,
seven genuine pinned repositories, source/corpus, head/tree/status, resolved GCC
driver and ld.bfd before and after. Exact commands and raw stdout/stderr are
retained. The chosen linker is explicit GCC with `-fuse-ld=bfd`.

The initial source was preserved in `[skip ci]` commit `3f03355e` before the
first new compiler run. Its first ordinary fork push stopped on an unrelated
historical LFS traversal. Root verified zero new LFS pointer blobs and preserved
this exact source ref using `GIT_LFS_SKIP_PUSH=1`; no security/review hook was
bypassed. The public source/corpus commit exists on the contributor's fork.

The actual run on that source passed **68 commands / 136 exact stdout/stderr
streams**. Debug and optimized profiles each passed the real decimal component's
one unit covering its1697 vectors, plus two real selector units: all8892 frozen
request vectors and same-object context identity/mutation. Separately linked
input-only clients in both profiles emitted exactly8892 expected rows, SHA256
`23927ea2bddffcb7a29e75e7aef91ad94e949654519273dab5e1d167b602a9aa`.

The optimized build and one additional optimized build produced raw-identical
6630-byte decimal libraries, 12114-byte selector libraries and 3956928-byte
clients, without normalization. This is reproducibility of our own research
builds; it is not target machine-byte equality. All9466 actual tracked/owned
physical files, seven genuine pins, all103 provider payloads, resolved GCC and
ld.bfd, source head/tree and clean status remained unchanged before/after.
The identical original audit byte streams are represented once by
`PHYSICAL-INPUT-AUDIT.json`; `AUDIT-IDENTITY.json` records both original identities.

Each of nine semantic mutants compiled, emitted a normal full8892-row client
transcript with exit0, differed from the independently frozen expectations, and
failed a real Rust unit assertion with exit101:

| Mutant relation | Different rows /8892 |
| --- | ---: |
| Both flags incorrectly choose upper | 1357 |
| Upper arm uses lower alphabet | 1357 |
| Empty hex prefix | 6669 |
| Hex digit slice incorrectly ends at20 | 6669 |
| Zero hex becomes empty | 972 |
| Raw sign incorrectly0 | 8892 |
| Boolean-normalized sink result | 8829 |
| Bit0 skips the callback | 12 |
| Decimal helper receives value/10 | 1899 |

All six comparator controls passed: missing, reordered and duplicated rows
rejected; independent status, digit and scratch byte corruptions each produced
exactly the intended one-row mismatch. Mutant sources and actual output identities
are retained. Repeated profiles and controls add no new unique-corpus coverage.

`RUST-RESULT.json` is the unchanged actual result, SHA256
`cd5ffe61bfb451d694d7276c0a17da5a57d2282ced123978e6970150e1e5579c`.
`RAW-STREAMS.json` losslessly retains all136 original command streams and the
original `CALLS.json`: 137 files,31 unique contents,10,731,101 original bytes.
Repeated positive outputs refer to the exact immutable public expectation file;
other unique bytes are base64 encoded. Nothing is normalized. Verify every
original size/hash and exact decode using:

```sh
python3 -B research/work-items/RE-005-numeric-selector-94/retain_raw_streams.py --verify
```

`native-peer/` retains the independent GNU raw listings, parser and original
native receipt. That shared receipt also has reader-context records; those are
excluded from this selector's235-byte/63-row primary scope and denominator.
The new component does not close a combined679-byte formatter or opaque sink.

Full current `make test` is **NOT RUN**: its expanded captured-instruction
evaluator families remain outside the user's authorization. Static repository
checks and relevant owned source executions are separately scoped. Hosted CI,
container success and native captured execution are not claimed.

## Limits and next question

No full `G`, rendering/padding/fill, sink implementation, hidden register
effects, original type/layout/ABI/compiler/machine-byte identity, invalid
pointers, raw aliasing, faults/unwind or concurrent mutation is qualified.
The input-only protocol constrains data flow; it is not a filesystem sandbox.
Every component gate remains false and no compiled-byte window is registered.
The next separate question is the opaque sink's actual formatting contract.
