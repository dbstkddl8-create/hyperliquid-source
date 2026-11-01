# RE-001: node94's complete normal formatter request relation

Component: foundation. Bounded question: what finite writer/value request,
context, descriptor-index and low-AL relation does the complete 448-byte
function at ELF VA `0x1571d90..0x1571f50` establish, when its dynamic callbacks
are supplied normally? The earlier accepted #1216 identifies licensed libcore
code but explicitly leaves this request/input relation open. This packet adds
an independently authored Rust controller for that qualified relation.

Target node94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base main is `3324e50333042b391312515e542279ca21f63dc8`; its seven genuine
reference gitlinks remain pinned. The unlicensed can1357 implementation was
not read or copied. No progress gate, catalogue byte-window or whole-node
identity is changed.

## Independent preparation and native authority

The pre-source proof and declarative oracle are under `oracle/`. An independent
worker froze 1,066 unique cases before this implementation. Expectations consume
high-level literal/value plans; the separate serializer produces raw stream
bytes. The Rust driver receives only the latter and supplied environment
scripts. `formatter448-freeze.json` binds the exact original uncompressed
identities. The three large synthetic files use deterministic gzip solely to
retain their complete bytes compactly. The superseded v1 receipt preserves a
labels-only duplicate-ID correction; no semantic case was changed.

The provisional proof's published-only basis is supplemented, without editing
that frozen proof, by `native/FORMATTER-NATIVE-REVIEW.json` and
`FORMATTER-OFFICIAL-REVIEW.json`: fresh full-target admission, executable
section/PT_LOAD coordinates, actual 52-byte FDE/CIE and caller/GOT/RELATIVE edge,
all 448 raw bytes, 138 GNU rows, 26 local branches, three indirect calls and one
indirect tail. Complete official libcore archive
`ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`
was reauthenticated; its entire named 448-byte function matches raw and has no
source relocation fields. These are static observations, not target execution
or a compiler-origin uniqueness result.

Direct input preserves raw callback low AL; encoded input returns canonical 0/1.
The structural proof covers literal forms, field order/endian widths, both
low16 quantities from the same live paired-row representation, explicit-index
rebasing, cached outer writer and full 24-byte G-context reset. The domain and
excluded raw pointer/frame/control/unwind behaviors are stated in the frozen
proof and the component README. Supplied nested requests are real callbacks,
not an original renderer or private ABI.

## Actual build and checks

Source commit `6c4a39f56885b188d464486582bc59675252176f` was preserved on
the fork before the first experiment. That experiment stopped at an actual
own-rlib reproducibility failure: the runner used `rebuild.rlib`, and rustc
embeds the output basename in archive member names. Its O0 observations and
external tests had passed, but no O3/mutant result existed. Complete raw command
streams and the original differing archive identities remain under
`failures/c1-rebuild-basename/`. An independent ar reader confirms identical
member payloads and different member names. The correction keeps the output
basename fixed in a separate directory; it does not mask or normalize bytes.

Fresh corrected run `build-c2/` at clean, pushed source commit
`63621fb578c1dd717722f2ddb5f6e937b53f469c` completed successfully:

- O0 and O3 each match all 1,066 complete JSON transcripts and final row/method
  states: 1,054 qualified native-domain cases plus 12 chosen safe refusals.
- All three independent external Rust test methods pass under each profile.
  Identical recipes with the same basename produce raw-equal own rlibs under
  each profile. These are own-library rebuilds, not target byte comparisons.
- Four actual compiled semantic mutants change direct status, index rebasing,
  quantity source and cached method behavior. The unchanged comparator rejects
  respectively 254, 66, 98 and 4 transcripts over the same 1,066-case corpus.
- Three Python control methods pass: exact independent oracle regeneration,
  complete comparator field/count corruption and real compressed-input
  corruption. Raw stdout/stderr are retained.

No source-level behavior changed after the independent pre-build review. The
runner's narrow recipe correction resolves this task's observed proof blocker.
The source has no Cargo dependencies, fake workspace or transplanted bytes.

```sh
python3 -B tools/format_request_protocol.py \
  --rustc /path/to/authenticated/1.94.1/bin/rustc \
  --output /tmp/fresh-format-request-build --controls
python3 -B -m unittest tests.test_format_request_protocol -v
```

`provider/PROVIDER-AUDIT.json` binds the official compiler/std archives,
installed manifests and all 103 payloads. The runner checks every payload,
complete target/body, frozen fixtures, own executable sources, actual cc/ld,
HEAD/tree/status and seven pins before/after. All commands and raw stdout/stderr
are retained, with raw streams compressed losslessly. Compiler 1.94.1 is a
research provider, not a recovered original node compiler.

Full current `make test` and hosted CI are NOT_RUN: newly merged captured
instruction-evaluator families have not been authorized. The draft will use
`[skip ci]`. Only reviewed own Rust, pure mathematical references and cleared
static repository checks are executed. Captured node/visor/object execution,
CPU/register/PC evaluators, networking, chain actions and signing remain absent.

New code/docs are MIT; original target evidence retains its separate ownership.
The existing full Rust Project Contributors MIT-option license/notice in
`RE-002-libcore-write-fmt448/fixtures/` is preserved and referenced, not replaced.
No official Rust source was copied. Original rendering, native callback/ABI
implementation, runtime faults/unwind, whole-ELF identity and all full component
gates remain open. Next qualify an actual caller's descriptor production and
dynamic callback identities against this established request controller.
