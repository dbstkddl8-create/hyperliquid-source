# Result: bounded static qualification, node #94 ABCI state

Verdict: **strong for the stated bounded static inventory**, with limited
novelty. The Location census, seeded/unseeded range set, linked-state literal
and loader call sites already exist in prior packets. The contribution is
instruction-boundary and length-bearing qualification, explicit negative
results and the local operand/address evidence below. It is not source
reconstruction, runtime validation or completion of RE-009.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The exact compiler path is confirmed from bytes in each Location's
`path_bytes` record. The shared prefix is the fixed hex `PREFIX` in the
[collector](../../../tools/abci_state_inventory.py), followed by exactly
`l1/src/abci/state.rs`; no analyst home path is captured.

## Derived counts

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| call_edges | 3 |
| constant_operand_anchors | 18 |
| constants_bound | 3 |
| constants_unresolved | 9 |
| counted_fragment_anchors | 12 |
| decoded_instructions | 7052 |
| diagnostics_absent | 3 |
| diagnostics_bound | 4 |
| diagnostics_probed | 10 |
| diagnostics_unresolved | 3 |
| indirect_calls_unresolved | 409 |
| indirect_jumps_unresolved | 4 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 169 |
| location_leas | 38 |
| locations | 28 |
| named_callee_rel32_calls | 3 |
| pointer_length_anchors | 4 |
| scoped_fde_bytes | 37052 |
| scoped_fdes | 20 |
| scoped_rel32_calls | 0 |
| scoped_rel32_jumps | 0 |
| shared_first_party_fdes | 2 |
| source_setup_triplets | 5 |
| unique_line_column | 17 |
| unresolved_external_rel32_calls | 213 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

`locations` counts distinct relocated records; `unique_line_column` counts
source coordinate pairs; `location_leas` counts accepted instruction sites.
`scoped_fdes` counts actual unwind extents that contain those sites, not
recovered functions. `decoded_instructions` and `scoped_fde_bytes` describe
the complete linear transcripts, not matched or reconstructed code.
`call_edges` counts sites, not unique caller/callee pairs.

## Literal observations and non-bindings

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| rmp | bound | 3 | 14 | 4 |
| @@ linked abci state @@ | bound | 23 | 1 | 3 |
| @@ serialized abci state @@ | bound | 27 | 1 | 8 |
| @@ successfully translated abci state | bound | 37 | 1 | 1 |
| exchange | present-but-unbound | 8 | 27 | 0 |
| /dev/null | present-but-unbound | 9 | 2 | 0 |
| assertion failed: freeze_height >= self.locus.context.height() | present-but-unbound | 62 | 5 | 0 |
| reference-line-119 (hash only) | absent | 31 | 0 | 0 |
| reference-line-165 (hash only) | absent | 40 | 0 | 0 |
| reference-line-497 (hash only) | absent | 37 | 0 | 0 |
<!-- END GENERATED LITERALS -->

<!-- BEGIN GENERATED ANCHORS -->
| Candidate | FDE start | LEA VA | Literal VA | Length | Proof |
| --- | --- | --- | --- | --- | --- |
| rmp | 0x2208e60 | 0x2208eeb | 0x3ec204 | 3 | adjacent_pointer_length_fields |
| rmp | 0x32725d0 | 0x32726c1 | 0x59c1e2 | 3 | adjacent_pointer_length_fields |
| rmp | 0x446da60 | 0x446daeb | 0x706a8d | 3 | adjacent_pointer_length_fields |
| rmp | 0x446e050 | 0x446e0db | 0x706a8d | 3 | adjacent_pointer_length_fields |
| @@ linked abci state @@ | 0x2208e60 | 0x22091bb | 0x1ee4c8 | 32 | counted_ascii_chunks |
| @@ linked abci state @@ | 0x446da60 | 0x446ddbb | 0x1ee4c8 | 32 | counted_ascii_chunks |
| @@ linked abci state @@ | 0x446e050 | 0x446e3ab | 0x1ee4c8 | 32 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x2811e40 | 0x28120ce | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x28122a0 | 0x2812591 | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x28127a0 | 0x28129b0 | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x46cea60 | 0x46cee22 | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x46cf030 | 0x46cf2be | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x46cf490 | 0x46cf781 | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x46cf990 | 0x46cfc81 | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ serialized abci state @@ | 0x46cfe90 | 0x46d0252 | 0x1e76cf | 38 | counted_ascii_chunks |
| @@ successfully translated abci state | 0x22ae8a0 | 0x22af155 | 0x202062 | 39 | counted_ascii_chunks |
<!-- END GENERATED ANCHORS -->

The `rmp` anchors have an immediately adjacent pointer store and a decoded
qword length equal to the entire token length. They establish the token's
extent and use in those ranges, not file-extension dispatch semantics.
The other bound candidates use explicit length-counted fragments reached
from a scoped LEA; the translated-state fragment sits in a shared FDE and
therefore has range-level attribution only. Its node behavior is not claimed.

`exchange` occurs but lacks the accepted scoped LEA/length proof. `/dev/null`
is present but unbound under this rule; RE-009's separate inline immediate
comparison evidence remains valid. The freeze assertion occurs elsewhere
in the binary but has no accepted scoped binding. Nearby rodata is not an
ownership argument. The absent hash-only probes are the reference's quoted
strings at the recorded source lines; their exact bytes are not in this
capture. That does not prove that equivalent conditions or behavior are absent.
Every rejected nearby candidate and rejection reason is preserved in JSON.

## Direct edges and prior work

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x22ae8a0 | 0x22aefea | e8b1659601 | 26633649 | 0x3c155a0 |
| 0x3273810 | 0x3273862 | e8391d9a00 | 10100025 | 0x3c155a0 |
| 0x4546ba0 | 0x4546bca | e8d1e96cff | -9639471 | 0x3c155a0 |
<!-- END GENERATED EDGES -->

There are no admitted direct edges between scoped entries. The displayed
calls land at the exact loader entry already named by
[RE-019](../RE-019-rmp-json-loader-94/EVIDENCE.md). Their short preceding
contexts contain decoded state-file Location LEAs. The callee extent/hash
is checked against the same digest and actual FDE records; no new analysis
of its body or implementation is claimed. All other direct transfers are
retained with an unresolved/internal disposition. Indirect calls and jumps
are counted separately, with no new callee resolution.

[RE-017 / #381](../RE-017-abci-state-link-94/EVIDENCE.md)'s GOT link is prior
work and is excluded from the rel32 total. [RE-009 / #23](../RE-009-storage-state-roots/README.md)
already owns the census and storage/root observations. The
[startup freshness packet / #430](../local-abci-gates-94/README.md) shares
`0x22ae8a0`; its claims are neither repeated nor reassigned to state.rs.
[PR #1129's staking packet](../staking-cstaking-state-wire-94/README.md)
covers neighboring wire-form work and has no FDE-entry intersection with
this census. Hashes and explicit intersections are recorded in `prior_work`.

## Numeric operands and layout limits

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric operand established |
| --- | --- | --- |
| EDX operand 0x810 | bound | 2064 |
| EDX operand 0x3ae8 | bound | 15080 |
| EDX operand 0x1fb8 | bound | 8120 |
| candidate response tag | unresolved | none |
| success tag | unresolved | none |
| missing-state tag | unresolved | none |
| mismatch tag | unresolved | none |
| freeze option tag offset | unresolved | none |
| freeze option value offset | unresolved | none |
| height offset | unresolved | none |
| first serialized field offset | unresolved | none |
| second serialized field offset | unresolved | none |
<!-- END GENERATED CONSTANTS -->

“Bound” here applies only to an EDX imm32 in a short decoded setup ending in
CALL, in an FDE whose observed first-party Locations all name this exact file.
It does **not** validate the reference's proposed copy-size meaning, callee
identity, enum tag, offset role, Rust layout or unit. The numeric setups in
shared FDEs are retained as unresolved occurrences and excluded from operand
anchors. The already-published `0x1fb8` setup in RE-017 is overlap, not novelty.

For the `0x810` setups, the contiguous local RSI address preparations give:

<!-- BEGIN GENERATED TRIPLETS -->
| FDE | EDX operand | RSI source displacements |
| --- | --- | --- |
| 0x2208e60 | 0x810 | 0xcb8, 0x15c0, 0x1ec8 |
| 0x2209450 | 0x810 | 0xcb8, 0x15c0, 0x1ec8 |
| 0x446da60 | 0x810 | 0x1738, 0x2040, 0x2948 |
| 0x446e050 | 0x810 | 0xcb8, 0x15c0, 0x1ec8 |
| 0x446e640 | 0x810 | 0xcb8, 0x15c0, 0x1ec8 |
<!-- END GENERATED TRIPLETS -->

The differing displacements in `0x446da60` are a concrete restriction on the
reference lead: a uniform displacement description cannot cover all these
setups. The first address forms are decoded base+displacement LEAs; the final
form adds a displacement to a register and moves that register into RSI.
The records retain the intervening destination-address setup and call-register
load where present. They do not establish the identity of the input object
across functions, what memory gets copied, or which field any offset names.
Other suggested tag/offset roles remain unresolved rather than promoted
from unrelated numeric matches.

## Validation and explicit non-claims

Passed: collector regeneration, the focused unittest suite, packet verifier,
`make doctor`, `make verify`, `make catalogue-check` and `make reproduce`.
Inventory and refined literal classifications reproduce the imported records.
The focused tests and verifier forbid external processes and network access;
the new packet has no native-disassembler dependency.

The broader `make verify test catalogue-check` attempt was interrupted during
`test_gossip_rpc_timeouts_static`. It includes legacy tests such as
[test_bincode_varint_slow.py](../../../tests/test_bincode_varint_slow.py)
that disassemble the entire `.text` section with objdump. Those earlier tests
ran before this conflict with the requested scoped-disassembly rule was
noticed. The remaining run was stopped; the runner reported interruption,
and **no full repository-suite pass is claimed**. Existing tests and tools
were not changed to work around this. Catalogue consistency was then checked
separately and passed. There is no hosted-CI or container-validation claim.

- The collector and its focused checks do not execute or emulate the captured
  executable, use public networking or perform chain actions.
- No runtime behavior, wire/protocol semantics, state-root algorithm or source reconstruction.
- No original source-function names, exclusive source ownership, CFG reachability or full call graph.
- No claims for engine.rs, qtys/*, fees, clearinghouse, margin, node/*,
  spot_meta, spot_clearinghouse or generic foundation helper internals.
- No reconstructed Rust, build scope, lockfile, ABI compatibility, rebuilt
  comparison, source equivalence, milestone update or full-node claim.
- No helper closure, indirect-call/vtable closure, full data or relocation
  equivalence, whole-ELF comparison, #115 parity or visor claim.
- FDE-less code, inlined operations lacking Locations, split bodies, argument
  meaning and all unresolved diagnostic/constant candidates remain gaps.

Next: establish call-target and object provenance for the differing source
triplet, with independent corruption controls, before reconstructing an
operation. See [README.md](README.md) for the method and reproduction commands.
