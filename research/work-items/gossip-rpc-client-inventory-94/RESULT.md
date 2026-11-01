# Results: exact-file gossip RPC client slice

## Verdict and observations

The bounded inventory is strong as a static cross-reference packet: exact-path
records, decoded instructions, length-bearing anchors and direct rel32 edges
are reproducible. Semantic attribution is thin: some Location-bearing unwind
ranges span tens of kilobytes and overlap code associated with other files, so
co-location alone does not establish which source function owns a literal or
edge. No exclusive file ownership or runtime use is inferred. The findings are
not a recovered client or a complete module map.

<!-- BEGIN GENERATED METRICS -->
| Measure | Count |
| --- | --- |
| constants_bound | 0 |
| constants_unresolved | 9 |
| counted_fragment_anchors | 16 |
| decoded_instructions | 24224 |
| diagnostics_absent | 1 |
| diagnostics_bound | 10 |
| diagnostics_probed | 11 |
| diagnostics_unresolved | 0 |
| indirect_calls_unresolved | 1419 |
| indirect_jumps_unresolved | 98 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 1212 |
| location_leas | 28 |
| locations | 15 |
| pointer_length_anchors | 9 |
| scoped_fde_bytes | 142120 |
| scoped_fdes | 11 |
| scoped_rel32_calls | 10 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 7 |
| unresolved_external_rel32_calls | 719 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

The request-related FDEs at `0x2039060` and `0x4387f40` each have a
Location reference and an adjacent pointer/length setup for the same binary
diagnostic. The `0x1fd4570` extent has Location references and additional
adjacent pointer/length setups. Their decoded lengths appear in the table below. The Location LEA and literal LEA can
be far apart within the same FDE; the bytes establish co-location and a length,
not dataflow between the Location and literal. Other anchors use bounded
u8-counted ASCII chunks ending in `c0`; they do not prove a formatter grammar,
rendered message, arguments, execution or control-flow relationship. Literal
binding means a scoped instruction references the encoded bytes under this
specific rule, not that this file exclusively owns the bytes. Probe membership
is finite, not a comprehensive string census.

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Occurrences | Anchors |
| --- | --- | --- | --- |
| rpc connect | bound | 1 | 2 |
| gossip response | bound | 1 | 2 |
| request err: | bound | 1 | 9 |
| querying client blocks | bound | 1 | 1 |
| send gossip rpc request | bound | 2 | 2 |
| gossip_rpc_request | bound | 7 | 5 |
| verify_rpc | bound | 1 | 1 |
| verified gossip rpc | bound | 1 | 1 |
| starting bootstrap | bound | 1 | 1 |
| finished bootstrap | bound | 1 | 1 |
| bootstrap log lead (text withheld; see hash) | absent | 0 | 0 |
<!-- END GENERATED LITERALS -->

The absent candidate is a reference search lead identified by its SHA-256
in JSON; its unlicensed text is withheld. Absence means its exact byte sequence
was not found anywhere in this ELF, not that equivalent wording is absent.

<!-- BEGIN GENERATED ANCHORS -->
| Candidate | FDE | LEA | Binding | Length |
| --- | --- | --- | --- | --- |
| rpc connect | 0x2039060 | 0x2039253 | counted_ascii_chunks | 12 |
| rpc connect | 0x4387f40 | 0x4388133 | counted_ascii_chunks | 12 |
| gossip response | 0x2039060 | 0x2039b45 | counted_ascii_chunks | 16 |
| gossip response | 0x4387f40 | 0x4388a25 | counted_ascii_chunks | 16 |
| request err: | 0x1fd4570 | 0x1fd4d1d | counted_ascii_chunks | 13 |
| request err: | 0x2039060 | 0x2039a65 | counted_ascii_chunks | 13 |
| request err: | 0x2039060 | 0x2039e86 | counted_ascii_chunks | 13 |
| request err: | 0x226bb20 | 0x226c0af | counted_ascii_chunks | 13 |
| request err: | 0x435cb20 | 0x435d1cc | counted_ascii_chunks | 13 |
| request err: | 0x4387f40 | 0x4388945 | counted_ascii_chunks | 13 |
| request err: | 0x4387f40 | 0x4388d66 | counted_ascii_chunks | 13 |
| request err: | 0x4759970 | 0x475ea06 | counted_ascii_chunks | 13 |
| request err: | 0x4b29760 | 0x4b2d648 | counted_ascii_chunks | 13 |
| querying client blocks | 0x4389070 | 0x438943a | counted_ascii_chunks | 28 |
| send gossip rpc request | 0x2039060 | 0x203995c | adjacent_pointer_length_fields | 23 |
| send gossip rpc request | 0x4387f40 | 0x438883c | adjacent_pointer_length_fields | 23 |
| gossip_rpc_request | 0x1fd4570 | 0x1fd4656 | adjacent_pointer_length_fields | 18 |
| gossip_rpc_request | 0x226bb20 | 0x226bb82 | adjacent_pointer_length_fields | 18 |
| gossip_rpc_request | 0x435cb20 | 0x435cb73 | adjacent_pointer_length_fields | 18 |
| gossip_rpc_request | 0x4759970 | 0x475e4e4 | adjacent_pointer_length_fields | 18 |
| gossip_rpc_request | 0x4b29760 | 0x4b2d0f9 | adjacent_pointer_length_fields | 18 |
| verify_rpc | 0x1fd4570 | 0x1fd4eff | adjacent_pointer_length_fields | 10 |
| verified gossip rpc | 0x1fd4570 | 0x1fd5641 | adjacent_pointer_length_fields | 19 |
| starting bootstrap | 0x4389070 | 0x438924b | counted_ascii_chunks | 40 |
| finished bootstrap | 0x4389070 | 0x4389d37 | counted_ascii_chunks | 40 |
<!-- END GENERATED ANCHORS -->

## Direct calls

Each edge is an E8 rel32 whose signed displacement resolves from the following
instruction to another Location-bearing FDE entry; the raw bytes, caller,
callee, next address and displacement are in JSON. These are static instruction
edges, not proof of reachability or a complete call graph.

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Bytes | Callee FDE |
| --- | --- | --- | --- |
| 0x1fd4570 | 0x1fd49d6 | e885460600 | 0x2039060 |
| 0x22615b0 | 0x22663c9 | e852570000 | 0x226bb20 |
| 0x22689f0 | 0x2269e87 | e8941c0000 | 0x226bb20 |
| 0x226bb20 | 0x226be20 | e83bd2dcff | 0x2039060 |
| 0x4356c90 | 0x435a51b | e800260000 | 0x435cb20 |
| 0x435cb20 | 0x435cf42 | e8f9af0200 | 0x4387f40 |
| 0x4389070 | 0x43894ea | e83136fdff | 0x435cb20 |
| 0x4759970 | 0x475aebd | e8aee1c2ff | 0x4389070 |
| 0x4759970 | 0x475e781 | e8ba97c2ff | 0x4387f40 |
| 0x4b29760 | 0x4b2d3a5 | e896ab85ff | 0x4387f40 |
<!-- END GENERATED EDGES -->

## Constants and reference comparison

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status |
| --- | --- |
| request timeout | unresolved |
| verification timeout | unresolved |
| connect timeout | unresolved |
| bootstrap block limit | unresolved |
| response wait threshold | unresolved |
| status retry delay | unresolved |
| peer retry delay | unresolved |
| per-block retry delay | unresolved |
| retry delay cap | unresolved |
<!-- END GENERATED CONSTANTS -->

All listed lead roles remain unresolved in this exact-file slice. The separate
[gossip RPC timeout packet](../gossip-rpc-timeouts-94/README.md) records byte observations at selected sites and explains why its
connect-timeout lead is unsupported in the examined request futures. This packet does not upgrade those observations to unique file-specific
constant roles, or claim the absence of a timeout in callees. A lead for a
bootstrap-log phrase has no exact byte occurrence, as listed above; that is a
literal mismatch, not evidence that a corresponding operation does not exist.

## Limits and next question

No runtime behavior, protocol semantics, source reconstruction, helper closure,
indirect-call targets, full relocation/data/vtable closure, rebuilt code or
whole-ELF comparison is claimed. No claim extends to `gossip_rpc.rs`,
`gossip_config.rs`, `net_utils/*`, `consensus/*`, `startup.rs`, `node.rs`,
`abci/state.rs`, generic foundation helpers, node #115 or visor. Normalization
masks: none. Imported reference material remains unlicensed and is not copied
into implementation. No progress gate changes.

The next useful question is whether a bounded CFG and register/dataflow slice
can connect a specific Location site to one of the length-bearing diagnostics
or a direct callee, with the same digest and corruption controls. This would
reduce the co-location ambiguity without treating shared FDE extents as source
function boundaries.
