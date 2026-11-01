# RE-012: gossip RPC client exact-file inventory, node #94

This bounded node-runtime packet inventories Location records whose complete path
ends exactly in `node/src/gossip_rpc_client.rs`. The binary compiler-prefix bytes
are preserved as `method.path_prefix_hex` and each Location's `path_bytes` in
[inventory.json](inventory.json); their decoded bytes match the prefix specified
in the task. This compiler-embedded path is target evidence, not local runtime
state. Node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Source baseline `3324e50333042b391312515e542279ca21f63dc8`; the unlicensed
reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` is used only for
search leads. The producer identifies the reference file by digest. Observations
are byte facts; no inferred reference source or names are adopted. No gate is
requested. Release #115 and visor are separate artifacts.

## Reproduce

From repository root, Python 3.10+ stdlib only, static, offline and without an
external disassembler (validated here with Python 3.13.5 on Linux):

```sh
python3 tools/gossip_rpc_client_inventory.py --out research/work-items/gossip-rpc-client-inventory-94/
python3 -m unittest tests.test_gossip_rpc_client_inventory -v
python3 research/work-items/gossip-rpc-client-inventory-94/verify.py
make verify
```

The producer authenticates the complete binary before parsing. It uses the
existing MIT `node_inventory.py` restricted instruction decoder, ELF section
parser and FDE parser, with their source digests in the output. It scans RELATIVE
relocations for the exact path and scans executable sections for candidate RIP
LEAs. Each candidate must start on a linear instruction boundary from an owning
FDE start, and internal direct branches must land on decoded boundaries. This
is not a full CFG or reachability proof. Bytes, VA, file offsets, relocation
entries, FDE/CIE records and instruction transcript are preserved in JSON.
FDEs are unwind extents, not established function boundaries. End addresses are
exclusive. The exact-path count covers matching Location-layout relocation
records; unusual unrelocated or nonstandard representations are outside it.

## Derived metrics

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

## Location records

<!-- BEGIN GENERATED LOCATIONS -->
| Slot VA | Line:column | LEA sites | FDE starts |
| --- | --- | --- | --- |
| 0x5692cb0 | 65:96 | 0x1fd57d3, 0x1fd57fa | 0x1fd4570 |
| 0x5692cc8 | 67:13 | 0x20394a2, 0x20394af | 0x2039060 |
| 0x569e630 | 19:60 | 0x2261664, 0x22619f1 | 0x22615b0 |
| 0x569e648 | 29:64 | 0x22698c4, 0x22698d6 | 0x22689f0 |
| 0x569e660 | 65:96 | 0x226c196, 0x226c1a3 | 0x226bb20 |
| 0x571cf28 | 47:13 | 0x438a151 | 0x4389070 |
| 0x571cf40 | 39:111 | 0x438a1aa, 0x438a1c8 | 0x4389070 |
| 0x571cf58 | 59:17 | 0x43895ec | 0x4389070 |
| 0x571cf70 | 19:60 | 0x4356dbf, 0x4357067 | 0x4356c90 |
| 0x571cf88 | 65:96 | 0x435d2cb, 0x435d2d8 | 0x435cb20 |
| 0x571cfa0 | 67:13 | 0x4388382, 0x438838f | 0x4387f40 |
| 0x572ecf8 | 19:60 | 0x4759f2a, 0x4759f3c | 0x4759970 |
| 0x572ed10 | 65:96 | 0x4759f7c, 0x4759f8e | 0x4759970 |
| 0x5738568 | 19:60 | 0x4b29c44, 0x4b29c6b | 0x4b29760 |
| 0x5738580 | 65:96 | 0x4b29cbb, 0x4b29cd5 | 0x4b29760 |
<!-- END GENERATED LOCATIONS -->

## Scoped FDE extents

<!-- BEGIN GENERATED FDES -->
| FDE start | End exclusive | Bytes |
| --- | --- | --- |
| 0x1fd4570 | 0x1fd5b28 | 5560 |
| 0x2039060 | 0x203a185 | 4389 |
| 0x22615b0 | 0x22689f0 | 29760 |
| 0x22689f0 | 0x226b503 | 11027 |
| 0x226bb20 | 0x226c2c8 | 1960 |
| 0x4356c90 | 0x435cb15 | 24197 |
| 0x435cb20 | 0x435d432 | 2322 |
| 0x4387f40 | 0x4389065 | 4389 |
| 0x4389070 | 0x438a38c | 4892 |
| 0x4759970 | 0x47604b0 | 27456 |
| 0x4b29760 | 0x4b2fd98 | 26168 |
<!-- END GENERATED FDES -->

See [RESULT.md](RESULT.md) for anchors, call edges, negative findings, limitations
and the next question. No captured node or visor was executed.
