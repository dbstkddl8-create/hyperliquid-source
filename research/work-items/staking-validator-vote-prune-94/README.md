# staking: validator vote expiry, cursor removal and tree repair in node #94

This packet identifies the separate validator-vote expiry sweep and its removal path, allowing a reconstruction to retain rows at their exact expiry, delete completed rows only after expiry, give unfinished rows an inclusive extra-day deadline, and resume traversal correctly after leaf or internal-node deletion.

- Component ID: staking, validator lifecycle; follow-up to `staking-validator-l1-vote-94`.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `3324e50333042b391313215e542279ca21f63dc8` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference was a search lead only; no reference implementation is copied.
- Claim status: observation for saved bytes, FDE records, operands and transfers; inference for descriptive function/field names and the path interpretation below; unresolved for excluded callees and dynamic tree/unwind behavior.
- Scope included and excluded: nine complete FDE windows for the expiry host, cursor removal, leaf repair, both borrow directions, action/value drops and the bucket-map consumer. Three incoming call windows establish linkage only; their enclosing callers are not claimed. Calendar arithmetic, recursive nested-value drops, the already studied shared node consumer, allocator, metrics and runtime unwinding are dependencies, not recovered bodies. Stake accounting and epoch transitions, including #115, remain outside this packet.

## Reproduce

From the repository root, with Python 3.12.3 and the authenticated node artifact:

```sh
python3 tools/staking_validator_vote_prune94.py --out research/work-items/staking-validator-vote-prune-94
python3 -m unittest tests.test_staking_validator_vote_prune94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For independent output directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_validator_vote_prune94.py --out <tmp-dir>/one
PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/staking_validator_vote_prune94.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The tool authenticates SHA-256 before parsing or writing. It imports the repository ELF section and CIE/FDE parsers, excludes SHT_NOBITS from file mappings, and directly reads relocation, symbol and jump-table records. A restricted opcode-pattern decoder records instruction lengths and transfers across each selected FDE; unsupported encodings and branch targets inside operands fail. It does not invoke external programs, require binutils or execute captured code. Its only writes are the requested output files. Hash seed and timezone do not enter evidence.

Generated files are `evidence.json`, `windows.json`, `witnesses.tsv`, `transfers.tsv`, `instructions.tsv`, `control-flow.tsv`, `incoming-xrefs.tsv`, `jump-tables.tsv`, `drop-table.tsv`, `failures.tsv`, `decisions.json`, `carry-cases.tsv`, `repair-choices.tsv`, `mutation-controls.tsv` and `leaf-projections.tsv`. `MANIFEST.sha256` covers these and this README. Raw FDE-window bytes and per-window SHA-256 values are retained; there is no normalization mask.

## Evidence

All addresses below are linked ELF virtual addresses. `evidence.json` records file offsets, FDE/CIE addresses, ends and LSDA pointers. A section membership check alone is not used as a function boundary. `windows.json` contains the actual bytes. Names in the following map are analytical labels, not recovered symbols.

### Function and branch map

| Entry | Exclusive FDE end | Interpreted role |
|---|---|---|
| `0x336fef0` | `0x33709e4` | Guard, ordered traversal, expiry selection, removal and cleanup |
| `0x2fd8770` | `0x2fd8bbd` | Remove at cursor; replace internal entry with predecessor |
| `0x2fc54c0` | `0x2fc6423` | Leaf compaction, sibling choice, merge/borrow, upward repair, root shrink |
| `0x2fa3650` | `0x2fa3cbb` | Borrow from left sibling through parent separator |
| `0x2faa040` | `0x2faa742` | Borrow from right sibling through parent separator |
| `0x337da10` | `0x337da62` | Action-key niche/tag drop dispatch |
| `0x337bd60` | `0x337c00c` | Nested action drop dispatch |
| `0x337cf10` | `0x337d05d` | Removed row's buffer and container cleanup |
| `0x33b8a70` | `0x33b8e31` | Consume nodes of the map at row offset `+0x28` |

`control-flow.tsv` retains every decoded transfer, conditional continuation, indirect slot, RELATIVE relocation target, imported symbol where available, and selected/external scope. Register-indirect bindings include their manually reviewed defining RIP loads. These bindings do not purport to be general data-flow analysis. The table has 393 records, including expanded jump-table targets; this is not a count of unique branch instructions or a whole-node coverage denominator.

The selected windows contain 13,341 bytes and 2,595 decoded instructions. Their transfer records comprise 194 conditional records, 25 direct calls, 89 indirect calls, 60 direct jumps, 12 indirect-jump records, 9 returns and 4 traps. A complete linear decoding of an FDE is not a reachability proof.

### Incoming linkage and scheduling boundary

The incoming windows end in calls at `0x222a25a`, `0x470f3eb` and `0x4716e48`. Each constructs a descriptor with the same byte string `validator_l1_vote_tracker_prune_expired` at `0x5a805f`, then calls `0x336fef0`. The map arguments are state offsets `+0x3688`, `+0x3688` and `+0x4108`. The guard byte in these windows is produced by unsigned `seta`; `incoming-xrefs.tsv` retains all window bytes and derives the offsets and label from operands.

The prior vote packet established the tracker at state `+0x3678` and its `atT` map at tracker `+0x10`. Thus the first two map arguments agree with that independently recorded layout. The third is the shifted state layout already observed there. The sweep reads descriptor byte `+0x20` and runs only for value 1; other byte values return. This packet does not reconstruct the bucket quotient calculation in the enclosing callers, or assert that these three callers are exhaustive.

This resolves the prior packet's explicit question about the reader of row expiry and done, and the function removing `atT` rows. It does not put pruning into the vote handler: that earlier handler still does not itself remove rows.

### Selection and failure precedence

The host receives the map by mutable pointer and the current time by pointer. A row value is 112 bytes; the compared fields are date word `+0x60`, seconds word `+0x64`, subsecond word `+0x68` and done byte `+0x6c`. Date comparison is signed 32-bit, while seconds/subseconds are unsigned 32-bit. The labels describe the established time layout; no conversion from a Unix timestamp is invented here.

| Condition, in evaluation order | Outcome | Witness |
|---|---|---|
| Guard byte differs from 1 | Return without sweep | `0x336ff05`, `0x336ff07` |
| Empty root / exhausted traversal | End sweep | `0x336ff3c`, `0x3370017`, `0x337006a` |
| Now is before or exactly equal to expiry | Keep, including a done row | `0x337009b` through `0x33700c2` |
| Now is after expiry and done is nonzero | Remove without grace calculation | `0x33700c8`, `0x33700cc` |
| Now is after expiry and done is zero | Compute shifted expiry with 86,400 seconds | `0x33700ed`, `0x33700fc`, `0x337015b` |
| Time carry fails range check or returned date word is zero | Panic before row-count decrement | `0x3370124`, `0x3370163`, `0x3370930` |
| Now is before shifted expiry | Keep | `0x3370169` through `0x33701af` |
| Now equals or exceeds shifted expiry | Remove | `0x3370194`, `0x3370196`, `0x33701af` |

The strict first boundary and inclusive second boundary differ. In particular, a done row at expiry remains, while an unfinished row at its successful grace deadline is removed. A nonzero done byte bypasses calendar failure. The time helpers are external at slots `0x576e8a8` and `0x576e8b0`; the literal interval and panic path are observed, but their calendar implementations are not evaluated. `decisions.json` supplies their result as an explicit input, not as a silently successful stub.

Between the two time-helper calls, the host range-checks the returned signed 64-bit carry seconds, then computes days by signed high-product multiplication and shifts. `carry-cases.tsv` tests 23 boundaries: accepted carry is `-185542587273599` through `185542587187199`, inclusive. The projected quotient agrees with truncation toward zero by 86,400, and ranges from i32 minimum to maximum. Either adjacent outside value fails before the date helper. These bounds and multiplier are read from `0x337010a`, `0x3370117` and `0x3370141`; the gate and quotient-shift mutations are separately rejected by tests. This recovers the host's lowering, not the external helper's calendar semantics. The resolved callees `0x15206e0` and `0x151f870` are already discussed in `RE-001-chrono-shift-helpers-94` and other time packets; their bodies are not claimed here.

The panic text is `` `NaiveDateTime + TimeDelta` overflowed ``. `failures.tsv` preserves eleven failure text references in the selected windows, including merge cursor/capacity, empty internal node, root-height, borrow-capacity, borrow-count and child-count checks. These are static failure branches, not demonstrations that valid staking inputs can reach them. The empty-parent literal uses the odd packed descriptor 123, giving length 61; its raw argument and interpretation are both retained rather than treating 123 as a string length. Other collected literal arguments are raw lengths. This table is not an exhaustive enumeration of panic formatting inside external helpers.

### State mutation and continuation

The host traverses from the leftmost leaf. On a kept leaf row it advances the slot; on a kept internal row it descends the following child. Exhausted nodes ascend using parent and parent-edge fields. On removal, it decrements map length at `0x3370266`, calls `0x2fd8770` at `0x337028d`, checks the returned niche, drops a present returned action and value, and resumes the returned cursor at `0x33704ab` without an extra increment. The negation/overflow check at `0x3370388`/`0x337038b` exits for the high-bit-only sentinel before those drops. Reusing the old cursor and incrementing would not match this path.

| Tree field | Offset / size | Source |
|---|---|---|
| Map root, height, total length | `+0`, `+8`, `+0x10` | Host loads and length pointer |
| Key element | 128 bytes | Shift by 7 in cursor and leaf removal |
| Value array / element | Node `+0x580` / 112 bytes | Address arithmetic in host and leaf helper |
| Parent / parent edge | Node `+0xa50` / u16 at `+0xa58` | Traversal and repair loads |
| Occupied entries | u16 at node `+0xa5a` | Leaf and parent count loads/stores |
| Child array | Node `+0xa60` | Descents and root promotion |
| Capacity / nonroot minimum | 11 / 5 | Merge bound and underfull comparisons |

Leaf deletion copies out the selected key/value, moves each following array segment left separately using the imported `memmove`, and decrements the u16 occupied count. It does not erase the stale final slot. `leaf-projections.tsv` covers every occupied slot for leaf lengths 1 through 11: 66 local projections with before/after hashes. They cover compaction only, not repair or allocation.

For an internal cursor, `0x2fd8770` descends the preceding child to its rightmost leaf, removes the predecessor through `0x2fc54c0`, exchanges that key/value into the internal entry, and returns the continuation cursor. Height zero takes the direct leaf call at `0x2fd8b1b`.

In `0x2fc54c0`, a resulting length of at least 5 needs no sibling repair. An underfull nonroot node prefers the left sibling when its parent edge is nonzero; the leftmost child uses the right sibling. The compared sum is the pre-removal length plus the sibling length: less than 12 selects merge, while at least 12 selects borrowing. This sum accounts for the separator that a merge will insert after deletion. Merge removes the parent separator and can propagate underfull repair upward. Both borrow helpers move a separator through the parent and update source/destination counts; their child-edge paths and assertion exits are retained in the full windows and transfer table.

`repair-choices.tsv` evaluates 275 initial repair choices from the captured comparison and branch opcodes, covering every leaf length 1 through 11, both sibling directions with sibling lengths 0 through 11, and the no-parent case. Independent occupancy rules check the results; underfull and sibling-threshold condition reversals are negative controls. Some small sibling counts are corruption controls rather than valid B-tree fixtures. This projection chooses the route only; it does not execute merge or borrow memory writes.

An empty internal root promotes its first child, decreases the map height, clears the promoted child's parent pointer and releases the former root with size `0xac0`. A leaf root is not lowered. The distinction between leaf and internal roots is essential; the captured root-height assertion must not be flattened into unconditional root removal.

### Owned values and drop dispatch

The host calls action-key cleanup at `0x3370475` before row-value cleanup at `0x3370482`. A landing-pad sequence also calls row-value cleanup at `0x3370965`; the LSDA is recorded, but full unwind dispatch is not decoded or tested.

For the action key, the first word is transformed into a niche-derived index: words above `0x8000000000000009` use addition of `0x7ffffffffffffff6` modulo 64 bits, and other words use index 6. Indices above 6 return. The seven relative entries at `0x58a43c` dispatch as follows:

| Indices | Destination | Cleanup |
|---|---|---|
| 0, 2, 3, 5 | `0x337da47` | If size at key `+8` is nonzero, tail-call deallocation with pointer at `+0x10` |
| 1, 4 | `0x337da5c` | Return |
| 6 | `0x337da5d` | Tail-call nested action drop at `0x337bd60` |

The nested action has another nine-entry table at `0x58a12c`. All sixteen combined entries, relative displacements and target instruction boundaries are reproduced in `jump-tables.tsv`; source enum names are deliberately unresolved. `drop-table.tsv` is the action-only view.

Row cleanup conditionally releases the first buffer, traverses the container at `+0x28` through `0x33b8a70`, passes its nested values to external `0x33f5900`, then consumes the container at `+0x40` through external `0x33b0800`. The prior layout identifies these as the vote bucket map and stake snapshot respectively. The latter consumer already appears in other packets and its body is excluded. Nested value drops and unwind cleanup targets are recorded as external edges. No complete recursive destruction or allocator-equivalence claim is made.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo/build/compiler comparison, two-build native equivalence and whole-ELF comparison: not yet implemented/measured. There is no invented workspace or transplanted executable code.

The Python decision evaluator interprets the selected compare/setcc/branch decisions from target opcodes. It intentionally supplies time-helper outputs and skips the tree and metrics operations. An independent tuple-order expectation checks 481 cases, including exact expiry and grace edges, signed date extremes, unsigned seconds/subseconds, noncanonical done/guard bytes and calendar failure precedence. Raw-word extremes establish machine comparison behavior; they are not asserted to be valid calendar dates.

Ten opcode/operand mutations are reported individually. All fail the static witness check; nine change at least one local decision outcome. One survives the behavioral projection: replacing signed greater with greater-or-equal when its result is consumed only after proving date inequality. This survivor is retained, not counted as killed. Separate tests corrupt every one of the 132 byte anchors and exercise hash, range, NOBITS, table-boundary, instruction-truncation and branch-interior failures.

The leaf expectation independently constructs the surviving array entries and checks the entire projected node, including unchanged stale tail bytes. These local controls support the stated boundary, initial repair-choice and compaction conclusions; they do not substitute for target execution or a full tree evaluator.

## Results and limitations

- 38 packet tests passed, with zero skips. Repository artifact verification and catalogue consistency checks passed.
- Two regenerations with different hash seeds and timezones, under a PATH containing no binutils, were byte-identical for all 15 generated files. Packet tests also passed with that PATH.
- Selected denominator: nine FDE windows, 13,341 bytes and 2,595 decoded instructions. This is neither whole-node function coverage nor proof every decoded instruction is executable on a valid input.
- Three incoming windows, 132 fixed witnesses, sixteen jump-table entries, eleven failure text references, 481 local decision cases, 23 carry-lowering cases, 275 repair choices and 66 leaf compaction cases are regenerated from the authenticated artifact and explicit fixture inputs.
- Calendar implementation, recursive cleanup, allocator and metrics closures remain external. Merge/borrow and unwind paths have static maps, not dynamic equivalence tests. No live node, key, network, chain action or user fixture was used.
- The staking component's first task includes stake accounting and epoch transitions for both #94 and #115. This follow-up answers a previously open expiry lifecycle question; it does not satisfy that entire task. No progress gate is requested, and all four gates remain false.

Next question: can an independent cursor-removal implementation reproduce the captured internal-predecessor, both sibling directions and root-shrink paths on multilevel trees, while preserving the returned continuation cursor?
