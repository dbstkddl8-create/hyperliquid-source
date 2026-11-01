# RE-001: what does the two-hop window at 0x514ad50 compute?

- Component ID: `foundation`, one small window; its source-level
  component is not established by this packet.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json digest for node #94).
- Source commit / reference commit: upstream main `3324e503` at branch time.
- Claim status: observation for the window's rule; inference for the
  shared-container reading; unresolved for source names, types, and callers.
- Scope included and excluded: included are exactly the one FDE window
  `0x514ad50..0x514ad6b`, its int3 padding, its FDE record, and a
  direct-caller census for it. Excluded are the preceding trio windows
  (`0x514acc0`, `0x514acf0`, `0x514ad20` — three-hop chain through
  `0x8e8`, different protocol, bound in #1286, not claimed here), the
  following window at `0x514ad70` (pushes rbx and calls — different
  protocol, not claimed here), all #115 addresses, target execution,
  and Rust reconstruction.

## Why this packet

The window is the immediate successor of the #1286 trio but is not a
fourth member of it: it shares only the first hop (`base =
[rdi + 0x788]`) and the store/return protocol, then takes a different
second hop (`inner = [base + 0x928]`, not `0x8e8`) and projects that
inner qword directly, with no third hop and no final field offset. It
is therefore bound alone, as one bounded work item: each byte of its
own rule is established independently from this window's retained
bytes, and grouping it with the trio would misstate its chain.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame record.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ad50 --stop-address=0x514ad70 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so it
cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was verified
to equal the provenance digest for node #94 (`3b7179cd…c0459f`,
91,774,280 bytes) before any byte was read from it. The checker
therefore takes an optional `--binary` argument: without it, it
verifies the packet files against each other (retained disassembly
bytes, FDE record, padding, rule edges); with it, it additionally
verifies the target digest, the window bytes, the padding, the FDE
pc range, and the direct-caller scan against that binary. On a
checkout where the LFS artifact is materialized, run the binary form
with `--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_two_hop_reader.py \
    --check research/work-items/foundation-two-hop-reader-94/evidence.json
python3 tools/foundation_two_hop_reader.py \
    --check research/work-items/foundation-two-hop-reader-94/evidence.json \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_two_hop_reader -v
```

## Evidence

Coordinate system: virtual addresses as reported by objdump on the
ELF; `.text` VA `0x1343c80` maps to file offset `0x1342c80` in this
binary, and the checker resolves every VA through the ELF section
headers rather than assuming VA equals file offset. Boundaries are the
FDE pc range, validated below against the `.eh_frame` record.

Window `0x514ad50` (27 bytes, FDE `.eh_frame+0x0029a1e4`, range
`0x514ad50..0x514ad6b`, SHA-256
`ccc59eb6bccf6e1f2780778f94984c242f0d3964e850bb4ac4d50923a47b3f51`,
5 int3 padding bytes to the next FDE at `0x514ad70`):
`endbr64; mov 0x788(%rdi),%rax; mov 0x928(%rax),%rax;
mov %rax,(%rsi); mov $0x1,%eax; ret`.
Rule: out = qword at `[[container + 0x788] + 0x928]`, return 1.
Direct e8 callers in `.text`: 0.

## Unknowns

- Source-level names and types for the container, the inner object, and
  the projected field are not established by these bytes.
- Why this field is exposed through a two-hop window while its trio
  neighbors use a three-hop chain is not established: the
  direct-caller census finds 0 e8 sites, so any caller must reach it
  indirectly.
- The `0x514ad70` window (different protocol, pushes rbx and calls)
  is a separate item and is deliberately not folded into this bind.
