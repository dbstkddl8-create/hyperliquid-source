# foundation-sentinel-field-read-94: what does the sentinel-checked field-reader window compute?

- Component: `foundation`, one small previously unclaimed window; its
  source-level component is not established by this packet.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: upstream main `b7fa6899` at branch time.
- Claim: observations about one target instruction window; its source-level
  name and types remain inferences.
- Included: the 51-byte FDE window, its thirteen int3 padding bytes, the
  window FDE record and the next FDE record, the exact sentinel-checked
  field-read rule, and a direct-caller scan (zero sites).
- Excluded: the neighboring accessor windows `0x514ab90` (plain copy) and
  `0x514abf0` (virtual call at vtable offset `0x478`), all #115 addresses,
  target execution, Rust reconstruction, and any family census.

## Why this packet

This window was first surfaced, unclaimed, as a neighbor in the merged
`foundation-devirtualized-getter-94` packet (#1274): that packet's README
names `0x514abb0` as a 51-byte sentinel-checked read of `[elem + 0x30]`
with no type check and no call, and states explicitly that no neighbor is
claimed anywhere in that packet. This packet claims only that window, and
verifies its rule independently from its own retained bytes below — the
neighbor description was a lead, not evidence. The window shares the
container protocol of the devirtualized-getter family (element qword at
`[rdx + 0x1200]`, sentinel at `rdx + 0x11e0`, return value always 1, value
stored to `[rsi]`), but unlike `0x514b620` it performs no type check and
no call: it is the plain sentinel-gated field read of the family.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64,
Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and
tests use Python's standard library only. No Ghidra or Java was used;
GNU `--dwarf=frames` output supplies the retained frame records.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514abb0 --stop-address=0x514abf0 work/hl-node-94.bin
objdump --dwarf=frames work/hl-node-94.bin
```

Environment note, stated plainly: `artifacts/node/94/hl-node` in this
checkout is still a 133-byte LFS pointer (no git-lfs on this VM), so it
cannot be the extraction source here. The extraction source is
`work/hl-node-94.bin`, an ignored work copy whose SHA-256 was verified to
equal the provenance digest for node #94
(`3b7179cd…c0459f`, 91,774,280 bytes) before any byte was read from it.
The checker therefore takes an optional `--binary` argument: without it,
it verifies the packet files against each other (retained disassembly
bytes, FDE records, padding, rule edges); with it, it additionally
verifies the target digest, the window bytes, the padding, and the
direct-caller scan against that binary. On a checkout where the LFS
artifact is materialized, run the binary form with
`--binary artifacts/node/94/hl-node`.

```sh
python3 tools/foundation_sentinel_field_read.py --check research/work-items/foundation-sentinel-field-read-94/evidence.json
python3 tools/foundation_sentinel_field_read.py --check research/work-items/foundation-sentinel-field-read-94/evidence.json --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_sentinel_field_read -v
```

No target binary was executed. All analysis below is static byte evidence.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA -
`0x1000`; the retained `.eh_frame` has equal file offsets and VAs.

### Entry, FDE extent, and padding

- `.eh_frame+0x0029a100` describes `[0x514abb0, 0x514abe3)`, 51 bytes.
  GNU's independent frame dump agrees. Complete linear decoding from that
  start gives the instruction sequence below, ending exactly at the FDE
  endpoint (the `ret` at `0x514abe2`).
- Thirteen `int3` bytes (`0xcc`) pad the window from `0x514abe3` to the
  next FDE start `0x514abf0`. The stride is **not** the FDE extent.
- The window SHA-256 over its 51 body bytes is
  `c0520b59bd2bd951d83f5639479e46f8c51fa9bfce9183082ccbc04a70d2be19`.

### Body behavior: sentinel check, then field read or zero

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x514abb0` | `endbr64` | Entry |
| `0x514abb4` | `mov 0x1200(%rdx), %rax` | Element pointer |
| `0x514abbb` | `add $0x11e0, %rdx` | Sentinel (rdx is clobbered) |
| `0x514abc2` | `cmp %rdx, %rax` | Empty test |
| `0x514abc5` | `je 0x514abd8` | Empty skips to the zero path |
| `0x514abc7` | `mov 0x30(%rax), %rax` | Field at elem + 0x30 |
| `0x514abcb` | `mov %rax, (%rsi)` | Store to out |
| `0x514abce` | `mov $0x1, %eax` | Return 1 |
| `0x514abd3` | `ret` | Return |
| `0x514abd4` | `nopl 0x0(%rax)` | Alignment padding between paths |
| `0x514abd8` | `xor %eax, %eax` | Zero |
| `0x514abda` | `mov %rax, (%rsi)` | Store 0 to out |
| `0x514abdd` | `mov $0x1, %eax` | Return 1 |
| `0x514abe2` | `ret` | Return |

- The rule, over container pointer (`rdx`), element pointer (the qword
  at `[rdx + 0x1200]`), sentinel (`rdx + 0x11e0`), and out pointer
  (`rsi`), is: if the element pointer equals the sentinel, store 0 to
  `[rsi]` and return 1; else store the qword at `[elem + 0x30]` to
  `[rsi]` and return 1. No call, no type check, no other store, and no
  other register is read: `rcx` is untouched, and the `je` target
  `0x514abd8` is exactly the next instruction address plus the `0x11`
  displacement.
- Direct callers: none. A byte-pattern scan of `.text` finds exactly 0
  direct `e8` calls to the window. Register-indirect references, other
  pointer paths, prefixes, and data sections are not a complete xref
  census.

## Inferences

- Inferred label: sentinel-checked field reader. The rule is observed and
  proven above; only the label is inferred.
- The sentinel comparison reads as a small-buffer/empty-container check
  (the stored pointer equals an inline address), but what the container
  is and why the sentinel lives at offset `0x11e0` is not established,
  so that reading is an inference only.

## Unknowns

- The source-level name and types of this window, its container, and its
  elements.
- What the `0x1200`/`0x11e0` container fields mean, and what the field
  at element offset `0x30` represents.
- What calls this window, beyond the direct-call scan above.
- The disassembly's nearest-symbol annotation carries a large offset and
  is not an identification of this window.

## Excluded

The neighboring windows `0x514ab90` and `0x514abf0`, the virtual-call
target question (this window has no call), all #115 addresses, target
execution, Rust reconstruction, any family census, and any progress gate.
This packet requests no gate.
