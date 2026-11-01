# RE-004: PDI decimal byte and binary64 display path

The node writes a decimal index into a PDI-indexed row and two display paths divide signed amounts by a 256-entry binary64 table whose repeated-rounding values can differ from independently rounded powers of ten; a reconstruction can preserve the stored table bits and the zero and missing-row branches.

- Component ID: RE-004, quantities and rounding; PDI-indexed display scaling.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `d3af75257a396c85d20857f421c370ddb8cb40e5` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead only; no source was copied.
- Claim status: byte and FDE observations below; shared row role and PDI name are inferences; reachability of decimal indices is unresolved.
- Scope included and excluded: one row-byte writer and two readers, their identifier split and full byte-indexed table; excludes caller-level ownership, reference type identity, allocator/lookup/drop helper internals, reachable input values, other readers and node #115.

## Reproduce

Run from the repository root with Python 3.12.3 and the standard library. The generator imports the repository ELF and FDE parsers, checks the target SHA-256 first, and reads the binary without running it. No subprocess, network, or disassembler is used by the tool or tests.

```sh
python3 tools/pdi_display_decimals94.py --out research/work-items/RE-004-pdi-display-decimals-94
python3 -m unittest tests.test_pdi_display_decimals94
(cd research/work-items/RE-004-pdi-display-decimals-94 && sha256sum -c MANIFEST.sha256)
```

`evidence.json` contains FDE extents, file offsets, full original function bytes, fixed decision windows, constants and the proof bound. `branches.tsv` holds 17 byte-decoded conditional targets. `power-table.tsv` holds all 256 original table entries and an independently calculated correctly rounded `10^index`. The table is read directly from file-backed ELF bytes; its decimal interpretation assumes IEEE 754 binary64. Function bodies are identified by full SHA-256 plus the FDE records. An FDE is an unwind range, not a proof of a complete source function.

## Evidence

All addresses are node #94 ELF virtual addresses, with file offsets in `evidence.json`. These are the three analysed FDE intervals:

| Role | Start | End (exclusive) | Observation |
| --- | --- | --- | --- |
| row-byte writer | `0x36ff3c0` | `0x36ff4e2` | A successful lookup whose selected record has zero at `+0x58` may store `bl` to row `+0x2a`. |
| list display | `0x3be4510` | `0x3be46f3` | Reads the same row offset; divides a nonzero signed input after `cvtsi2sd`. |
| optional pair display | `0x4a06c30` | `0x4a06dba` | Two independently gated inputs share the row byte and table; each absent or zero input contributes positive zero. |

### Row selection and failure decisions

Each selected path computes `q = floor(id / 10000)` and `r = id - q * 10000`; it compares q with context `+0x30` and requires `r < context.+0x10`. The row address is `context.+0x08 + r * 48` and the decimal byte is at `+0x2a`. The reciprocal immediate at `0x36ff45b` is `0x346dc5d63886594b`: for every u64 id, `(id * reciprocal) >> 75` equals `id // 10000`. The generator checks the exact integer bound `10000 * reciprocal - 2^75 = 432` and `(2^64-1) * 432 < 2^75`; the largest fractional part of `id/10000` is `9999/10000`, so this error cannot cross the next integer. The equivalent multiply and shift are present in each fixed decision window.

| Path | Condition | Observed result |
| --- | --- | --- |
| writer | initial lookup absent or selected lookup word `+0x58` nonzero | no row write |
| writer | eligible lookup, wrong q or r outside length | constructs tag `0x60` and calls error helper |
| writer | eligible lookup and valid q and r | stores the supplied low byte at row `+0x2a` |
| list | wrong q or r outside length, amount zero | produces an empty/default item and zero float |
| list | wrong q or r outside length, amount nonzero | calls the failure helper at `0x3be46ba` |
| list | valid row, amount zero | writes zero float without reading the decimal byte |
| list | valid row, amount nonzero | loads row byte and computes signed binary64 conversion divided by selected table entry |
| pair | respective option low bit clear or value zero | corresponding float remains positive zero, without row lookup |
| pair | option present and value nonzero, wrong q or r out of range | calls the failure helper at `0x4a06dad` |
| pair | option present and value nonzero, valid row | converts that signed 64-bit value to binary64 and divides by selected table entry |

These are static control-flow readings, not execution of the target. Error helper effects after entry are not modelled. The writer's lookup predicate and consumers' surrounding objects have not been shown to share a live object instance; the equal row layout and byte offset support a data-format relationship only.

### Divisor table

Both readers load the table at `0x5b8f60` using a zero-extended row byte as an eight-byte index. Thus every byte value addresses one of the 256 inspected entries. Index 0 is binary64 `1.0`; each subsequent original bit pattern equals the previous value multiplied by 10 with round-to-nearest, ties-to-even. The checker proves this for all 255 transitions using exact integer significands and rounding, not host floating-point arithmetic. This establishes the relation among the bytes, not the original table-generation method.

Of 256 entries, 195 differ from independently rounding the exact integer `10^index` to binary64. The first difference is index 25: stored bits `45208b2a2c280290`, versus `45208b2a2c280291`. Indices 0 through 24 match. Index reachability is unknown; no claim is made that the difference occurs for an admitted asset. Conversion and division are binary64 instructions subject to the active hardware floating-point environment; the table check makes no claim about the exact output of every division.

### Inferences

The quotient/remainder split resembles the reference's PDI dex/local split and the byte resembles a display decimal count. These names are not established by a typed symbol. The copied string and other output fields in the list and pair paths remain unnamed; none is necessary for the divisor observation.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo build, code comparison, normalization, relocation closure or target execution was performed. The 9 focused unit tests check real input authentication, FDE ranges, all table entries, the exact recurrence, reciprocal boundaries and ties-to-even arithmetic; corruption controls reject a changed binary digest, branch byte, table byte and an unbacked address. Tests of the mathematical model are not a runtime comparison with the target.

## Results and limitations

The checked scope is 3 FDE intervals, 5 fixed decision windows, 17 decoded conditional branches and 256 consecutive table entries; 255 of 255 table transitions match the stated recurrence. The u64 quotient proof is over the full input domain. These are not a census of the node's quantity code. The table check assumes binary64 nearest-even to describe its bit relation; it does not establish the target's active rounding mode. Alias relationships, provenance and range of the decimal byte, behavior of callees and all other readers remain unresolved. No component progress gate is requested.

Next question: trace the producer of the writer's decimal-byte argument and establish its admitted range, then compare an independently authored Rust display path against an authorized offline target harness.
