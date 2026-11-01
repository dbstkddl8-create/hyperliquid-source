# RE-005 / foundation: reconstruct the established ASCII address projection

- Target node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base main `3324e50333042b391312515e542279ca21f63dc8` plus shared CI
  prerequisite `516b1e3a` / #1295, not additional contribution credit.
- Accepted native evidence: merged #339,
  `RE-001-address-parser-94` and `tools/address_parser_static.py`, unchanged.
- Outcome: independently authored `no_std` Rust ASCII acceptance/payload
  projection, a real direct-compiler build and target-grounded comparisons.

## The missing reconstruction and its boundary

The accepted packet establishes conditional ASCII acceptance and successful
twenty-byte output but provides no Rust implementation. Existing signable action
writers consume address bytes; they do not implement this parser. This change
implements the established subset as one parser/iterator family, not independent
PRs for prefix, padding, nibble case or each loop copy. It serves the approved
reconstruction scope and RE-005 foundation/serialization leaf work.

Native evidence covers complete actual FDEs `0x1444a00..0x1444d6c` (876 bytes /
204 instructions) and `0x4eb64f0..0x4eb68a9` (953 bytes / 242 instructions):
**1,829 bytes / 446 instructions** in ELF virtual coordinates. The old complete
exports, original FDE/CIE records and body hashes remain intact. The new oracle
authenticates the full input, regenerates all accepted records and requires exact
equality. It verifies both full body hashes, iterator relocation
`0x576f580 -> 0x4eb64f0`, source Locations and all prior operand controls.

These are the native evidence denominator, not recovered machine-byte counts.
Only ASCII acceptance and successful payload values are implemented. The original
parser's error allocation/display helpers, Unicode iterator behavior, UTF-8 slice
panic paths, input/output object ABI, caller ownership and complete function
equivalence remain unresolved. A projected rejection assumes ordinary error-
helper return. Native valid/nonwrapping backing slices and disjoint input/output
are explicit assumptions; safe Rust borrows and a fixed array are our own API.
The new `OutsideAsciiDomain` refusal does not classify native non-ASCII behavior.

## Why the compact Rust relation follows

The captured outer comparison removes only lowercase `0x`. It then requires at
least forty remaining bytes, splits before the final forty and requires each
leading scalar to be U+0030. Within ASCII, this is exactly a zero-byte padding
check. The iterator accepts ASCII hex digits and skips a fixed whitespace set.
But the parser requires twenty tag-2 byte results and then an end tag: any skipped
whitespace in the forty-byte window leaves fewer than forty digits, so cannot
succeed. Any invalid hex digit fails. The inner optional `0x` leaves only 38
bytes and also cannot provide twenty outputs.

Consequently the accepted ASCII language is exactly the full-match expression
`(?:0x)?0*[0-9a-fA-F]{40}`. On success each ordered digit pair supplies one byte.
The Rust strips its outer prefix, checks zero padding and directly decodes the
last forty bytes, preserving that relation without mimicking intermediate error
objects or iterator state. It is not claimed to reproduce instruction/fault/
allocation traces. No address checksum, normalization policy or blockchain
interface is invented.

## Freeze, independent expectations and denominators

Commit `e1a58400` freezes full deterministic corpus hashes and the compact
fourteen-row smoke file **before `lib.rs` exists**. The input corpus and expected
output are regenerated in the fresh build directory; Git need not duplicate
their long repeated strings. `PRE-RUST-FREEZE.json` pins their hashes, source
identities, counts and the absent Rust source. It is preserved unchanged.

There are **10,872 comparison rows**: **10,869 ASCII cases** and **three separately
labelled own-API non-ASCII cases**. There are **10,789 distinct input strings**;
case counts are not distinct inputs or captured calls. The population includes
the accepted 10,240 single-position substitutions (40 positions, 128 ASCII bytes,
two prefix forms), zero/nonzero padding lengths 0..96 with three prefix forms,
short lengths, inner-prefix/whitespace/long-zero boundaries and the domain cases.

Expected outputs use actual prefix/padding/classifier offset/bound/bias operands
from the authenticated capture. They must agree with both the accepted static
model and an independent regex plus Python hex decoder. This is static integer/
language reasoning, not a CPU interpreter or captured execution. The separately
linked production Rust driver receives only an ID and input bytes. Expected
answers remain in the external comparator; `cfg(test)` alone reads smoke answers.

Both actual Rust 1.94.1 builds (opt levels zero/three) match all rows. Each runs
the ordinary frozen smoke test. Identical optimized recipes produce raw-equal
own rlibs with no normalization. Rustfmt and Clippy library/test configurations
with warnings denied pass on the pinned toolchain. This is a research compiler,
not recovered original build provenance; no original Cargo dependency graph or
root workspace is fabricated.

Three compiled Rust mutants change the outer prefix, zero-padding requirement
and uppercase nibble bias. Production comparisons detect **1,077 / 385 / 1,956**
mismatches, respectively; actual compiled smoke assertions fail too. Three actual
private native operand edits change the same prefix/padding/first-uppercase-
nibble observations and are rejected by the native operand checker below the
whole-input gate. Selected witnesses are retained, not claims about every path
of the modified binary. No altered capture is executed or emulated.

## Reproduce and results

```sh
python3 -m unittest tests.test_address_ascii_rust tests.test_address_parser_static -v
python3 tools/address_ascii_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
make doctor verify catalogue-check reproduce
make test
git diff --check
```

Actual local host: macOS arm64, Python 3.12.14, Rust 1.94.1. The runner builds
a genuine dependency-free `no_std` library and separate standard-library driver,
edition 2021, warnings denied, one codegen unit and overflow checks on. Compiler,
linker, SDK, source/input hashes, exact recipes, outputs and controls are retained
in `build-result.json`. Private path placeholders affect path spelling only;
no target code operand is normalized. Raw logs/compiler products stay outside
Git in the requested fresh output folder.

The focused run passed **11 tests in 4.529 seconds**; safe repository checks
also pass. Full-suite state is recorded separately in `validation.json`; pending
must not imply passed. Prior packet's historical failed platform checks are not
rewritten. All captures/imports/pins and component gates remain unchanged. Host
arm64 rlib reproducibility is not an x86-64 target match; target raw/normalized
counts are unmeasured. Next close a real caller and error allocation/Unicode
boundaries before claiming the complete original address parsing interface.
