# Node #94 ASCII address acceptance and payload

This independently authored dependency-free `no_std` Rust component implements
the **ASCII** acceptance and twenty-byte payload relation established by merged
PR #339 / `research/work-items/RE-001-address-parser-94`. Target node #94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
No inferred reference implementation is copied.

```rust
pub fn parse_ascii_address(input: &[u8])
    -> Result<Option<[u8; 20]>, OutsideAsciiDomain>;
```

Within ASCII, the accepted language is `(?:0x)?0*[0-9a-fA-F]{40}` with a full
match. Only lowercase `0x` is a prefix; extra leading zero bytes are permitted.
The final forty bytes form exactly twenty decoded bytes, with either hex case.
Whitespace is not accepted in this address window. `Some` returns the observed
successful payload; `None` projects the observed rejection path conditional on
ordinary returns from opaque error helpers. No error allocation/display, original
enum layout, caller ownership or full parsing interface is recovered.

Non-ASCII input returns `OutsideAsciiDomain` as our research API's domain policy.
It does not assign the native Unicode, UTF-8-boundary panic or invalid-memory
behavior. Slice borrows and a fixed array are our safe representations, not a
claim about the original Rust object ABI.

The real build is direct repository-pinned `rustc 1.94.1`, edition 2021, without
external dependencies or a fabricated original Cargo package/workspace:

```sh
python3 tools/address_ascii_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
```

The runner authenticates the full capture and accepted native records before
compilation. A host C linker is required; `RECONSTRUCTION_LINKER` can select it,
and macOS may need `SDKROOT`. It regenerates the entire input-only corpus and
checks its pre-Rust frozen input/expected hashes. A compact fourteen-row frozen
smoke fixture stays beside the source; the larger deterministic corpus is kept
in the fresh output directory rather than duplicated in Git.

The [RE-005 packet](../../research/work-items/RE-005-address-ascii-rust-94/README.md)
records actual two-profile builds, compiled mutation controls, native-operand
counterfactuals and scope limits. No captured node, visor or instruction emulator
is run by this component runner. No target-byte equivalence or full component
gate is claimed. New code is MIT; imported evidence keeps its original ownership.
