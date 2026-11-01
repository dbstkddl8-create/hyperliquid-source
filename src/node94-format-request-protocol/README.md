# Node94 formatter request controller

This independently authored, dependency-free `no_std` Rust implements the
complete finite normal-callback request relation of node94 ELF VA
`0x1571d90..0x1571f50` (448 bytes). It consumes direct bytes or a compact
descriptor stream and calls real supplied writer/value proxies. There is no
default renderer, guessed private value implementation, or copied libcore Rust.

Direct input requests all supplied bytes, including an empty slice, and returns
the writer's raw `u8`. Encoded input returns zero at its first terminator and
canonicalizes every nonzero callback reply to one. Short literal tags cover
1..127 bytes; tag128 has a little-endian u16 length, including zero. Tag192
requests the next implicit paired row with options `0x60000020` and two zero
quantities. Other high tags independently control options, quantities, explicit
index and quantity indirection with their low six bits.

`Row` contains two live `Cell<u64>` words. Both indirect quantities read the
low16 of the selected row's **second** word. A value request reads that row's
current data and second word; a successful explicit index also rebases the
next implicit index. Every value receives a fresh full 24-byte `Context` with
the original destination/table and decoded options/quantities. Proxy edits to
that context do not survive into the next value. Literal requests use the
writer method sampled once before the first encoded callback, even when a
proxy changes the method cell. Nested requests implemented by supplied value
proxies may follow the context's current destination/table and current methods.

The API has chosen safe roles and valid references, immutable stream bytes,
live row/method cells and normal, finite callbacks. Opaque words are symbolic
identities rather than native addresses. `Context` has a 24-byte C layout to
make its word projection explicit; this does not establish an original nominal
type, vtable or ABI. Stream/frame/control corruption, concurrent mutation,
faults and unwind are outside the bridge. `Refusal` checks truncated input or
missing rows lazily; those are this API's policy, not recovered native errors.

The actual build uses the authenticated research rustc 1.94.1, without Cargo,
registry dependencies, an invented lockfile or a root workspace:

```sh
/path/to/verified/rustc --edition=2021 --crate-name node94_format_request_protocol \
  --crate-type=rlib -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-format-request-protocol/lib.rs -o /tmp/libnode94_format_request_protocol.rlib
python3 -B tools/format_request_protocol.py --rustc /path/to/verified/rustc \
  --output /tmp/fresh-format-request-build --controls
```

`input_only.rs` is a separately linked external client. It accepts only raw
route/stream, row words and explicit proxy scripts on stdin, then prints actual
requests, contexts, replies and final method/rows. It cannot open an oracle or
receive expected event roles. The independent plan oracle and its separate raw
serializer were frozen before this Rust existed. Build/comparison results,
native proof, rights and limits belong to the [evidence packet](../../research/work-items/RE-001-format-request-controller-94/README.md).
