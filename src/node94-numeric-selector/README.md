# Node94 unsigned numeric request projection

`lib.rs` independently implements the argument projection of ELF VA
`0x14f7660..0x14f774b`, bound to node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New source is MIT. No inferred unlicensed source or captured bytes are used.

`request_unsigned(value, flags, &mut [u8;20], &mut context, sink)` selects lower
hex for lowDWORD bit25, otherwise upper hex for bit26, otherwise decimal. It
writes canonical unsigned digits (including one digit for zero), preserving all
other buffer bytes. Hex ends at offset16; decimal ends at20. The sink receives
raw sign1, prefix `0x` in either hex mode or an empty decimal prefix, and the
digit slice. The same borrowed context is forwarded exactly once. The supplied
sink's raw u8 return is forwarded without boolean normalization.

The initialized scratch array, separate u64 flags, generic context, `FnOnce`
sink and span metadata are chosen safe interfaces. Native flags are a DWORD at
context+16; native decimal prefix is raw pointer word1 with length0. No native
pointer identity, original type/layout/ABI/compiler, hidden register behavior,
opaque sink implementation, full `G`, rendering, faults/unwind, arbitrary raw
aliases or concurrent mutation is claimed. No component gate is requested.

This is a direct-rustc component with one real path dependency:
`src/node94-integer-digit-span/lib.rs`, accepted in PR1128, is built unchanged
as `node94_integer_digit_span` and genuinely linked using `--extern`. There are
no Cargo registry dependencies, manifests, synthetic lockfiles or copied stubs.
The scoped qualification runner records the exact compiler, sysroot payloads,
linker, commands, source hashes, immutable input hashes and raw output streams.

The independent pre-source corpus and all-u64 mathematical argument are under
`research/work-items/RE-005-numeric-selector-94/independent-pre-source/`.
`input_only_driver.rs` receives stimulus fields only, and writes the complete
observed request/status and all20 final bytes. The unit build additionally
embeds the frozen corpus through the `NODE94_SELECTOR_FIXTURES` build variable.
Real Rust units check object identity and callback mutation in this chosen API.
