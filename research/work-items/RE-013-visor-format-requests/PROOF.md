# Conditional formatter/sink argument

This is a manual static argument over the retained instructions, data and RELA records, not execution or instruction evaluation. Assume ordinary x86-64 calling conventions; valid, stable, non-overlapping object/payload/output storage; normal completion of opaque preparation calls; and ordinary imported `memcpy` semantics. Heap allocation failure, invalid pointers, aliasing, unwinding and mutation of live argument storage are outside the statement.

The request-order conclusion below needs callbacks to return success. The constructed-byte-string conclusion additionally assumes that internal allocation supplies valid disjoint storage and that every selected growth operation preserves the initialized prefix and yields adequate capacity. Those allocator properties are **assumptions, not established results** of this packet. In particular, the growth slot binds to internal `0x710ea0`; calling it libc `realloc` would overstate the evidence.

## Caller and prepared argument records

The retained fixed caller copies the sixteen bytes at `0x6df30`, initializes its option byte to zero and calls the unique `0x7e5f88 -> 0x3d8d70` binding. The helper preserves that input object and stores its pointer at `rsp+0x50`.

Its prelude calls `0x3a0440` into a local object and formats data at `0x688d6` using `0x3d7320`. The raw stream requests thirteen literal bytes `shell_rs_out/` and argument 0. Opaque `0x3a1780` then receives this formatted pointer/length and produces an object at `rsp+0xa8` (R14). `0x3a0d10` is called with its pointer/length words. A nonzero return from that call selects an early return before the main command formatter. No identity between the raw temporary-format result and the later prepared payload is assumed.

On the selected preparation-success edge, the fixed input contains neither `2>&1` nor boundary parentheses, so the helper reaches `0x3d8eed`. Its zero option selects `0x3d8f36..0x3d8f78`, which constructs two 16-byte records:

1. `(pointer-to-input-object-pointer, callback 0x3d8230)`;
2. `(pointer R14 to the prepared object, callback 0x3d7320)`.

The stream pointer is `0x7a9a8`. The stack argument-array pointer is even, excluding the low-bit-set literal-only representation used by the formatter/driver. No third callback record is constructed on this path.

## Allocation wrapper and driver

`0x2bebb0` preserves stream RSI in R15, argument-array RDX in R14 and destination RDI in RBX. Its literal-size prepass estimates capacity; it is not an output semantic oracle. It initializes local capacity/pointer/length words, with initialized length zero, then passes their address, writer data `0x7a8840`, the stream and the argument array through slot `0x7e4c28 -> 0x49a480` at `0x2becce`. A nonzero returned byte selects opaque error construction. On zero it copies the three storage words to the supplied destination.

The driver's even-argument-array branch loads the writer function from `[writer-data+0x18]` and sets its next-argument counter to zero. At `0x49a4e0..0x49a503`, a positive signed byte is a literal length: the sink is called with the bytes immediately following the tag and exactly that length. After a zero sink result, the stream advances past those bytes. A zero tag selects the success return at `0x49a62b`.

At `0x49a514..0x49a530`, `0xc0` takes the current next index, multiplies it by 16, and installs option words whose low DWORD is `0x60000020` and whose width/precision words are zero. The common callback block at `0x49a5d2..0x49a5f5` reads data/function from that record, supplies a formatter containing the same sink object/vtable and invokes the callback. A nonzero result leaves through `0x49a62f`; only success increments selected index and stores the new next index.

For `0xc8`, the general branch keeps default option `0x60000020`, reads neither optional flags nor width/precision (bits 0,1,2 are clear), and takes the bit-3 edge at `0x49a5a4`. That reads a little-endian unsigned 16-bit index, advances the stream by two bytes and selects that record. Bits 4 and 5 are clear, so no width/precision argument lookup occurs. Width and precision remain zero. Successful callback return again sets next index to selected index + 1. This establishes only the used opcode subset, not the full compact format language.

## Three admitted data streams

Following the actual byte tags at `0x7a9a8` gives:

| Stream offset | Bytes/action | Argument counter after successful action |
| --- | --- | --- |
| 0 | `01 28`: literal `(` | 0 |
| 2 | `c0`: callback record 0 | 1 |
| 3 | `04 29 20 3e 20`: literal `) > ` | 1 |
| 8 | `c0`: callback record 1 | 2 |
| 9 | `0c 20 32 3e 26 31 20 26 26 20 72 6d 20`: literal ` 2>&1 && rm ` | 2 |
| 22 | `c8 01 00`: explicit callback record 1 | 2 |
| 25 | `00`: successful terminator | 2 |

Thus callback record 1 is requested twice; an implementation that advances to an absent record 2 at the last placeholder would misread these bytes.

The nonzero-option helper branch constructs a one-record array for `0x6bf04`. Its stream requests `(`, command record 0, then the eighteen bytes `) > /dev/null 2>&1`, then terminates. This is an alternative helper path, not the fixed caller's observed option.

At `0x688d6`, tag 13 requests `shell_rs_out/`, followed by `0xc0` selecting its single callback record and a zero terminator. This establishes the prelude's requests only. Its source object and later preparation transformations remain opaque.

## Callbacks and unchanged-byte sink path

`0x3d8230` first dereferences the pointer passed in RDI to obtain the command object. It loads payload pointer at object +8 and length at +16, moves the supplied formatter from RSI to RDI and tail-jumps through `0x7e4c50`. `0x3d7320` loads the same two offsets directly from its supplied object before the same tail jump. Let the stable payload byte strings read here be C and T, respectively.

The unique slot binding selects `0x499ae0`. At `0x499af4..0x499aff`, mask `0x18000000` is tested against the low option DWORD. Its intersection with `0x60000020` is zero, selecting `0x499e50` directly. That block forwards the original payload pointer and length to the formatter's writer at vtable offset +24. The character-counting, width and precision paths are not selected. No callback-added quotation, padding or truncation is on this selected byte-forwarding path.

## Writer and explicit storage boundary

The wrapper's writer data at `0x7a8840` has the unique offset-24 RELATIVE binding `0x7a8858 -> 0x2bf090`. On sufficient capacity, the writer computes the destination as buffer pointer + old initialized length, copies the supplied length via uniquely imported `memcpy` (skipping the copy for zero bytes), increments initialized length and returns byte zero. Under ordinary copy and storage assumptions this appends the input byte string unchanged.

If spare capacity is insufficient, `0x2bf0d7..0x2bf0ef` calls `0x2bd9a0` with the old length and incoming byte count. That helper checks addition carry, chooses at least 8 and the unsigned maximum of doubled old capacity versus required length, calls `0x2be970`, and on its non-error result replaces the buffer pointer and capacity. The lower helper binds its old-capacity-nonzero path to internal `0x710ea0` through `0x7e4bc8`; its no-old-capacity path binds to internal `0x70bf30`. Neither internal allocator body is qualified here. Error paths go to an opaque helper. Prefix preservation, valid fresh storage, capacity arithmetic being within its successful domain and normal return are explicit conditions; merely exporting their callees would not prove them.

Consequently the ordered sink requests are established as above. If the stated writer/heap conditions hold, the local output is their concatenation: `(C) > T 2>&1 && rm T`; for the fixed caller, substitute exactly `pkill run-client` for C. The quiet path similarly yields `(C) > /dev/null 2>&1`. This conclusion does not recover the bytes of T, establish success of subsequent C-string conversion, prove that the process consumes this object, identify a host shell, or establish creation/readback/deletion or command success. #1266's separate argv/wait conditions and all component gates remain unchanged.
