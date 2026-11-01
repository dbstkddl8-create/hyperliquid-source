# Formatter448 independent pre-source proof and admissible proxy domain

This is a new mathematical input authority, frozen before new formatter Rust.
It is not a recovered historical log or an execution result. At freeze the
basis is the connected, published #1216 native listing at head
`13d5e1c36bb4e7c8d09d37086a3398c243a0efe1`, path
`research/work-items/RE-002-libcore-write-fmt448/observed/target.objdump.txt`,
Git blob `1ee3901046eaf711b08adbed83bdc45946900ca2`. Root must subsequently
authenticate the full target and raw function bytes before implementation
claims. Target #94 is SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete function is VA `0x1571d90..0x1571f50`: 448 bytes, 138 GNU rows,
26 local direct branches, three indirect calls and one indirect tail jump.

## Native domain and relation

The native function has two entry representations. An odd fourth word chooses
the direct representation: its logical length is that unsigned word shifted
right by one. The tail call reads the writer method at table+24, passes the
original writer data, byte pointer and logical length, and returns whatever
that callback leaves in AL. Only low AL is modeled. The proxy bridge uses a
length-bounded byte slice; arbitrary native pointer arithmetic/aliases remain
outside that bridge. A zero direct length still calls the writer.

An even fourth word supplies the paired descriptor rows. A compact byte stream
begins at the third entry argument. Its initial zero byte returns zero without
reading table+24. Otherwise table+24 is read once and cached before any callback.
The implicit descriptor index begins at zero. Each iteration reads one tag:

* 0 terminates successfully, with no callback.
* 1..127 requests a writer call for exactly that many following bytes.
* 128 requests a writer call whose length is the next little-endian u16,
  including length zero, and consumes those two length bytes.
* 192 requests the current implicit descriptor with options `0x60000020`
  and two zero quantities.
* All other high tags use their low six bits as independent field controls.
  Bit0 supplies a little-endian u32 options word; otherwise `0x60000020`.
  Bit1 supplies a little-endian u16 first quantity; otherwise zero. Bit2
  supplies the second u16 quantity; otherwise zero. Bit3 supplies a u16
  descriptor index; otherwise the current implicit index. Fields occur in
  that order. Bit4 replaces the first quantity by low16 of the second word
  of the row indexed by the first quantity. Bit5 similarly replaces the
  second quantity. A dynamic bit with its field absent therefore reads row0.
  Bit6 has no effect except that exact tag192 is the short form above.

Each value request reads the selected row's current first and second u64 words
as callback data and callback method. Immediately before that callback, the
whole logical 24-byte G context is reset: original writer data, original writer
table, options u32, first u16, second u16. These are respectively the native
stores to rbp-48, rbp-40, rbp-38, rbp-34, rbp-32; the short form writes the
last eight bytes as one qword. Mutations to a prior G context do not persist.
If G returns low AL zero, next implicit index becomes selected+1, including
after an explicit index. Every nonzero W/G low AL ends compact mode with
canonical low AL one. No future tag, descriptor or callback is then touched.

Literal calls use the cached original writer method even after callbacks change
the method stored in the original table. G starts with the original writer
table identity, and a nested writer action follows the G context's current
table and data. All descriptor/quantity reads are live: preceding supplied
callbacks may change row words. Stream mutation is outside the chosen bridge.

The proof is structural induction over the finite callback/tag trace. The
initial state agrees by the entry branches at d90..dcc. Each literal form
advances to the next tag by its encoded length (df0..e13 and e45..e67). The
generic field prefix and both quantity substitutions are exactly e6c..ed7
and f0a..f19. Value context/row stores and dispatch are ed7..efa. The successful
value step efe..f05 establishes the next-index invariant; error/termination
branches f3b..f41 establish the stated AL relation. Direct mode f1b..f39
establishes the separate tail-call relation. Thus the relation covers every
finite, admitted native trace, independently of corpus size. Unbounded or
nonterminating callback/stream traces are no termination claim.

## Chosen safe executable bridge

Byte slices and descriptor cells have stable allocation; writer destination
and table are opaque u64 identities rather than raw addresses. Descriptor
rows contain live `Cell<u64>` first/second words. Second words serve both as
opaque supplied G methods and as low16 quantity sources. The original table's
writer method is a live cell sampled once as described above. Table identity2
in supplied nested scripts has a declared method202. No hidden register,
stack, scratch, return-PC, padding or private ABI behavior is exposed. No
claim identifies the original renderer or callback implementation.

Supplied scripts are an explicit environment: callbacks are indexed by global
invocation ordinal across outer W, G and nested W. Missing entries mean return0
with no actions. Actions execute in order: set original writer method; change
a row; replace the whole G context; or request a nested writer call. Nested
writes use current G destination/table. If propagate is true, a nonzero nested
reply immediately returns that raw byte from G. Scripts contain no expected
event roles, semantic plans or oracle results.

The callback transcript records a value event at entry, retaining both before
and after contexts; nested writer events follow it. Final method/row state is
also compared. Values and writer replies are u8; native compact replies are
canonicalized while direct replies remain raw. No copied renderer is used.

Malformed/truncated byte streams, out-of-range row references, unknown nested
table identities and invalid script operations are chosen checked refusals
outside the qualified native domain. The native instructions do not perform
these checks: their possible faults, out-of-allocation reads, forged pointers,
UTF-8/callback contracts and native undefined behavior are not claimed. Refusal
is lazy: already-required callbacks happen, and an earlier callback error or
terminator can prevent inspection of a malformed tail. A safe refusal is never
labeled a native error result or evidence that the native program faults.

## Corpus separation

`generate_formatter.py` defines high-level literal/value plans and supplied
scripts. Its expected transcript interpreter consumes plans, never serialized
compact bytes. An independent serializer produces raw bytes from those plans.
The driver input file contains only raw route/stream, opaque entry identities,
descriptor words and supplied scripts. Plans and expected transcripts are
retained in a separate authority file. All 128 high tags, all compact literal
length tags, all256 raw callback replies, alias tags, live mutations, nested
calls, context reset, index rebases, zero requests, endian fields and bounded
refusals have explicit cases. No captured code or instruction evaluator runs.

This does not advance a component gate or establish rebuilt byte identity,
whole-node equivalence, unwind equivalence or private/native callback ABI.
