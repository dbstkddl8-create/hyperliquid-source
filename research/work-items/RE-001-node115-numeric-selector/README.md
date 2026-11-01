# RE-001: node115 numeric-selector normalization and caller gates

- Component: foundation / serialization projections. Bounded static research; no reconstruction gate.
- Target: node115,105896032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source base:3324e50333042b391312515e542279ca21f63dc8 plus shared CI prerequisite PR1295. New tooling, equations and documentation are independently authored under root MIT. No inferred unlicensed implementation is copied.
- Question: which byte strings reach the numeric state, how is its raw word classified by the next helper, and which immediate caller branches consume that classification?

The original Rust names/types and API association are unproved. Names in GNU's symbol-proximity annotations do not identify these functions. In particular, this packet does not assert a call-chain link to the previously studied snapshot workers. The node94 wire-asset codec packet is related background on another target, not proof of parity or new work credited here.

## Measured owners and input assumptions

| Role assigned by this packet | Actual FDE, original ELF VA, half-open | Bytes | Native rows |
| --- | --- | ---: | ---: |
| Byte-slice projection | 0x46aa760..0x46aab78 | 1048 | 269 |
| Numeric namespace / lookup helper | 0x46aa570..0x46aa753 | 483 | 116 |
| Caller A | 0x2c6fa00..0x2c6fdac | 940 | 178 |
| Caller B | 0x2c6fdb0..0x2c7015c | 940 | 178 |
| Total | Four complete FDE exports | 3411 | 741 |

These are export/binding denominators, not recovered-function coverage or four complete behavioral contracts. Every owner lies in a unique executable section. The producer checks full body bytes, FDE/CIE bytes, direct calls, RIP bindings and relevant actual relocations; readelf independently confirms the FDE extents. Original unnormalized native exports are retained. Filename spelling alone is replaced by <authenticated-node115>; no instruction operand or byte is masked. Native frame presentation is retained in frames.txt while comparison records use typed fields and raw frame bytes.

The projections assume readable finite byte slices with length below2^63, valid disjoint output/stack memory, and normally returning allocation/copy/comparison operations. Allocation/deallocation callbacks are additionally assumed to preserve unrelated live memory and callee-saved state on normal returns; their implementations are unclosed. Actual GLOB_DAT entries bind memcpy at0x64df508 and bcmp at0x64df9f8; the byte-copy/equality contracts are assumptions about those imports, not implementation or DSO-version proofs. The [GNU libc comparison documentation](https://sourceware.org/glibc/manual/2.27/html_node/String_002fArray-Comparison.html) documents bcmp as a memcmp alias. Allocation failure, exceptions and malformed pointers are not normal returns qualified here.

## Observed raw states

"Tag" in records/model output names only the observed low16-bit word; no original Rust enum or Result meaning is assigned.

| Byte slice | Low word | Selected numeric word at output+8 |
| --- | --- | --- |
| Exact nine-byte PURR/USDC | 0x1a2 | 0 |
| @ followed by canonical decimal n,1 <= n <100000000 | 0x1a2 | n |
| # followed by canonical decimal n,0 <= n <=2^64-1 | 0x1a2 | min(2^64-1,n+100000000) |
| Other slices, under normal allocation/copy | 0x68 | Not a numeric projection |

For the last state the input bytes are copied; two raw words at+8/+24 equal its byte length and the pointer is at+16. The empty case uses pointer word1 and length words0. These observations do not assign capacity/length fields in an original Rust layout or call this state an error.

The input is canonical ASCII decimal: one zero digit, or a nonzero first digit followed by digits, without a sign or leading zeros. The internal parser can skip an initial plus while accumulating, but its final comparison uses the original remainder pointer/length. Therefore #+1 reaches the copied-string state, rather than establishing plus-sign acceptance. A minus or non-digit also fails the numeric projection. Inputs longer than20 digits cannot equal a canonical u64 rendering even when accumulation of leading zeros would not overflow.

## Source phases and arithmetic proof

The following addresses anchor the manual relation in the complete retained native body:

- 0x46aa777..0x46aa7a4: empty and exact nine-byte shortcut; the immediate encodes PURR/USD and the final byte comparison is C.
- 0x46aa7a4..0x46aa7da and0x46aa889..0x46aa8e6: prefix/short forms, optional-plus adjustment, and the unchecked short digit loop. At most16 digits implies a value below10^16, so its multiply-by10/add arithmetic cannot overflow u64.
- 0x46aa9ba..0x46aa9fc: longer accumulation uses unsigned MUL's overflow condition and the ADD carry saved in DL, plus the unsigned digit-range check. These bound every admitted numeric value to u64.
- 0x46aa8e6: the @ zero guard.0x46aa8f5..0x46aaa2d renders the accumulated value into decimal groups.0x46aaa80..0x46aaaa6 compares original length/bytes against that rendering through bcmp.
- 0x46aaafe..0x46aab43: @ upper-bound selection and # unsigned addition/clamp. The SUB by sign-extended -100000000 takes the no-overflow result on borrow; otherwise ADD's carry selects all-one RAX. This is saturation, not wrapping.
- 0x46aa857/0x46aa872 and0x46aa804: common raw-state writes; other allocation/deallocation/failure paths remain conditional on the stated import/memory assumptions.

The 200-byte table at0x46ea12 is verified to contain all two-digit ASCII pairs00..99. Four integer certificates are extracted from actual native operands:

| Division relation | Multiplier | Shift | Input bound | M*D-2^s |
| --- | --- | ---: | --- | ---: |
| floor(x/10) | 0xcccccccccccccccd | 67 | u64 | 2 |
| floor(x/10000) | 0x346dc5d63886594b | 75 | u64 | 432 |
| floor(x/100) | 5243 | 19 | x <=9999 | 12 |
| floor(y/25) | 5243 | 17 | y <=249 | 3 |

For each row,0 <= e=M*D-2^s and N*e <2^s. Writing x=D*q+r gives x*M/2^s = x/D + x*e/(D*2^s); the extra fraction is below1/D and cannot cross the next integer. Thus these are all-domain floor-division proofs over their stated bounds, not exhaustive sampling claims. The final /100 path first takes y=floor(x/4); for x<=999, floor(y/25)=floor(x/100).

The /10000 remainder is formed with low32-bit multiply/subtract, but the true remainder is0..9999, so modular subtraction gives that exact remainder. Its two /100 pairs form each four-byte group. The loop's9999999 test leaves at most999 for the tail. At most20 digits occupy stack offsets+36..+55 inside the56-byte local allocation (saved registers are additional). The independent Python grouping equations reproduce Python's decimal spelling at power-of-ten/u64 boundaries and1000 deterministic full-width samples; the certificates, not those samples, establish the division domains.

## Namespace and immediate caller relation

Let B=100000000. At0x46aa583, raw words below B enter a context-dependent direct-index path. At or above B,0x46aa5c3..0x46aa5f5 computes q=floor((raw-B)/10) and r=(raw-B)%10. Only r=0 or1 continues into context-dependent table work; the selected offsets are0 or32. The table/search/predicate helpers and context values are unclosed, so these branches are not described as successful lookups.

For r=2..9, the selected path has no opaque call or context-memory read: it reaches XOR EAX,EAX at0x46aa71a and returns RDX=r. The claim assumes a valid stack and the captured code; it does not require a valid dereferenceable context on this particular path.

Both callers read the byte pointer/length from their input object's+8/+16 words, call0x46aa760, compare its low word to0x1a2, and call0x46aa570 with the numeric word and context+0x90. Their TEST AL,1/JZ sites are0x2c6fa57/0x2c6fa59 and0x2c6fe07/0x2c6fe09. On the immediate nonzero route they write low word0x1a2, qword1 at+8 and the helper's RDX at+16. The zero edges target0x2c6fd30 and0x2c700e0. Later opaque paths and terminal result types are not qualified.

Consequently every canonical # decimal n in [2^64-1-B,2^64-1] produces the numeric word2^64-1. Its namespace remainder is5, so these two callers take their named immediate zero edges. This does not establish a globally rejected request, a final error tag, an exploit or accepted asset identity; it closes the local saturation-to-gate relation without those unsupported claims.

## Reproduce and controls

macOS arm64/Python3.12.14/GNU readelf and objdump2.47.20260726 were used for the retained exports. The ELF is x86-64 data, never a launched program. From repo root with materialized inputs and GNU tools:

~~~sh
python3 -B tools/numeric_selector_static.py --output work/numeric-selector-check
python3 -B -m unittest discover -s tests -p test_numeric_selector_static.py -v
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-001-node115-numeric-selector && shasum -a 256 -c MANIFEST.sha256)
~~~

The public generator authenticates the entire capture before interpretation, native invocation or output creation. GNU reads private byte-identical snapshots. JSON comparison records contain typed geometry/raw bytes; native text rendering may vary between tool versions and is preserved separately. The producer is not an instruction interpreter and the integer model advances no captured PC/register/memory state.

Nine focused tests cover regeneration, the four division certificates and independent decimal fixtures, raw numeric/copied-string states, namespace residues, the saturation-to-zero-edge relation, and actual-byte counterfacts. Prefix, bound, paired addition, raw tag and zero-prefix/late-prefix changes alter a projected fact before rejection. Real multiplier/remainder operands change namespace routing; one real decimal-table byte changes the rendered1 and its canonicality result. A real JZ retarget changes the named edge. Additional controls corrupt actual CALL, GLOB_DAT symbol index, FDE extent and executable-section flag. Modified/truncated public inputs reject before native calls/output. Modified private snapshots are only statically inspected; they are not alternate admitted targets.

Full current-head CI is a separate pending result. The existing shared LLVM bootstrap repair is credited solely to PR1295, not again here. All original artifacts/imports/source pins and all component gates remain unchanged. No reconstructed Rust, complete original ABI, allocator/context/error/helper closure, captured native/Unicorn execution, live target service, signing, wallet, chain action or deployment is claimed. Next: close the context-dependent helpers and establish the callers' original source/type association before assigning protocol meaning.

Observed final focused validation: all9 tests passed in50.119s. The earlier development version passed9 tests in58.522s; subsequent changes separately retained native frame presentation and clarified extracted late-prefix/caller operands. Neither run is a full-suite claim.
