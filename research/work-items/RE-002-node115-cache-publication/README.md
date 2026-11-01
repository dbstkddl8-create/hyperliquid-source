# RE-002: node115 three-word cache publication

- Component: foundation / runtime-cache provenance; partial static research, no gate.
- Target: node115,105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source/base: 6d727b9ea2ca4dc497c96a2de35cfba064e14dcc. New tooling/docs independently authored under root MIT; no inferred unlicensed code is copied.
- Question: how does the previously unresolved refresh helper publish cache words, and how does the stored first word relate to its raw RAX return?

## Observation and relation

[PR1014](https://github.com/lalalune/hyperliquid-source/pull/1014) already maps the cached selector and its initializer callers. Its unchanged spec is authenticated by SHA-256 d84ce3fb8f1d82bc498a34f4380d48201248c5006c5f6ef22d6cfd8152d2bcf4. This packet follows its refresh relocation0x64dfa68 to0x5cadd50 and closes the publication suffix. Feature names, collection of the raw feature words and complete detector semantics remain open.

One complete actual FDE0x5cadd50..0x5cae3da contains1,674 bytes/454 native instruction rows. Full unnormalized GNU output, body SHA-256 f4cc818ee02b994599bfc53910323d3edf8420d0b404c2e5060faab72524c349 and raw FDE/CIE records are retained. The next function starts at0x5cae3e0; alignment bytes are excluded. All coordinates are original ELF virtual addresses, half-open.

Let A be R13 and B be RDX on entry to suffix0x5cae39b, each an arbitrary raw u64. Let H=2^63. With valid writable cache memory and the retained data/call assumptions, the selected store values are:

~~~text
C0 = A | H
C1 = (((B << 1) mod 2^64) | (A >> 63)) | H
C2 = (B >> 62) | H
raw RAX return = A
~~~

The cache base comes from relocated slot0x64dfa60 ->0x6500098. The three stores use offsets0,8,16 in that order. Their24-byte selected footprint lies inside writable allocated .bss; complete Rust object extent/layout is unproved. Relocations, section metadata and code/RIP operands are checked. On-disk/NOBITS bytes are not runtime cache observations. Without interfering writes, these equations give the final three words.

For A=B=0, all three stored words equal H while the raw return equals0. For each bit below63, the first stored word preserves A's bit. In particular bits10,15,19,25 consumed by the prior selector are preserved; their CPU/ISA meanings remain unassigned.

## Static control certificate

The retained CFG has454 instruction nodes, direct conditional edges in both directions of each condition, one direct call and one RET. It contains no unresolved jump target. Edges must land on native instruction boundaries inside the complete body. Calls contribute only a conditional normal-return fallthrough; their actual execution is not performed.

A finite reaching-definition analysis tracks sets of possible definitions of RDI. Each unconditional MOVABS RDI,imm64 introduces that constant definition. Other possible RDI writes and the opaque call add an unknown definition while conservatively retaining prior definitions. Joins union sets. No concrete register, flag, feature or memory state is advanced; conditions are never evaluated.

At publication and at the selected RET, the only reaching RDI definitions are the exact H assignments at0x5cadd70,0x5cae251,0x5cae2f3. Removing publication from the CFG makes the RET unreachable from entry, so publication dominates this normal return. This is a structural overapproximation, not a claim that every CFG path is feasible or executed. The fixed suffix has no call or branch and pins all moves, ORs, stores, shift operands and the return transfer.

The prefix contains ten CPUID instructions and one direct call to the separately bounded, unmeasured FDE0x5cae3e0..0x5cae3ed. Its probe results, feature mapping and effects remain unqualified. No CPUID, XGETBV, captured function or concrete instruction interpreter is run by this producer or its focused tests.

## Lossless integer representation

Write L=H-1. The inverse over the proved representation is:

~~~text
A = (C0 & L) | ((C1 & 1) << 63)
B = ((C1 >> 1) & (2^62-1)) | ((C2 & 3) << 62)
~~~

C0 contributes A[0..62], C1 bit0 contributes A[63], C1 bits1..62 contribute B[0..61], and C2 bits0..1 contribute B[62..63]. Thus the inverse reconstructs every possible pair of raw u64 values. This is an integer identity for the extracted suffix; it establishes no reachability of every pair through the prefix.

The [Intel SDM SHLD reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf#page=613) grounds the cross-register bit transfer. With the captured64-bit operand/count1, the high bit of the source enters the low bit of the shifted destination. The resulting equations and partition proof are independently written.

## Reproduction and controls

macOS arm64; Python3.12.14; GNU readelf/objdump2.47.20260726. From repo root with materialized inputs/native GNU tools:

~~~sh
python3 -B tools/cache_publication_static.py --output work/cache-publication-check
python3 -B -m unittest discover -s tests -p test_cache_publication_static.py -v
make doctor verify catalogue-check reproduce
~~~

The producer authenticates the complete capture before interpretation, output or native calls. GNU reads private byte-identical snapshots. Actual FDE boundaries are independently confirmed by readelf. The original captures, old selector packet, source pins, runner policy and all gates remain unchanged.

Seven focused tests passed in7.746s, and safe make doctor verify catalogue-check reproduce passed. Native evidence regenerates byte-for-byte. A130-pair basis/edge set covers zero, all-one and each individual bit of both raw words; all cases round-trip and retain the selector's four low bits. This is equation testing, not target execution.

Actual operand counterfacts change SHLD count1->2, SHR count62->61 and store offset8->0; each changes an extracted store equation before rejection. Changing each actual H literal changes the reaching-definition certificate; a local zero-word equation then loses the required high marker. Retargeting the real early JMP to the epilogue makes publication fail to dominate RET. A branch into an operand is rejected. Additional controls corrupt actual call displacements, RELA addends, writable-region flags and FDE metadata. Modified/truncated/wrong-release public inputs reject before output/native analysis. Controlled modified ELFs are only disassembled for static negative controls.

## Limits and next question

No complete feature detector, CPU/ISA baseline, cryptographic algorithm, whole-prefix semantics, opaque helper, original source/ABI, runtime comparison or concurrency/atomic-publication guarantee is established. Other prefix/helper writes and exceptional behavior remain outside this local relation. All scope and reconstruction gates stay false. Rust implementation/two-build identity and hosted CI remain unmeasured.

Full make test, captured instruction evaluation and push/PR-triggered CI remain held by the operator's explicit choice. Results here qualify only the static producer, graph certificate and independent integer equations.

Next: map a reader of the second/third words and close the detector's feature/OS-state conditions before assigning feature names or generalizing the publication protocol.
