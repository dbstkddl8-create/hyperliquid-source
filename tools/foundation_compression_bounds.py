#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 compression-bound evidence packet.

Two leaf windows are locked:

* 0x546af50..0x546af6b returns 32 + n + floor(n / 6) for a 64-bit n
  (wrapping), the arithmetic of Snappy's MaxCompressedLength.
* 0x546e280..0x546e2ad returns 0 when the 32-bit input is above 0x7e000000
  as an unsigned value, else n + floor(n / 255) + 16, the arithmetic of the
  LZ4 C library's LZ4_compressBound / LZ4_COMPRESSBOUND.

The library names are inferences from the arithmetic, the shared callers and
the embedded Snappy/LZ4 strings; they are kept separate from the observations.
This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1

SNAPPY = {
    'start': 0x546af50, 'end': 0x546af6b, 'pad_end': 0x546af70,
    'body': bytes.fromhex('f30f1efa48b8abaaaaaaaaaaaaaa48f7e748c1ea02488d441720c3'),
    'fde_offset': 0x2be1a0,
    'fde': bytes.fromhex('10000000a4e12b0090b84c041b00000000000000'),
    'next_fde_offset': 0x2be1b4,
    'next_fde': bytes.fromhex('10000000b8e12b009cb84c04bb00000000000000'),
    'next_range': (0x546af70, 0x546b02b),
    'callers': [0x5081ae3, 0x5343c43, 0x546b097, 0x546c24f],
    # Instruction starts from linear decoding of the FDE (GNU objdump).
    'insn_starts': [0, 4, 14, 17, 21, 26],
}
LZ4 = {
    'start': 0x546e280, 'end': 0x546e2ad, 'pad_end': 0x546e2b0,
    'body': bytes.fromhex(
        'f30f1efa31c081ff0000007e771e4863c789fa4869c081808080c1fa1f48c1e8'
        '2001f8c1f80729d08d440710c3'),
    'fde_offset': 0x2be544,
    'fde': bytes.fromhex('1000000048e52b001ce84c042d00000000000000'),
    'next_fde_offset': 0x2be558,
    'next_fde': bytes.fromhex('140000005ce52b0038e84c0439000000005e0e10500e0800'),
    'next_range': (0x546e2b0, 0x546e2e9),
    'callers': [0x5081bcf, 0x5081ce0, 0x5343e07, 0x5343ec0, 0x5489260],
    'insn_starts': [0, 4, 6, 12, 14, 17, 19, 26, 29, 33, 35, 38, 40, 44],
}
# Shared CIE at .eh_frame+0 (zR, data alignment -8, return column 16).
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
# Callers that call both windows: the two compression dispatch FDEs.
SHARED_CALLER_FDES = [(0x50814d0, 0x5081fe5), (0x5343ab0, 0x53440f8)]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def snappy_bound(n):
    """Closed-form restatement of 0x546af50: 32 + n + n // 6, mod 2**64."""
    require(isinstance(n, int) and 0 <= n <= U64, 'Input must be a u64')
    return (32 + n + n // 6) & U64


def snappy_bound_insns(n):
    """Instruction-order restatement of 0x546af50 (mul, shr 2, lea)."""
    require(isinstance(n, int) and 0 <= n <= U64, 'Input must be a u64')
    rdx = (n * 0xaaaaaaaaaaaaaaab) >> 64      # mul %rdi: high half to RDX
    rdx >>= 2                                 # shr $0x2,%rdx
    return (n + rdx + 0x20) & U64             # lea 0x20(%rdi,%rdx,1),%rax


def lz4_bound(edi):
    """Closed-form restatement of 0x546e280 on the raw 32-bit EDI value.

    Returns the 32-bit EAX value. Inputs above 0x7e000000 as unsigned,
    which includes every negative int32, return 0.
    """
    require(isinstance(edi, int) and 0 <= edi <= U32, 'Input must be 32 bits')
    if edi > 0x7e000000:
        return 0
    return edi + edi // 255 + 16


def lz4_bound_insns(edi):
    """Instruction-order restatement of 0x546e280 (imul magic, sar, lea)."""
    require(isinstance(edi, int) and 0 <= edi <= U32, 'Input must be 32 bits')
    if edi > 0x7e000000:                      # cmp $0x7e000000,%edi; ja
        return 0                              # xor %eax,%eax
    s = edi - (1 << 32) if edi & 0x80000000 else edi   # movslq %edi,%rax
    prod = (s * -0x7f7f7f7f) & U64            # imul $0xffffffff80808081
    eax = (prod >> 32) & U32                  # shr $0x20,%rax (low 32 used)
    eax = (eax + edi) & U32                   # add %edi,%eax
    sx = eax - (1 << 32) if eax & 0x80000000 else eax
    eax = (sx >> 7) & U32                     # sar $0x7,%eax
    edx = U32 if edi & 0x80000000 else 0      # sar $0x1f,%edx
    eax = (eax - edx) & U32                   # sub %edx,%eax
    return (edi + eax + 0x10) & U32           # lea 0x10(%rdi,%rax,1),%eax


def magic_exactness():
    """Granlund-Montgomery error terms showing both divisions are exact."""
    e6 = 0xaaaaaaaaaaaaaaab * 6 - (1 << 66)
    e255 = 0x80808081 * 255 - (1 << 39)
    # n // 6 exact for every u64 when e6 <= 2**2; n // 255 exact for every
    # n with e255 * n < 2**39, which covers all of 0..0x7e000000.
    return {'div6_error': e6, 'div6_exact_all_u64': e6 <= 4,
            'div255_error': e255,
            'div255_exact_to': ((1 << 39) - 1) // e255,
            'div255_covers_admitted_range': e255 * 0x7e000000 < (1 << 39)}


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')

    def fde_range(offset):
        head = read(eh['address'] + offset, 16)
        require(struct.unpack_from('<I', head, 4)[0] == offset + 4,
                'FDE does not point at the shared CIE')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', head, 8)[0]
        return pc, pc + struct.unpack_from('<I', head, 12)[0]

    text = by_name['.text']
    code = read(text['address'], text['size'])

    def direct_calls(target):
        hits, pos = [], 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            rel = struct.unpack_from('<i', code, pos + 1)[0]
            if text['address'] + pos + 5 + rel == target:
                hits.append(text['address'] + pos)
            pos += 1
        return hits

    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rela = read(relsec['address'], relsec['size'])
    addends = {struct.unpack_from('<q', rela, off + 16)[0]
               for off in range(0, len(rela), 24)}

    result = {}
    for name, w in (('snappy', SNAPPY), ('lz4', LZ4)):
        body = read(w['start'], w['end'] - w['start'])
        require(body == w['body'], name + ' instruction window changed')
        for off, raw in ((w['fde_offset'], w['fde']),
                         (w['next_fde_offset'], w['next_fde'])):
            require(read(eh['address'] + off, len(raw)) == raw,
                    name + ' FDE record changed')
        require(fde_range(w['fde_offset']) == (w['start'], w['end']),
                name + ' FDE PC/range changed')
        require(fde_range(w['next_fde_offset']) == w['next_range'],
                name + ' next FDE PC/range changed')
        require(w['next_range'][0] == w['pad_end'], name + ' stride changed')
        require(read(w['end'], w['pad_end'] - w['end']) ==
                b'\xcc' * (w['pad_end'] - w['end']), name + ' padding changed')
        # No call, jmp or indirect-branch opcode at any instruction start;
        # the only control transfer is LZ4's short ja and each final ret.
        starts = w['insn_starts']
        require(starts[0] == 0 and body[starts[-1]] == 0xc3 and
                starts[-1] == len(body) - 1, name + ' instruction map changed')
        require(all(body[i] not in (0xe8, 0xe9, 0xeb, 0xff) for i in starts),
                name + ' unexpected call/jmp opcode in window')
        require(w['start'] not in addends, name + ' named by a relocation')
        callers = direct_calls(w['start'])
        require(callers == w['callers'], name + ' incoming direct calls changed')
        result[name] = {
            'window': (w['start'], w['end']),
            'body_sha256': hashlib.sha256(body).hexdigest(),
            'direct_callers': callers,
        }

    # Fixed-offset instruction locks (relative to each FDE start).
    s = read(SNAPPY['start'], SNAPPY['end'] - SNAPPY['start'])
    require(s[4:14] == bytes.fromhex('48b8abaaaaaaaaaaaaaa'), 'Divide-by-6 magic changed')
    require(s[14:17] == bytes.fromhex('48f7e7'), 'Unsigned mul changed')
    require(s[17:21] == bytes.fromhex('48c1ea02'), 'Post-shift changed')
    require(s[21:26] == bytes.fromhex('488d441720'), 'Add-32 lea changed')
    l = read(LZ4['start'], LZ4['end'] - LZ4['start'])
    require(l[6:12] == bytes.fromhex('81ff0000007e'), 'Input limit changed')
    require(l[12:14] == bytes.fromhex('771e'), 'Unsigned limit branch changed')
    require(LZ4['start'] + 12 + 2 + 0x1e == LZ4['start'] + 44,
            'Limit branch no longer lands on ret')
    require(l[19:26] == bytes.fromhex('4869c081808080'), 'Divide-by-255 magic changed')
    require(l[33:35] == bytes.fromhex('01f8'), 'Add-back changed')
    require(l[35:38] == bytes.fromhex('c1f807'), 'Post-shift changed')
    require(l[40:44] == bytes.fromhex('8d440710'), 'Add-16 lea changed')

    # Both windows are called from each of the two shared dispatch FDEs.
    for lo, hi in SHARED_CALLER_FDES:
        require(any(lo <= c < hi for c in result['snappy']['direct_callers']),
                'Shared caller lost the Snappy-bound call')
        require(any(lo <= c < hi for c in result['lz4']['direct_callers']),
                'Shared caller lost the LZ4-bound call')

    # Decoded-rule edges (restatements of retained bytes, not execution).
    for n in (0, 1, 5, 6, 7, 65536, U64 - 32, U64):
        require(snappy_bound(n) == snappy_bound_insns(n), 'Snappy rule drift')
    require(snappy_bound(0) == 32 and snappy_bound(6) == 39, 'Snappy edge changed')
    require(snappy_bound(65536) == 76490, 'Snappy block edge changed')
    for n in (0, 1, 254, 255, 256, 0x7dffffff, 0x7e000000, 0x7e000001,
              0x7fffffff, 0x80000000, U32):
        require(lz4_bound(n) == lz4_bound_insns(n), 'LZ4 rule drift')
    require(lz4_bound(0) == 16 and lz4_bound(255) == 272, 'LZ4 edge changed')
    require(lz4_bound(0x7e000000) == 0x7e7e7e8e, 'LZ4 limit edge changed')
    require(lz4_bound(0x7e000001) == 0 and lz4_bound(U32) == 0,
            'LZ4 rejection edge changed')
    m = magic_exactness()
    require(m['div6_exact_all_u64'] and m['div255_covers_admitted_range'],
            'Magic-number exactness bound changed')
    return result


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == SIZE, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 compression-bound '
                    'evidence packet.')
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['target_sha256'] == SHA256, 'Retained digest changed')
        for name in ('snappy', 'lz4'):
            r, w = retained['windows'][name], result[name]
            require(r['start_va'] == hex(w['window'][0]), 'Retained start changed')
            require(r['end_va_exclusive'] == hex(w['window'][1]), 'Retained end changed')
            require(r['sha256'] == w['body_sha256'], 'Retained body hash changed')
            require(r['e8_candidates'] == [hex(c) for c in w['direct_callers']],
                    'Retained callers changed')
        print('Foundation compression-bound evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
