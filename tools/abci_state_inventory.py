#!/usr/bin/env python3
"""Static node #94 abci/state.rs evidence; Python 3.10+ stdlib only (MIT).

No captured executable is run. Unknown instruction encodings fail closed.
The ELF/FDE helpers are repository MIT tooling; reference text supplies search hints only.
"""
from __future__ import annotations
import argparse
import bisect
from collections import Counter
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import fde_extents

ROOT = TOOLS.parent
TARGET = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
REFERENCE_COMMIT = '999556f6e0a474b8312db96ec3149e1c44e97c23'
BASE_COMMIT = '391fe838467760eefc04072c0ea762a7a1155c78'
# Embedded compiler path in the target, never the analyst's local home.
PREFIX = bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f')
SCOPE = b'l1/src/abci/state.rs'
LEA_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
OUTPUTS = ('inventory.json', 'instructions.json')
# Catalogue seeds are leads, not validated source names or function boundaries.
SEEDS = (35685760, 35688032, 35689552, 36366496, 52897232, 52901904, 71611440, 71615248, 71752288, 71753808, 71755328, 72641440, 74246752, 74248240, 74249360, 74250640, 74251920)



class EvidenceError(ValueError):
    """Incomplete or inconsistent evidence is never silently accepted."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(sha(data) == SHA256, 'node #94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64, 'truncated ELF')
        require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 LE')
        require(struct.unpack_from('<HH', data, 16) == (3, 62), 'expected x86-64 ET_DYN')
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')
        self.by_name = {s['name']: s for s in self.sections}
        for name in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn', '.eh_frame', '.eh_frame_hdr'):
            require(name in self.by_name, f'missing section {name}')
        require(self.by_name['.text']['flags'] & 4, 'non-executable .text')
        for name in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn', '.eh_frame', '.eh_frame_hdr'):
            s = self.by_name[name]
            require(s['type'] != 8 and s['flags'] & 2 and s['size'] > 0,
                    f'required section is not allocated file-backed data: {name}')

    def mapping(self, va, size=1):
        require(size > 0 and va >= 0, 'invalid read range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'not one file-backed section for {va:#x}+{size}')
        s = matches[0]
        return s, s['offset'] + va - s['address']

    def read(self, va, size):
        _, off = self.mapping(va, size)
        return self.data[off:off + size]

    def section_bytes(self, name):
        s = self.by_name[name]
        return self.data[s['offset']:s['offset'] + s['size']]

    def evidence(self, va, size):
        s, off = self.mapping(va, size)
        return {'va': hex(va), 'file_offset': hex(off), 'section': s['name'],
                'bytes': self.read(va, size).hex()}


def relative_relocations(image):
    s = image.by_name['.rela.dyn']
    require(s['size'] % 24 == 0, 'truncated RELA section')
    result, seen = {}, set()
    for delta in range(0, s['size'], 24):
        pos = s['offset'] + delta
        slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
        require(slot not in seen, 'duplicate relocation slot')
        seen.add(slot)
        if info & 0xffffffff != 8:  # R_X86_64_RELATIVE
            continue
        require(info == 8 and addend >= 0, 'invalid RELATIVE symbol/addend')
        result[slot] = {'target': addend, 'entry_va': s['address'] + delta,
                        'entry_file_offset': pos,
                        'raw': image.data[pos:pos + 24].hex()}
    return result


def decode_location(image, slot, relocation):
    section, _ = image.mapping(slot, 24)
    require(section['name'] == '.data.rel.ro' and slot % 8 == 0, 'Location storage/alignment')
    pointer, length, line, column = struct.unpack('<QQII', image.read(slot, 24))
    require(pointer == 0, 'unexpected pre-relocation Location pointer')
    require(0 < length < 256 and 0 < line < 1000000 and 0 < column < 1000000,
            'invalid Location length/line/column')
    target = relocation['target']
    path_section, _ = image.mapping(target, length)
    require(path_section['name'] == '.rodata', 'Location path outside .rodata')
    path = image.read(target, length)
    require(path.startswith(PREFIX + SCOPE) and path.endswith(b'.rs') and b'\0' not in path,
            'Location path outside exact scope')
    relative = path[len(PREFIX):].decode('ascii')
    require(path == PREFIX + SCOPE, 'Location path differs from exact scope')
    return {**image.evidence(slot, 24), 'path': relative, 'path_bytes': image.evidence(target, length),
            'path_length': length, 'line': line, 'column': column,
            'relocation': {'entry_va': hex(relocation['entry_va']),
                           'entry_file_offset': hex(relocation['entry_file_offset']),
                           'type': 'R_X86_64_RELATIVE', 'addend': hex(target),
                           'bytes': relocation['raw']}}


def locations(image, relocations):
    ro = image.by_name['.rodata']
    result = {}
    prefix = PREFIX + SCOPE
    for slot, relocation in sorted(relocations.items()):
        target = relocation['target']
        if not (ro['address'] <= target <= ro['address'] + ro['size'] - len(prefix)):
            continue
        if image.read(target, len(prefix)) == prefix:
            # Every matching path relocation must be accounted for; malformed
            # records stop the census instead of silently reducing its count.
            result[slot] = decode_location(image, slot, relocation)
    return result


class Fdes:
    def __init__(self, image):
        summary, rows, _ = fde_extents(image.data)
        for key in ('unwind_start_differs_from_fde_start', 'duplicate_start', 'zero_length',
                    'starts_inside_earlier_extent', 'extent_crosses_section_end',
                    'fde_records_not_in_unwind_table', 'lsda_outside_gcc_except_table'):
            require(summary[key] == 0, f'ambiguous FDE inventory: {key}')
        self.rows = rows
        self.starts = [f['start'] for f in rows]

    def owner(self, va, size=1):
        require(size > 0, 'invalid FDE query size')
        i = bisect.bisect_right(self.starts, va) - 1
        if i >= 0 and va + size <= self.rows[i]['end']:
            return self.rows[i]
        return None

    @staticmethod
    def record(image, fde):
        def record_bytes(va):
            size = 4 + struct.unpack('<I', image.read(va, 4))[0]
            return image.evidence(va, size)
        hdr = image.by_name['.eh_frame_hdr']['address'] + 12 + 8 * fde['index']
        return {'start': hex(fde['start']), 'end_exclusive': hex(fde['end']),
                'size': fde['end'] - fde['start'], 'section': fde['section'],
                'code_sha256': sha(image.read(fde['start'], fde['end'] - fde['start'])),
                'fde_record': record_bytes(fde['fde']), 'cie_record': record_bytes(fde['cie']),
                'unwind_index': fde['index'], 'unwind_index_entry': image.evidence(hdr, 8)}


def decode_lea(raw, site):
    require(len(raw) == 7 and LEA_RE.fullmatch(raw[:3]) is not None, 'unsupported RIP LEA')
    register = ((raw[2] >> 3) & 7) + (8 if raw[0] & 4 else 0)
    displacement = struct.unpack_from('<i', raw, 3)[0]
    return site + 7 + displacement, register


def scan_leas(image, targets=None):
    """Candidates only; acceptance additionally requires FDE-start disassembly."""
    result = {}
    for s in image.sections:
        if not s['flags'] & 4 or s['type'] == 8:
            continue
        lower, upper = s['offset'], s['offset'] + s['size']
        for match in LEA_RE.finditer(image.data, lower, upper):
            offset = match.start()
            if offset + 7 <= upper:
                site = s['address'] + offset - lower
                target, _ = decode_lea(image.data[offset:offset + 7], site)
                if targets is None or target in targets:
                    result.setdefault(target, []).append(site)
    return result


def verified_lea(image, instructions, site, expected_target):
    matches = [x for x in instructions if x['site'] == site]
    require(len(matches) == 1, 'LEA candidate is inside another instruction or absent')
    insn = matches[0]
    target, register = decode_lea(insn['raw'], site)
    require(target == expected_target, 'LEA target/decode mismatch')
    require(insn['raw'] == image.read(site, 7), 'LEA bytes differ from input')
    return insn, register



def decode_instruction(code, offset=0, base=0):
    """Restricted legacy x86-64 length decoder, not a general disassembler.

    Decode sequentially from FDE entry; never resynchronize after an unknown
    opcode. ModRM/SIB/displacements and immediates are consumed, so opcode-like
    bytes inside operands cannot become anchors. Only enumerated forms pass.
    Operand semantics used for claims get a second exact decoder below.
    """
    require(0 <= offset < len(code), 'instruction offset outside input')
    start = offset
    def take(n):
        nonlocal offset
        require(offset + n <= len(code), 'truncated instruction')
        value = code[offset:offset+n]
        offset += n
        require(offset - start <= 15, 'overlong instruction')
        return value
    def byte():
        return take(1)[0]
    prefixes = []
    while offset < len(code) and code[offset] in (0x66, 0xf2, 0xf3, 0xf0, 0x2e, 0x64):
        p = byte()
        require(p not in prefixes or p == 0x66, 'duplicate legacy prefix')
        prefixes.append(p)
    require(not (0xf2 in prefixes and 0xf3 in prefixes), 'conflicting repeat prefixes')
    rex = 0
    if offset < len(code) and 0x40 <= code[offset] <= 0x4f:
        rex = byte()
    op = byte()
    operand = 2 if 0x66 in prefixes and not rex & 8 else 4
    kind, imm, modrm, group = 'other', 0, False, None
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        require(not prefixes and not rex, 'unsupported branch prefixes')
        kind = 'call_rel32' if op == 0xe8 else 'jmp_rel32' if op == 0xe9 else 'branch'
        imm = 4 if op in (0xe8, 0xe9) else 1
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else operand
        kind = 'mov_imm'
    elif 0xb0 <= op <= 0xb7:
        imm = 1
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc3, 0xcc, 0xc9, 0xfc):
        pass
    elif op in (0x68, 0x6a, 0xa8, 0xa9, 0xc2):
        imm = 2 if op == 0xc2 else 1 if op in (0x6a, 0xa8) else operand
    elif op in tuple(x + y for x in range(0, 0x40, 8) for y in range(4)) + (
            0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7,
            0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff):
        modrm = True
        if op in (0x69, 0x81, 0xc7): imm = operand
        if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6): imm = 1
        if op in (0x8f, 0xc6, 0xc7): group = {0}
        if op == 0xfe: group = {0, 1}
        if op == 0xff: group = {0, 1, 2, 4, 6}  # excludes far forms and reserved /7
        if op in (0xf6, 0xf7): group = {0, 2, 3, 4, 5, 6, 7}
        if op == 0x8d: kind = 'lea'
        if op == 0xc7: kind = 'mov_imm'
    elif op < 0x40 and op % 8 in (4, 5):
        imm = 1 if op % 8 == 4 else operand
    elif op == 0x0f:
        op2 = byte()
        if 0x80 <= op2 <= 0x8f:
            require(not prefixes and not rex, 'unsupported conditional branch prefixes')
            imm, kind = 4, 'branch'
        elif op2 == 0x0b:
            kind = 'ud2'
        elif 0xc8 <= op2 <= 0xcf:
            require(not prefixes, 'unsupported BSWAP prefixes')
        elif op2 in (0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29,
                     0x2a, 0x2c, 0x2d, 0x2e, 0x2f, 0x50, 0x51, 0x54, 0x55,
                     0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
                     0x5f, 0x60, 0x61, 0x62, 0x66, 0x6c, 0x6d, 0x6e, 0x6f,
                     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x7e, 0x7f,
                     0xa3, 0xa4, 0xa5, 0xab, 0xaf, 0xb0, 0xb1, 0xb3, 0xb6, 0xb7, 0xba,
                     0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc6,
                     0xd4, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef, 0xf3,
                     0xf4, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe) or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f:
            modrm = True
            if op2 in (0x70, 0x71, 0x72, 0x73, 0xa4, 0xba, 0xc2, 0xc6): imm = 1
            if op2 == 0x1f: group = {0}
            if op2 in (0x71, 0x72): group = {2, 4, 6}
            if op2 == 0x73: group = {2, 3, 6, 7}
            if op2 == 0xba: group = {4, 5, 6, 7}
        else:
            raise EvidenceError(f'unsupported 0f opcode {op2:02x}')
    else:
        raise EvidenceError(f'unsupported opcode {op:02x}')
    if modrm:
        m = byte()
        mod, reg, rm = m >> 6, (m >> 3) & 7, m & 7
        require(group is None or reg in group, 'unsupported ModRM group')
        if op == 0xff and reg in (2, 4):
            kind = 'call_indirect' if reg == 2 else 'jmp_indirect'
        require(op != 0x8d or mod != 3, 'register-source LEA is invalid')
        require(op != 0x0f or op2 != 0x13 or mod != 3, '0f13 requires memory destination')
        if op in (0xf6, 0xf7) and reg == 0: imm = 1 if op == 0xf6 else operand
        if mod != 3:
            if rm == 4:
                sib = byte()
                if mod == 0 and sib & 7 == 5: take(4)
            elif mod == 0 and rm == 5:
                take(4)
            if mod == 1: take(1)
            if mod == 2: take(4)
        if 0xf0 in prefixes:
            require(mod != 3 and (op in (0x01, 0x09, 0x21, 0x29, 0x31, 0x80, 0x81, 0x83, 0xff)
                    or op == 0x0f and op2 in (0xb0, 0xb1, 0xc0, 0xc1)), 'unsupported LOCK form')
    else:
        require(0xf0 not in prefixes, 'LOCK without memory operand')
    if 0xf0 in prefixes and op in (0x80, 0x81, 0x83):
        require(reg != 7, 'LOCK CMP is invalid')
    if 0xf0 in prefixes and op == 0xff:
        require(reg in (0, 1), 'unsupported LOCK FF group')
    if 0xf0 in prefixes:
        require(prefixes == [0xf0], 'unsupported combined LOCK prefixes')
    if op == 0x0f and op2 == 0x1f:
        require(all(p in (0x66, 0x2e) for p in prefixes), 'unsupported NOP prefixes')
    if op == 0x0f and op2 in (0x71, 0x72, 0x73, 0x50, 0xd7):
        require(mod == 3, 'SIMD encoding requires register operand')
    if op == 0x0f and op2 in (0x17,):
        require(mod != 3, 'SIMD encoding requires memory operand')
    if op == 0x0f and op2 in (0x6c, 0x6d, 0xd6):
        require(0x66 in prefixes, 'unsupported mandatory SIMD prefix')
    if prefixes.count(0x66) > 1 or 0x2e in prefixes:
        require(op == 0x0f and op2 == 0x1f and all(p in (0x66, 0x2e) for p in prefixes),
                'redundant prefixes only supported on NOP')
    if 0x64 in prefixes:
        fs_plain = prefixes == [0x64] and op in (0x8b, 0x89, 0x80, 0x83, 0x88, 0xc6, 0x0f, 0xff, 0x22)
        fs_vector = prefixes == [0x64, 0xf3] and op == 0x0f and op2 == 0x6f
        fs_word = prefixes == [0x64, 0x66] and not rex & 8 and op == 0xc7
        require(modrm and mod != 3 and (fs_plain or fs_vector or fs_word),
                'unsupported FS form')
    # Mandatory/segment prefixes are accepted only in enumerated combinations.
    # No REP arithmetic, conflicting SSE prefixes or guessed vector encodings.
    profile = {
        (0xf2,): {0x0fc2, 0x0f10, 0x0f11, 0x0f58, 0x0f70, 0x0f2a, 0x0f5e, 0x0f59, 0x0f5f, 0x0f5d, 0x0f2c, 0x0f5c},
        (0xf3,): {0x90, 0x0f11, 0x0f6f, 0x0f7f, 0x0f7e, 0x0fbc, 0x0fe6},
        (0x66,): {0x0f54, 0x0f55, 0x0f56, 0x3b, 0x0f13, 0x81, 0x83, 0xb8, 0xb9, 0xf7, 0x90, 0xc7, 0x89, 0x0f7f, 0x0f10, 0x0f29, 0x0f11,
                  0x0f7e, 0x0f6f, 0x0f28, 0x0f6e, 0x0f60, 0x0f70, 0x0f72, 0x0f73, 0x0f5c, 0x0f58, 0x0f5e, 0x0f15, 0x0fdf, 0x0fef, 0x0f6c, 0x0f6d, 0x0f62, 0x0fdb, 0x0feb, 0x0f74, 0x0fd7, 0x0f57, 0x0f2e, 0x0f1f, 0x0fd6, 0x0f12},
        (0x64,): {0x22, 0x80, 0xff, 0x89, 0x8b, 0x0fb6, 0xc6, 0x88},
        (0x64, 0xf3): {0x0f6f},
        (0x64, 0x66): {0xc7},
    }
    if prefixes and 0xf0 not in prefixes and not (op == 0x0f and op2 == 0x1f):
        opcode = 0x0f00 + op2 if op == 0x0f else op
        require(opcode in profile.get(tuple(prefixes), set()), 'unsupported prefix/opcode combination')
    take(imm)
    return {'site': base + start, 'raw': bytes(code[start:offset]), 'kind': kind}


def decode_fde(image, fde):
    code = image.read(fde['start'], fde['end'] - fde['start'])
    instructions, cursor = [], 0
    while cursor < len(code):
        try:
            insn = decode_instruction(code, cursor, fde['start'])
        except EvidenceError as exc:
            raise EvidenceError(f"FDE {fde['start']:#x} site {fde['start']+cursor:#x}: {exc}") from exc
        instructions.append(insn)
        cursor += len(insn['raw'])
    require(cursor == len(code), 'FDE decode did not end exactly')
    validate_branch_boundaries(instructions, fde['start'], fde['end'])
    return instructions

# Independently read from authenticated target bytes after reference-hint search.
# Finite diagnostic probes, not all literals. Generic helper/runtime text excluded.
DIAGNOSTICS = (
    'rmp', '@@ linked abci state @@', '@@ serialized abci state @@',
    '@@ successfully translated abci state',
    'exchange', '/dev/null',
    'assertion failed: freeze_height >= self.locus.context.height()',
)
REFERENCE_PATH = 'references/can1357-hl/l1/abci/state.rs'
REFERENCE_SHA256 = 'c68433ea732dea69896eca896e216a54d7325baa916bd9a4552e9512ce505794'


def diagnostic_probes():
    raw = (ROOT/REFERENCE_PATH).read_bytes()
    require(sha(raw) == REFERENCE_SHA256, 'reference lead file SHA-256 mismatch')
    result = [{'id': f'binary-literal-{i+1}', 'probe': text,
               'needle': text.encode('ascii'), 'origin': 'authenticated target bytes'}
              for i, text in enumerate(DIAGNOSTICS)]
    # These three unlicensed reference-only strings are read as search hints;
    # neither their text nor their source code is copied into this packet.
    for line in (119, 165, 497):
        row = raw.splitlines()[line-1]
        tokens = re.findall(rb'"([^"\n]*)"', row)
        require(len(tokens) == 1, 'reference-only probe extraction differs')
        result.append({'id': f'reference-line-{line}', 'probe': f'reference-line-{line} (hash only)',
                       'reference_line': line, 'needle': tokens[0],
                       'origin': 'unlicensed reference search hint; no text retained'})
    return result


def instruction_evidence(image, insn):
    require(insn['raw'] == image.read(insn['site'], len(insn['raw'])), 'instruction evidence differs from input')
    decoded = decode_instruction(insn['raw'], base=insn['site'])
    require(decoded == insn, 'instruction metadata differs from byte decoder')
    result = {**image.evidence(insn['site'], len(insn['raw'])), 'kind': insn['kind']}
    if insn['kind'] in ('call_rel32', 'jmp_rel32'):
        result['target'] = hex(decode_rel32_transfer(insn['raw'], insn['site']))
    if len(insn['raw']) == 6 and insn['raw'][:2] in (b'\xff\x15', b'\xff\x25'):
        result['indirect_pointer_slot'] = hex(insn['site'] + 6 + struct.unpack_from('<i', insn['raw'], 2)[0])
        result['callee'] = 'unresolved; slot not dereferenced'
    return result


def decode_rel32_transfer(raw, site):
    require(len(raw) == 5 and raw[0] in (0xe8, 0xe9), 'not E8/E9 rel32')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_mov_immediate(raw):
    """B8+r imm32 (optional REX without W), or REX.W C7 /0 sign-extended imm32."""
    i, rex = 0, 0
    if raw and 0x40 <= raw[0] <= 0x4f:
        rex, i = raw[0], 1
    require(i < len(raw), 'truncated immediate MOV')
    if 0xb8 <= raw[i] <= 0xbf:
        require(not rex & 8 and len(raw) == i + 5, 'not register imm32 MOV')
        return {'register': raw[i] - 0xb8 + (8 if rex & 1 else 0),
                'value': struct.unpack_from('<I', raw, i+1)[0], 'width': 32}
    require(rex & 8 and raw[i] == 0xc7 and len(raw) >= i + 6, 'not qword immediate MOV')
    require(raw[i+1] >> 3 & 7 == 0, 'not C7 /0')
    if raw[i+1] >> 6 == 3:
        require(len(raw) == i + 6, 'overlong immediate MOV')
        return {'register': (raw[i+1] & 7) + (8 if rex & 1 else 0),
                'value': struct.unpack_from('<i', raw, i+2)[0], 'width': 64}
    memory, end = decode_base_memory(raw, i+1, rex)
    require(end + 4 == len(raw), 'qword MOV trailing/truncated bytes')
    return {'memory': memory, 'value': struct.unpack_from('<i', raw, end)[0], 'width': 64}


def decode_base_memory(raw, i, rex):
    """Only base+signed displacement, with optional no-index SIB. No RIP/index."""
    require(i < len(raw), 'missing ModRM')
    mod, rm = raw[i] >> 6, raw[i] & 7
    require(mod in (0, 1, 2), 'not memory operand')
    i += 1
    if rm == 4:
        require(i < len(raw), 'missing SIB')
        sib = raw[i]; i += 1
        require(sib >> 3 & 7 == 4 and not rex & 2 and sib >> 6 == 0, 'indexed/scaled memory not accepted')
        rm = sib & 7
    require(not (mod == 0 and rm == 5), 'RIP/no-base memory not accepted')
    width = {0: 0, 1: 1, 2: 4}[mod]
    require(i + width <= len(raw), 'truncated displacement')
    disp = int.from_bytes(raw[i:i+width], 'little', signed=True) if width else 0
    return {'base_register': rm + (8 if rex & 1 else 0), 'displacement': disp}, i + width


def decode_pointer_store(raw):
    require(len(raw) >= 3 and 0x48 <= raw[0] <= 0x4f and raw[1] == 0x89,
            'not qword register store')
    memory, end = decode_base_memory(raw, 2, raw[0])
    require(end == len(raw), 'store trailing bytes')
    return memory, (raw[2] >> 3 & 7) + (8 if raw[0] & 4 else 0)


def decode_register_move(raw):
    """Exact REX.W 89 /r register move; return destination and source."""
    require(len(raw) == 3 and raw[0] in (0x48, 0x49, 0x4c, 0x4d)
            and raw[1] == 0x89 and raw[2] >> 6 == 3, 'not qword register move')
    return ((raw[2] & 7) + (8 if raw[0] & 1 else 0),
            (raw[2] >> 3 & 7) + (8 if raw[0] & 4 else 0))


def pointer_length_pair(image, insns, index, literal):
    first = insns[index]
    for previous, current in zip(insns[index:index+7], insns[index+1:index+8]):
        require(current['site'] == previous['site']+len(previous['raw']), 'noncontiguous literal setup')
    target, reg = decode_lea(first['raw'], first['site'])
    require(image.read(target, len(literal)) == literal, 'literal mismatch')
    require(index + 2 < len(insns), 'truncated pointer/length sequence')
    following = insns[index+1]
    # Adjacent fields: store pointer register, then store qword length at +8.
    if len(following['raw']) >= 2 and following['raw'][1] == 0x89:
        memory, source = decode_pointer_store(following['raw'])
        length = decode_mov_immediate(insns[index+2]['raw'])
        require(source == reg, 'stored register differs from LEA')
        require(length.get('memory') == {**memory, 'displacement': memory['displacement'] + 8},
                'length is not adjacent to pointer')
        require(length['value'] == len(literal), 'stored length differs from probe')
        return {'kind': 'adjacent_pointer_length_fields', 'length': len(literal),
                'pointer_field': memory, 'setup': [instruction_evidence(image, x) for x in insns[index:index+3]]}
    # Only a short contiguous setup, without control transfer or clobber, passes.
    # A setup may initialize a second independent pointer/length register pair.
    # These are register-byte facts, not recovered ABI parameter roles.
    length_reg = {1: 8, 2: 1, 6: 2, 7: 6, 8: 9}.get(reg)
    require(length_reg is not None, 'unsupported pointer/length register pair')
    seen_length = False
    writes = {reg}
    for j in range(index+1, min(index+8, len(insns))):
        x, raw = insns[j], insns[j]['raw']
        if x['kind'] == 'call_rel32' or len(raw) == 6 and raw[:2] == b'\xff\x15':
            require(seen_length, 'call before matching length')
            setup = insns[index:j+1]
            return {'kind': 'register_pointer_length_pair', 'length': len(literal),
                    'pointer_register': reg, 'length_register': length_reg,
                    'setup': [instruction_evidence(image, t) for t in setup]}
        # MOVSD xmm, [RIP+disp32] writes only an XMM register. This exact
        # target-observed form cannot overwrite either integer argument.
        if len(raw) == 8 and raw[:3] == b'\xf2\x0f\x10' and raw[3] & 0xc7 == 5:
            continue
        if x['kind'] == 'lea':
            if len(raw) == 7 and LEA_RE.fullmatch(raw[:3]):
                _, dest = decode_lea(raw, x['site'])
            else:
                require(len(raw) >= 3 and raw[0] in (0x48, 0x4c) and raw[1] == 0x8d,
                        'unsupported intervening LEA')
                _, end = decode_base_memory(raw, 2, raw[0])
                require(end == len(raw), 'intervening LEA length')
                dest = (raw[2] >> 3 & 7) + (8 if raw[0] & 4 else 0)
            require(dest != length_reg, 'intervening LEA clobbers length')
        elif len(raw) == 3 and raw[0] in (0x48, 0x49, 0x4c, 0x4d) and raw[1] == 0x89 and raw[2] >> 6 == 3:
            dest, _ = decode_register_move(raw)
            require(dest != length_reg, 'register move clobbers length')
        else:
            immediate = decode_mov_immediate(raw)
            require('register' in immediate, 'intervening memory write')
            dest = immediate['register']
            if dest == length_reg:
                require(immediate['value'] == len(literal), 'register length differs from probe')
                seen_length = True
        require(dest not in writes, 'literal setup clobbers register')
        writes.add(dest)
    raise EvidenceError('no call within bounded register pair setup')


def counted_fragment(image, anchor, occurrence, probe):
    """Prove a bounded byte pattern, not a formatter grammar or rendered log.

    From the LEA target traverse at most four (u8 length, ASCII bytes, C0)
    chunks, retaining each byte. Accept only a probe wholly within one chunk.
    Stop at the probe's chunk; do not interpret placeholders or later bytes.
    """
    cursor, chunks = anchor, []
    if image.read(cursor, 1) == b'\xc0':
        cursor += 1  # Explicit initial marker; no grammar/argument semantics.
    for _ in range(4):
        n = image.read(cursor, 1)[0]
        require(0 < n < 128, 'zero terminator or counted chunk length outside bounded grammar')
        text = image.read(cursor+1, n) if n else b''
        require(all(32 <= b < 127 or b in (9, 10, 13) for b in text), 'non-ASCII counted chunk')
        require(image.read(cursor+1+n, 1) == b'\xc0', 'counted chunk lacks C0 marker')
        chunks.append({'length': n, 'text': text.decode('ascii'), 'record': image.evidence(cursor, n+2)})
        if cursor+1 <= occurrence and occurrence+len(probe) <= cursor+1+n:
            require(text[occurrence-cursor-1:occurrence-cursor-1+len(probe)] == probe, 'probe differs within chunk')
            return {'kind': 'counted_ascii_chunks', 'chunks': chunks,
                    'probe_offset_in_last_chunk': occurrence-cursor-1,
                    'length': n, 'pattern': image.evidence(anchor, cursor+n+2-anchor)}
        cursor += n+2
    raise EvidenceError('probe outside bounded counted chunks')


def occurrences(image, needle):
    # Whole-file exact bytes, then section mapping; absence is not inferred from
    # absence of code xrefs. The entire binary is already authenticated.
    pos, result = -1, []
    while (pos := image.data.find(needle, pos+1)) >= 0:
        matches = [s for s in image.sections if s['type'] != 8
                   and s['offset'] <= pos and pos+len(needle) <= s['offset']+s['size']]
        require(len(matches) == 1, 'literal has ambiguous/no section mapping')
        s = matches[0]
        result.append({'va': hex(s['address']+pos-s['offset']), 'file_offset': hex(pos),
                       'section': s['name'], 'bytes': needle.hex()})
    return result


def diagnostic_inventory(image, decoded):
    leas = []
    for start, insns in sorted(decoded.items()):
        for i, x in enumerate(insns):
            if len(x['raw']) == 7 and LEA_RE.fullmatch(x['raw'][:3]):
                a, _ = decode_lea(x['raw'], x['site'])
                leas.append((a, start, i))
    result = []
    for spec in diagnostic_probes():
        probe = spec['needle']
        hits, anchors, rejected = occurrences(image, probe), [], []
        for hit in hits:
            if hit['section'] != '.rodata': continue
            occurrence = int(hit['va'], 16)
            for anchor, start, i in leas:
                if not 0 <= occurrence - anchor <= 128:
                    continue
                insns = decoded[start]
                row = {'owner': hex(start), 'occurrence': hex(occurrence), 'anchor': hex(anchor),
                       'lea': instruction_evidence(image, insns[i])}
                try:
                    proof = (pointer_length_pair(image, insns, i, probe) if occurrence == anchor
                             else counted_fragment(image, anchor, occurrence, probe))
                except EvidenceError as exc:
                    rejected.append({**row, 'reason': str(exc),
                                     'following_instructions': [instruction_evidence(image, x) for x in insns[i+1:i+6]]})
                else:
                    anchors.append({**row, **proof})
        result.append({**{k: v for k, v in spec.items() if k != 'needle'},
                       'probe_sha256': sha(probe), 'probe_length': len(probe), 'status': 'bound' if anchors else 'present-but-unbound' if hits else 'absent',
                       'occurrences': hits, 'anchors': anchors, 'rejected_candidates': rejected})
    return result


def first_party_attribution(image, decoded, relocations):
    """Account for foreign Location references in scoped ranges, not ownership."""
    result = {}
    ro = image.by_name['.rodata']
    for start, insns in sorted(decoded.items()):
        refs = []
        for insn in insns:
            if len(insn['raw']) != 7 or not LEA_RE.fullmatch(insn['raw'][:3]):
                continue
            slot, _ = decode_lea(insn['raw'], insn['site'])
            relocation = relocations.get(slot)
            if relocation is None: continue
            target = relocation['target']
            if not ro['address'] <= target <= ro['address']+ro['size']-len(PREFIX): continue
            if image.read(target, len(PREFIX)) != PREFIX: continue
            section, _ = image.mapping(slot, 24)
            require(section['name'] == '.data.rel.ro' and slot % 8 == 0,
                    'first-party Location storage/alignment')
            pointer, length, line, column = struct.unpack('<QQII', image.read(slot, 24))
            require(pointer == 0 and len(PREFIX) < length < 256 and 0 < line < 1000000
                    and 0 < column < 1000000, 'malformed first-party Location')
            path = image.read(target, length)
            require(path.endswith(b'.rs') and b'\0' not in path, 'invalid first-party path')
            refs.append({'path': path[len(PREFIX):].decode('ascii'), 'location': hex(slot),
                         'line': line, 'column': column,
                         'lea': instruction_evidence(image, insn),
                         'record': image.evidence(slot, 24),
                         'path_bytes': image.evidence(target, length),
                         'relocation_bytes': relocation['raw']})
        paths = sorted({r['path'] for r in refs})
        require(SCOPE.decode() in paths, 'scope attribution missing')
        result[start] = {'first_party_paths': paths,
                         'only_exact_file_locations_observed': paths == [SCOPE.decode()],
                         'location_references': refs}
    return result


def constant_setup(image, insns, index, value):
    """EDX imm32 followed by at most one non-clobbering register move and CALL.

    This binds an operand, never a copy length, enum tag or helper behavior.
    """
    first = insns[index]
    require(decode_mov_immediate(first['raw']) == {'register': 2, 'value': value, 'width': 32},
            'constant is not expected EDX imm32')
    setup = [first]
    for x in insns[index+1:index+3]:
        require(x['site'] == setup[-1]['site']+len(setup[-1]['raw']), 'noncontiguous constant setup')
        setup.append(x)
        raw = x['raw']
        if raw[:2] == b'\xff\x15' and len(raw) == 6 or raw in (b'\xff\xd3', b'\x41\xff\xd5'):
            require(x['kind'] == 'call_indirect', 'constant transfer is not CALL')
            return {'setup': [instruction_evidence(image, y) for y in setup],
                    'value': value, 'register': 2, 'width': 32,
                    'meaning': 'EDX immediate before CALL; callee and value role unresolved'}
        dest, _ = decode_register_move(raw)
        require(dest not in (2, 3, 13), 'constant setup clobbers argument or call register')
    raise EvidenceError('no supported call after immediate')


def constant_inventory(image, decoded, attribution):
    result = []
    # Numeric hints only, independently qualified as instruction operands.
    for value, line in ((0x810, 39), (0x3ae8, 40), (0x1fb8, 41)):
        anchors, unresolved = [], []
        for start, insns in sorted(decoded.items()):
            for i, x in enumerate(insns):
                if x['kind'] != 'mov_imm': continue
                try: immediate = decode_mov_immediate(x['raw'])
                except EvidenceError: continue
                if immediate.get('register') != 2 or immediate['value'] != value: continue
                row = {'owner': hex(start), 'instruction': instruction_evidence(image, x)}
                try:
                    require(attribution[start]['only_exact_file_locations_observed'],
                            'shared FDE: other first-party Location paths present')
                    proof = constant_setup(image, insns, i, value)
                except EvidenceError as exc:
                    unresolved.append({**row, 'reason': str(exc)})
                else:
                    anchors.append({**row, **proof})
        result.append({'candidate': f'EDX operand {value:#x}', 'reference_line': line,
                       'status': 'bound' if anchors else 'unresolved',
                       'value': value if anchors else None, 'anchors': anchors,
                       'unresolved_occurrences': unresolved,
                       'semantic_name_and_units': 'unresolved',
                       'claim': 'Numeric instruction operand only; reference size/layout roles not validated'})
    for line, role in ((35, 'candidate response tag'), (36, 'success tag'),
                       (37, 'missing-state tag'), (38, 'mismatch tag'),
                       (42, 'freeze option tag offset'), (43, 'freeze option value offset'),
                       (44, 'height offset'), (45, 'first serialized field offset'),
                       (46, 'second serialized field offset')):
        result.append({'candidate': role, 'reference_line': line, 'status': 'unresolved',
                       'value': None, 'anchors': [], 'semantic_name_and_units': 'unresolved',
                       'reason': 'No unique decoded dataflow tie to the suggested role; numeric matches alone insufficient'})
    return result


def decode_base_lea(raw):
    require(len(raw) >= 3 and raw[0] in (0x48, 0x49, 0x4c, 0x4d) and raw[1] == 0x8d,
            'unsupported base LEA')
    memory, end = decode_base_memory(raw, 2, raw[0])
    require(end == len(raw), 'base LEA trailing bytes')
    return (raw[2] >> 3 & 7) + (8 if raw[0] & 4 else 0), memory


def decode_register_add(raw):
    require(len(raw) == 7 and raw[0] in (0x48, 0x49) and raw[1] == 0x81
            and raw[2] & 0xf8 == 0xc0, 'not ADD r64, imm32')
    return (raw[2] & 7)+(8 if raw[0] & 1 else 0), struct.unpack_from('<i', raw, 3)[0]


def source_setup(image, insns, index):
    """Short source-address setup around an EDX=0x810 use, no source type inferred."""
    require(index >= 3, 'short source setup')
    constant = constant_setup(image, insns, index, 0x810)
    for previous, current in zip(insns[index-3:index+2], insns[index-2:index+3]):
        require(current['site'] == previous['site']+len(previous['raw']), 'noncontiguous source setup')
    # LEA RSI,[base+disp], followed only by destination-address LEA and,
    # optionally, a RIP load of the independent call register (RBX or R13).
    for begin in (index-2, index-3):
        try: dest, mem = decode_base_lea(insns[begin]['raw'])
        except EvidenceError: continue
        if dest != 6: continue
        for x in insns[begin+1:index]:
            raw = x['raw']
            if len(raw) == 7 and raw[:3] in (b'\x48\x8b\x1d', b'\x4c\x8b\x2d'):
                call_register = 3 if raw[0] == 0x48 else 13
                require(call_register != mem['base_register'], 'call load clobbers source base')
                expected_call = 'ffd3' if call_register == 3 else '41ffd5'
                require(constant['setup'][-1]['bytes'] == expected_call, 'loaded register differs from call register')
            else:
                dst, _ = decode_base_lea(raw)
                require(dst in (7, 14) and dst != mem['base_register'], 'unexpected source setup write')
        tail = [bytes.fromhex(x['bytes']) for x in constant['setup'][1:-1]]
        require(not tail or tail == [b'\x4c\x89\xf7'], 'source RSI clobber')
        return {**mem, 'address_form': 'LEA RSI, [base+displacement]',
                'instructions': [instruction_evidence(image, x) for x in insns[begin:index]] + constant['setup']}
    # Third setup adds the displacement to the original base, then copies it
    # into RSI. An independent RDI LEA and EDX immediate are the only gap.
    reg, displacement = decode_register_add(insns[index-2]['raw'])
    dest, memory = decode_base_lea(insns[index-1]['raw'])
    require(dest == 7 and memory['base_register'] != reg, 'unexpected third destination setup')
    require(decode_register_move(insns[index+1]['raw']) == (6, reg), 'source ADD not passed into RSI')
    return {'base_register': reg, 'displacement': displacement,
            'address_form': 'ADD base, displacement; MOV RSI, base',
            'instructions': [instruction_evidence(image, x) for x in insns[index-2:index]] + constant['setup']}


def source_triplets(image, decoded, constants):
    result = []
    for start, insns in sorted(decoded.items()):
        anchors = [a for a in constants[0]['anchors'] if a['owner'] == hex(start)]
        if not anchors: continue
        require(len(anchors) == 3, 'size operand triplet count differs')
        rows = []
        for a in anchors:
            index = next(i for i, x in enumerate(insns) if x['site'] == int(a['instruction']['va'], 16))
            rows.append(source_setup(image, insns, index))
        require(len({r['base_register'] for r in rows}) == 1, 'triplet source bases differ')
        result.append({'owner': hex(start), 'edx_value': 0x810, 'sources': rows,
                       'source_displacements': [hex(r['displacement']) for r in rows],
                       'claim': 'Local address setup only. No object identity, copy semantics, fields or callee closure.'})
    return result


LOADER_PACKET = 'research/work-items/RE-019-rmp-json-loader-94/rmp-json-loader.json'
LOADER = 0x3c155a0


def scoped_edges(image, decoded, named=None):
    named = named or {}
    result = []
    for start, insns in sorted(decoded.items()):
        for i, insn in enumerate(insns):
            if insn['kind'] not in ('call_rel32', 'jmp_rel32'): continue
            proof = instruction_evidence(image, insn)
            target = decode_rel32_transfer(insn['raw'], insn['site'])
            if target in decoded or target in named:
                result.append({'caller': hex(start), 'callee': hex(target),
                               'callee_scope': 'scoped_fde' if target in decoded else 'previously_named_callee',
                               'prior_packet': named.get(target), 'instruction': proof,
                               'preceding_context': [instruction_evidence(image, x) for x in insns[max(0,i-3):i]],
                               'signed_displacement': struct.unpack_from('<i', insn['raw'], 1)[0],
                               'next_instruction': hex(insn['site']+5)})
    return result



def validate_branch_boundaries(insns, start, end):
    boundaries = {x['site'] for x in insns}
    for insn in insns:
        raw, site = insn['raw'], insn['site']
        if insn['kind'] in ('call_rel32', 'jmp_rel32'):
            target = decode_rel32_transfer(raw, site)
        elif insn['kind'] == 'branch':
            displacement = int.from_bytes(raw[2:] if raw[0] == 0x0f else raw[1:], 'little', signed=True)
            target = site+len(raw)+displacement
        else:
            continue
        if start <= target < end:
            require(target in boundaries, 'internal branch lands inside an instruction')


def metric_table(metrics):
    """Shared derived report block; verifier/tests reject stale documentation."""
    return ('<!-- BEGIN GENERATED METRICS -->\n'
            '| Metric | Count |\n| --- | ---: |\n' +
            ''.join(f'| {key} | {value} |\n' for key, value in sorted(metrics.items())) +
            '<!-- END GENERATED METRICS -->')


def evidence_tables(evidence):
    """Report facts derive exclusively from the regenerated evidence object."""
    def table(tag, columns, rows):
        return (f'<!-- BEGIN GENERATED {tag} -->\n| ' + ' | '.join(columns) + ' |\n| ' +
                ' | '.join('---' for _ in columns) + ' |\n' +
                ''.join('| ' + ' | '.join(str(v) for v in row) + ' |\n' for row in rows) +
                f'<!-- END GENERATED {tag} -->')
    return {
        'METRICS': metric_table(evidence['metrics']),
        'LOCATIONS': table('LOCATIONS', ['Location VA', 'Line:column', 'LEA sites', 'Owning FDE starts'],
                           [(x['va'], f"{x['line']}:{x['column']}", ', '.join(x['lea_sites']),
                             ', '.join(x['owning_fdes'])) for x in evidence['locations']]),
        'FDES': table('FDES', ['Start VA', 'End exclusive', 'Bytes', 'FDE record VA', 'First-party path count'],
                     [(f['start'], f['end_exclusive'], f['size'], f['fde_record']['va'], len(f['first_party_paths'])) for f in evidence['fdes']]),
        'LITERALS': table('LITERALS', ['Candidate', 'Status', 'Bytes', 'Occurrences', 'Bindings'],
                         [(d.get('probe', d['id']), d['status'], d['probe_length'],
                           len(d['occurrences']), len(d['anchors'])) for d in evidence['diagnostics']]),
        'ANCHORS': table('ANCHORS', ['Candidate', 'FDE start', 'LEA VA', 'Literal VA', 'Length', 'Proof'],
                         [(d['probe'], a['owner'], a['lea']['va'], a['anchor'], a['length'], a['kind'])
                          for d in evidence['diagnostics'] for a in d['anchors']]),
        'ATTRIBUTION': table('ATTRIBUTION', ['FDE', 'First-party Location paths'],
                             [(f['start'], ', '.join(f['first_party_paths'])) for f in evidence['fdes']
                              if len(f['first_party_paths']) > 1]),
        'EDGES': table('EDGES', ['Caller FDE', 'Call VA', 'Raw E8 rel32', 'Signed displacement', 'Callee FDE'],
                      [(e['caller'], e['instruction']['va'], e['instruction']['bytes'],
                        e['signed_displacement'], e['callee']) for e in evidence['call_edges']]),
        'TRIPLETS': table('TRIPLETS', ['FDE', 'EDX operand', 'RSI source displacements'],
                          [(r['owner'], hex(r['edx_value']), ', '.join(r['source_displacements']))
                           for r in evidence['source_setup_triplets']]),
        'CONSTANTS': table('CONSTANTS', ['Candidate', 'Status', 'Numeric operand established'],
                          [(c['candidate'], c['status'], 'none' if c['value'] is None else c['value'])
                           for c in evidence['constants']]),
    }



def prior_work(scoped, image, fdes):
    result = []
    def read(path):
        raw = (ROOT/path).read_bytes()
        data = json.loads(raw)
        require(data.get('binary_sha256', data.get('sha256', data.get('target_sha256'))) == SHA256,
                'prior work target digest differs')
        return data, {'path': path, 'sha256': sha(raw)}
    path = 'research/work-items/RE-009-storage-state-roots/state-roots.json'
    data, record = read(path)
    shared = []
    for f in data['functions']:
        start = int(f['start'], 16)
        if start in scoped:
            require(scoped[start]['end'] == int(f['end'], 16), 'RE-009 shared range differs')
            shared.append({'start': f['start'], 'end_exclusive': f['end']})
    require({int(r['start'],16) for r in shared} == set(scoped), 'RE-009 range intersection incomplete')
    result.append({**record, 'shared_ranges': shared,
                   'relationship': 'Existing census and range attribution, including unseeded ranges; not new discoveries. This packet adds sequential byte decoding and length-bearing/local setup qualification.'})
    path = 'research/work-items/RE-017-abci-state-link-94/abci-state-link.json'
    data, record = read(path)
    f = data['fn_fde']; start, end = int(f['start'], 16), int(f['end'], 16)
    require(scoped[start]['end'] == end and sha(image.read(start, end-start)) == data['fn_bytes_sha256'],
            'RE-017 shared body differs')
    result.append({**record, 'shared_ranges': [f],
                   'relationship': 'Existing :66 -> :107 GOT link to materializer slot; not re-claimed or included in rel32 edge totals.'})
    data, record = read(LOADER_PACKET)
    start, end = int(data['function'], 16), int(data['function_end'], 16)
    callee = fdes.owner(start)
    require(start == LOADER and callee['start'] == start and callee['end'] == end,
            'RE-019 callee extent differs')
    require(sha(image.read(start, end-start)) == data['extent_sha256'], 'RE-019 callee body differs')
    result.append({**record, 'relationship': 'Existing loader name and three caller sites; instruction boundary revalidation only, no new loader semantics.',
                   'prior_caller_sites': data['callers']})
    named = [{**Fdes.record(image, callee), 'prior_packet': LOADER_PACKET,
              'prior_label': 'RE-019 rmp/json path loader', 'new_body_analysis': False}]
    path = 'research/work-items/local-abci-gates-94/records.json'
    data, record = read(path)
    require(int(data['callers']['caller_fde'], 16) in scoped, 'freshness packet shared caller differs')
    result.append({**record, 'shared_fde_starts': [data['callers']['caller_fde']],
                   'relationship': 'PR #430 startup freshness and later poll-arm work remain separate; shared bytes do not assign this state-file range exclusively to ABCI.'})
    path = 'research/work-items/staking-cstaking-state-wire-94/evidence.json'
    data, record = read(path)
    path_table = 'research/work-items/staking-cstaking-state-wire-94/path.tsv'
    raw_table = (ROOT/path_table).read_bytes()
    rows = raw_table.decode('ascii').splitlines()[1:]
    starts = {int(row.split('\t')[1], 16) for row in rows}
    result.append({**record, 'path_table': path_table, 'path_table_sha256': sha(raw_table),
                   'shared_fde_starts': [hex(x) for x in sorted(starts & set(scoped))],
                   'relationship': 'PR #1129 staking wire form is neighboring work; no wire or staking semantics imported.'})
    return result, named


def build(data):
    authenticate(data)
    image = Image(data)
    relocations = relative_relocations(image)
    locs = locations(image, relocations)
    require(locs, 'no exact-path Locations')
    fdes = Fdes(image)
    leas = scan_leas(image, locs)
    scoped, pending = {}, []
    for slot in locs:
        require(leas.get(slot), 'Location lacks a RIP LEA')
        for site in leas[slot]:
            owner = fdes.owner(site, 7)
            require(owner is not None, 'Location LEA lacks an FDE extent')
            scoped[owner['start']] = owner
            pending.append((site, slot, owner['start']))
    decoded = {start: decode_fde(image, fde) for start, fde in sorted(scoped.items())}
    accepted = []
    for site, slot, start in sorted(pending):
        insn, reg = verified_lea(image, decoded[start], site, slot)
        i = next(i for i, x in enumerate(decoded[start]) if x['site'] == site)
        context = []
        for x in decoded[start][i+1:i+5]:
            context.append(instruction_evidence(image, x))
            if x['kind'] in ('call_rel32', 'jmp_rel32', 'call_indirect', 'jmp_indirect', 'branch'):
                break
        accepted.append({'following_context': context, 'location': hex(slot), 'owner': hex(start), 'destination_register_index': reg,
                         'instruction': instruction_evidence(image, insn)})
    require({int(x['owner'], 16) for x in accepted} == set(scoped), 'unanchored FDE')
    for slot, loc in locs.items():
        loc['lea_sites'] = [x['instruction']['va'] for x in accepted if x['location'] == hex(slot)]
        loc['owning_fdes'] = sorted({x['owner'] for x in accepted if x['location'] == hex(slot)})
    diagnostics = diagnostic_inventory(image, decoded)
    attribution = first_party_attribution(image, decoded, relocations)
    constants = constant_inventory(image, decoded, attribution)
    triplets = source_triplets(image, decoded, constants)
    prior, named_callees = prior_work(scoped, image, fdes)
    edges = scoped_edges(image, decoded, {LOADER: LOADER_PACKET})
    transfers, transfer_counts = [], Counter()
    for start, insns in sorted(decoded.items()):
        for insn in insns:
            kind = insn['kind']
            if kind in ('call_rel32', 'jmp_rel32'):
                target = decode_rel32_transfer(insn['raw'], insn['site'])
                disposition = ('scoped_fde_entry' if target in scoped else
                               'previously_named_callee' if target == LOADER else
                               'internal_instruction' if start <= target < scoped[start]['end'] else
                               'outside_scoped_entries_unresolved')
                transfer_counts[disposition + '_' + kind] += 1
                transfers.append({'caller': hex(start), 'disposition': disposition,
                                  'instruction': instruction_evidence(image, insn)})
            elif kind in ('call_indirect', 'jmp_indirect'):
                transfer_counts[kind] += 1
    metrics = {'locations': len(locs), 'location_leas': len(accepted), 'scoped_fdes': len(scoped),
               'unique_line_column': len({(x['line'], x['column']) for x in locs.values()}),
               'scoped_fde_bytes': sum(f['end']-f['start'] for f in scoped.values()),
               'decoded_instructions': sum(len(x) for x in decoded.values()),
               'diagnostics_probed': len(diagnostics),
               'diagnostics_bound': sum(x['status'] == 'bound' for x in diagnostics),
               'diagnostics_unresolved': sum(x['status'] == 'present-but-unbound' for x in diagnostics),
               'diagnostics_absent': sum(x['status'] == 'absent' for x in diagnostics),
               'pointer_length_anchors': sum(a['kind'] != 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'counted_fragment_anchors': sum(a['kind'] == 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'constants_bound': sum(x['status'] == 'bound' for x in constants),
               'constants_unresolved': sum(x['status'] == 'unresolved' for x in constants),
               'scoped_rel32_calls': sum(e['instruction']['kind'] == 'call_rel32' and e['callee_scope'] == 'scoped_fde' for e in edges),
               'named_callee_rel32_calls': sum(e['callee_scope'] == 'previously_named_callee' and e['instruction']['kind'] == 'call_rel32' for e in edges),
               'call_edges': len(edges),
               'constant_operand_anchors': sum(len(c['anchors']) for c in constants),
               'source_setup_triplets': len(triplets),
               'shared_first_party_fdes': sum(not a['only_exact_file_locations_observed'] for a in attribution.values()),
               'scoped_rel32_jumps': sum(e['instruction']['kind'] == 'jmp_rel32' and e['callee_scope'] == 'scoped_fde' for e in edges),
               'unresolved_external_rel32_calls': transfer_counts['outside_scoped_entries_unresolved_call_rel32'],
               'unresolved_external_rel32_jumps': transfer_counts['outside_scoped_entries_unresolved_jmp_rel32'],
               'internal_rel32_jumps': transfer_counts['internal_instruction_jmp_rel32'],
               'internal_rel32_calls': transfer_counts['internal_instruction_call_rel32'],
               'indirect_calls_unresolved': transfer_counts['call_indirect'],
               'indirect_jumps_unresolved': transfer_counts['jmp_indirect']}
    evidence = {'schema_version': 1, 'work_item': 'abci-state-inventory-94', 'task': 'RE-001 / RE-009 exact-file boundary and anchor qualification',
                'component': 'abci', 'target': {'path': TARGET, 'sha256': SHA256, 'release': 94},
                'scope_rule': SCOPE.decode('ascii'), 'metrics': metrics,
                'coordinates': 'ELF link-time VA; explicit file offsets; FDE end exclusive; no ASLR/rebase',
                'source_commit': BASE_COMMIT, 'reference_commit_leads_only': REFERENCE_COMMIT,
                'reference_leads': {'path': REFERENCE_PATH, 'sha256': sha((ROOT/REFERENCE_PATH).read_bytes()),
                                    'text_or_code_copied': False,
                                    'catalogue_distinct_address_seeds_for_file': len(SEEDS),
                                    'semantic_labels': 'Unvalidated; no source names or behavior adopted'},
                'decoder_derived_from': {'branch': 'node-rs-inventory-94',
                    'commit': '4647df111947397d3039cbb97df80a155c63cd62',
                    'path_at_commit': 'tools/node_inventory.py', 'license': 'MIT'},
                'producer_sources_sha256': {f'tools/{name}': sha((TOOLS/name).read_bytes()) for name in
                                           ('abci_state_inventory.py', 'elf_index.py', 'fde_extents.py')},
                'method': {'decoder': 'abci_state_inventory restricted legacy x86-64 byte decoder v1',
                           'dependency': 'Python 3.10+ stdlib; no external disassembler',
                           'counted_chunks': 'At most four u8-counted ASCII chunks each ending C0, beginning at the scoped LEA target; no formatter semantics',
                           'diagnostic_probe_scope': 'Finite state-file hint list plus scoped state-specific diagnostics; unrelated node diagnostics excluded',
                           'literal_binding': 'exact target LEA plus adjacent pointer/length fields or non-clobbering register setup ending in call',
                           'absent_probe_rule': 'exact whole-file search; lengths/hashes and hint identifiers retained; reference-only absent text not exported',
                           'all_fde_records_checked': len(fdes.rows),
                           'boundary_check': 'complete linear decoding from actual FDE start and internal direct-branch alignment; not CFG reachability',
                           'location_layout': 'RELA pointer + u64 path length + u32 line + u32 column',
                           'normalization_masks': [], 'captured_binary_executed': False, 'network_used': False},
                'prior_work': prior, 'named_callees': named_callees,
                'seed_checks': [{'address': hex(a), 'fde_start': bool(fdes.owner(a) and fdes.owner(a)['start'] == a),
                                 'references_scoped_location': a in scoped} for a in SEEDS],
                'locations': list(locs.values()), 'location_leas': accepted,
                'fdes': [{**Fdes.record(image, f), **attribution[start]} for start, f in sorted(scoped.items())],
                'source_setup_triplets': triplets,
                'diagnostics': diagnostics, 'constants': constants, 'call_edges': edges,
                'rel32_transfers': transfers,
                'remaining_gaps': {
                    'call_targets': 'Only scoped entries and the prior RE-019 loader endpoint qualified; other direct and all indirect targets unresolved.',
                    'helpers': 'No helper closure, argument roles or error propagation established.',
                    'indirect_calls': 'Only RIP pointer slot addresses in retained context are decoded; no callee/vtable resolution claimed.',
                    'relocations': 'Location RELATIVE relocations only; no whole-program relocation comparison.',
                    'data_and_vtables': 'Only recorded Location/literal/adjacent-field bytes; other data unresolved.',
                    'whole_elf': 'No build or comparison; normalization masks empty.'},
                'non_claims': [
                    'No runtime behavior, network activity, protocol semantics or source reconstruction.',
                    'No recovered Rust, build, binary equivalence, coverage denominator or progress gate.',
                    'No exclusive component ownership, source function names, CFG reachability or full call graph.',
                    'No claims for other files or components.',
                    'FDE extents are unwind ranges; code without FDEs, inlining and split bodies remain gaps.',
                    'No tokio, net_utils/networking internals or generic base/foundation helper semantics.',
                    'No engine.rs, qtys/*, fees, clearinghouse, margin, node/*, spot_meta, spot_clearinghouse or generic foundation helper claim.',
                    'No novelty claim for RE-009 census, RE-017 GOT link, RE-019 loader edges, PR #430 startup freshness or PR #1129 staking wire form.',
                    'No semantic constant roles, struct offsets, copy semantics or enum tags established; bound constants are local EDX operands only.',
                    'No formatter grammar, rendered message, placeholder arguments or side effects from counted chunks.',
                    'No helper closure, indirect-call/vtable/data closure, relocation equivalence or whole-ELF comparison.',
                    'No parity claim for node #115 or visor.'
                ]}
    instructions = {'target_sha256': SHA256, 'decoder': evidence['method']['decoder'],
                    'columns': ['offset_from_fde_start', 'raw_hex', 'decoded_kind'],
                    'fdes': [{'start': hex(start), 'end_exclusive': hex(scoped[start]['end']),
                              'instructions': [[hex(x['site']-start), x['raw'].hex(), x['kind']] for x in insns]}
                             for start, insns in sorted(decoded.items())]}
    return {'inventory.json': evidence, 'instructions.json': instructions}


def render(value):
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
    if isinstance(value, dict) and 'columns' in value:
        # One compact raw instruction row per line keeps the transcript reviewable.
        text = re.sub(r'\[\n\s+("0x[0-9a-f]+"),\n\s+("[0-9a-f]+"),\n\s+("[a-z0-9_]+")\n\s+\]',
                      r'[\1, \2, \3]', text)
    return (text+'\n').encode('ascii')


def generate(binary, out):
    with Path(binary).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = build(data)
    Path(out).mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:
        Path(out, name).write_bytes(render(result[name]))
    return result['inventory.json']['metrics']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        metrics = generate(args.binary, args.out)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'FAIL: {exc}\n')
    print(json.dumps(metrics, sort_keys=True))


if __name__ == '__main__':
    main()
