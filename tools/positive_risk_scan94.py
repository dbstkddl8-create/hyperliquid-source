#!/usr/bin/env python3
"""Extract the node #94 positive per-DEX risk-row collector, without executing it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('dex_filter', 0x21bc7c0, 0x21bc94e, 'ddf9ea6b75fa7db09594d21262281cdb52f7fae7c9ff099179ff5d04598058be'),
    ('user_collector', 0x24fdfe0, 0x24fe266, 'd8cdc329854be00b7aaceb0ffc29bd05b7aa75227c859e8b47fc6010ff72fbc9'),
    ('batch_fold', 0x251c9d0, 0x251cb95, '5cc626dc3c7fbeed13b24e0d39a92698906d76c54fdfa925f269e8544ab31eb4'),
)
# Instruction starts verified by decoding from the FDE start.  Names describe the
# branch condition only; fall-through and semantic interpretation are separate.
BRANCHES = (
    (0x21bc7e4, 'jne', 0x21bc82a, 'kind byte differs from 2'),
    (0x21bc7ea, 'ja', 0x21bc82a, 'row id above limit'),
    (0x21bc7f4, 'je', 0x21bc82a, 'row mode equals 3'),
    (0x21bc828, 'je', 0x21bc885, '20-byte values equal'),
    (0x21bc839, 'jno', 0x21bc88d, 'id times scale fits'),
    (0x21bc83e, 'jne', 0x21bc941, 'product overflow and nonempty rows'),
    (0x21bc870, 'jle', 0x21bc885, 'helper result signed nonpositive'),
    (0x21bc8ca, 'jb', 0x21bc844, 'row walk exhausted'),
    (0x21bc8d3, 'jb', 0x21bc934, 'iteration index wrapped'),
    (0x21bc8e5, 'jne', 0x21bc927, 'derived quotient differs from row id'),
    (0x21bc8fb, 'jae', 0x21bc927, 'derived local index outside count'),
    (0x21bc911, 'jne', 0x21bc8c0, 'row byte is nonzero'),
    (0x24fe016, 'ja', 0x24fe028, 'mode above 3'),
    (0x24fe024, 'jne', 0x24fe031, 'low mode or first flag nonzero'),
    (0x24fe02f, 'je', 0x24fe057, 'second flag zero'),
    (0x24fe0a3, 'je', 0x24fe031, 'no rows left before first match'),
    (0x24fe0cb, 'jne', 0x24fe0a0, 'first scan item absent'),
    (0x24fe0ea, 'je', 0x24fe22f, 'first allocation failed'),
    (0x24fe153, 'je', 0x24fe1df, 'remaining DEX walk exhausted'),
    (0x24fe178, 'jne', 0x24fe150, 'later scan item absent'),
    (0x24fe198, 'jne', 0x24fe1ba, 'vector has spare capacity'),
    (0x24fe1e9, 'jno', 0x24fe204, 'capacity is not sentinel'),
    (0x24fe24b, 'je', 0x24fe25e, 'cleanup has no allocation'),
    (0x251c9f9, 'je', 0x251cb1a, 'input slice empty'),
    (0x251ca5d, 'je', 0x251cb1a, 'input slice exhausted'),
    (0x251ca85, 'jo', 0x251ca30, 'collector returned sentinel'),
    (0x251cab7, 'jne', 0x251cac4, 'output vector has spare capacity'),
)
WINDOWS = (
    ('special_exclusion', 0x21bc7d3, 0x21bc82a),
    ('multiplication_gate', 0x21bc82a, 0x21bc844),
    ('risk_call_and_result', 0x21bc844, 0x21bc888),
    ('asset_row_walk', 0x21bc88d, 0x21bc913),
    ('filter_return_and_failures', 0x21bc913, 0x21bc94e),
    ('user_admission', 0x24fe00c, 0x24fe057),
    ('first_dex_walk', 0x24fe090, 0x24fe0dc),
    ('subsequent_dex_walk', 0x24fe150, 0x24fe1df),
    ('user_output', 0x24fe1df, 0x24fe22f),
    ('fold_call_and_append', 0x251ca63, 0x251cb1a),
    ('fold_return', 0x251cb1a, 0x251cb4a),
)

OPCODES = {
    0x70: 'jo', 0x71: 'jno', 0x72: 'jb', 0x73: 'jae', 0x74: 'je',
    0x75: 'jne', 0x77: 'ja', 0x7e: 'jle',
    0x80: 'jo', 0x81: 'jno', 0x82: 'jb', 0x83: 'jae', 0x84: 'je',
    0x85: 'jne', 0x87: 'ja', 0x8e: 'jle',
}


def file_view(data, va, size, executable=False):
    if size <= 0 or va < 0:
        raise ValueError('invalid virtual range')
    matches = [s for s in sections(data) if s['type'] != 8 and
               (not executable or s['flags'] & 4) and s['address'] <= va and
               va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('virtual range is not uniquely file-backed')
    s = matches[0]
    offset = s['offset'] + va - s['address']
    return offset, data[offset:offset + size]


def branch(data, va):
    raw = file_view(data, va, 2, True)[1]
    if raw[0] == 0x0f:
        ins = file_view(data, va, 6, True)[1]
        op, displacement = ins[1], struct.unpack_from('<i', ins, 2)[0]
    else:
        ins = raw
        op, displacement = ins[0], struct.unpack_from('<b', ins, 1)[0]
    if op not in OPCODES:
        raise ValueError('unsupported branch opcode')
    return OPCODES[op], va + len(ins) + displacement, ins.hex()


def direct_call(data, site):
    ins = file_view(data, site, 5, True)[1]
    if ins[0] != 0xe8:
        raise ValueError('not an E8 call')
    return site + 5 + struct.unpack_from('<i', ins, 1)[0], ins.hex()


def got_call(data, site):
    ins = file_view(data, site, 6, True)[1]
    if ins[:2] != b'\xff\x15':
        raise ValueError('not a RIP-relative indirect call')
    return site + 6 + struct.unpack_from('<i', ins, 2)[0], ins.hex()


def relocation(data, slot):
    candidates = []
    for sec in sections(data):
        if sec['name'] == '.rela.dyn' and sec['type'] == 4:
            if sec['size'] % 24:
                raise ValueError('truncated RELA')
            for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
                address, info, addend = struct.unpack_from('<QQq', data, pos)
                if address == slot:
                    candidates.append((info, addend))
    if len(candidates) != 1 or candidates[0][0] != 8:
        raise ValueError('missing or ambiguous relative relocation')
    return candidates[0][1]


def immediate(data, address, prefix, fmt):
    length = struct.calcsize(fmt)
    raw = file_view(data, address, len(prefix) + length, True)[1]
    if not raw.startswith(prefix):
        raise ValueError('immediate instruction changed')
    return struct.unpack_from(fmt, raw, len(prefix))[0]


def analyze(data, verify_digest=True):
    digest = hashlib.sha256(data).hexdigest()
    if verify_digest and digest != DIGEST:
        raise ValueError('target SHA-256 mismatch')
    _, fdes, _ = fde_extents(data)
    out, byte_lines = [], []
    for name, start, end, body_hash in FUNCTIONS:
        matches = [r for r in fdes if r['start'] == start and r['end'] == end]
        if len(matches) != 1:
            raise ValueError('FDE mismatch')
        offset, body = file_view(data, start, end - start, True)
        if hashlib.sha256(body).hexdigest() != body_hash:
            raise ValueError('function bytes mismatch: ' + name)
        out.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                    'file_offset': hex(offset), 'length': len(body), 'sha256': body_hash,
                    'fde_va': hex(matches[0]['fde'])})
        for i in range(0, len(body), 16):
            byte_lines.append(f'{name}\t{start + i:#x}\t{body[i:i + 16].hex()}')
    rows = []
    for site, expected_op, expected_target, description in BRANCHES:
        op, target, raw = branch(data, site)
        if (op, target) != (expected_op, expected_target):
            raise ValueError('branch mismatch')
        if not any(start <= site < end and start <= target < end for _, start, end, _ in FUNCTIONS):
            raise ValueError('branch outside subject extent')
        rows.append((hex(site), raw, op, hex(target), description))
    edges = []
    direct = (
        (0x251ca72, 0x24fdfe0, 'per-user collector'),
        (0x24fe0b7, 0x21bc7c0, 'first per-DEX filter'),
        (0x24fe16b, 0x21bc7c0, 'later per-DEX filter'),
        (0x24fe1b0, 0x251b070, 'inner vector growth'),
        (0x24fe261, 0x5660110, 'cleanup transfer'),
        (0x251cb6b, 0x2505550, 'cleanup helper'),
        (0x251cb73, 0x5660110, 'cleanup transfer'),
        (0x251cb88, 0x2505550, 'cleanup helper'),
        (0x251cb90, 0x5660110, 'cleanup transfer'),
    )
    indirect = (
        (0x21bc867, 0x57738b8, 0x3708bf0, 'risk helper'),
        (0x21bc92e, 0x576e470, 0x157a9f0, 'index failure'),
        (0x21bc93b, 0x576e118, 0x157b480, 'increment failure'),
        (0x21bc948, 0x576e1b0, 0x157b4a0, 'multiply failure'),
        (0x24fe0e1, 0x576dfd8, 0x54c06b0, 'first allocation'),
        (0x24fe239, 0x576dfb8, 0x1346068, 'allocation failure'),
        (0x24fe258, 0x576e010, 0x54c8cb0, 'cleanup'),
        (0x251cabe, 0x57745b8, 0x454e7e0, 'outer vector growth'),
        (0x251cb60, 0x576e010, 0x54c8cb0, 'cleanup'),
    )
    for site, expected, role in direct:
        target, raw = direct_call(data, site)
        if target != expected:
            raise ValueError('direct call target mismatch')
        edges.append({'site': hex(site), 'bytes': raw, 'kind': 'E8 rel32',
                      'target': hex(target), 'role': role})
    for site, expected_slot, expected_target, role in indirect:
        slot, raw = got_call(data, site)
        target = relocation(data, slot)
        if slot != expected_slot or target != expected_target:
            raise ValueError('indirect call relocation mismatch')
        edges.append({'site': hex(site), 'bytes': raw, 'kind': 'indirect RELATIVE relocation',
                      'slot': hex(slot), 'target': hex(target), 'role': role})
    edges.sort(key=lambda row: int(row['site'], 16))
    constants = {
        'row_id_limit': immediate(data, 0x21bc7e6, bytes.fromhex('4983fe'), '<B'),
        'asset_multiplier': immediate(data, 0x21bc82e, bytes.fromhex('ba'), '<I'),
        'row_stride': immediate(data, 0x24fe0a5, bytes.fromhex('488d9a'), '<I'),
        'outer_item_stride': immediate(data, 0x251ca56, bytes.fromhex('4983c4'), '<B'),
        'result_row_shift': immediate(data, 0x251cacd, bytes.fromhex('48c1e1'), '<B'),
        'risk_mode': immediate(data, 0x21bc862, bytes.fromhex('ba'), '<I'),
        'special_kind': immediate(data, 0x21bc7dd, bytes.fromhex('803a'), '<B'),
        'special_excluded_mode': immediate(data, 0x21bc7ec, bytes.fromhex('4180b930020000'), '<B'),
        'asset_row_stride': immediate(data, 0x21bc90c, bytes.fromhex('4d8d6424'), '<B'),
        'asset_status_offset': immediate(data, 0x21bc89f, bytes.fromhex('4983c4'), '<B'),
        'risk_parameter_offset': immediate(data, 0x21bc854, bytes.fromhex('410fb689'), '<I'),
        'mode_limit': immediate(data, 0x24fe013, bytes.fromhex('80f9'), '<B'),
        'low_mode_limit': immediate(data, 0x24fe018, bytes.fromhex('80f9'), '<B'),
        'low_mode_flag_offset': immediate(data, 0x24fe01e, bytes.fromhex('0a88'), '<I'),
        'high_mode_flag_offset': immediate(data, 0x24fe028, bytes.fromhex('80b8'), '<I'),
        'initial_allocation_bytes': immediate(data, 0x24fe0dc, bytes.fromhex('bf'), '<I'),
    }
    if constants != {'row_id_limit': 109, 'asset_multiplier': 10000, 'row_stride': 752,
                     'outer_item_stride': 16, 'result_row_shift': 4, 'risk_mode': 4,
                     'special_kind': 2, 'special_excluded_mode': 3, 'asset_row_stride': 48,
                     'asset_status_offset': 40, 'risk_parameter_offset': 749, 'mode_limit': 3,
                     'low_mode_limit': 2, 'low_mode_flag_offset': 281, 'high_mode_flag_offset': 280,
                     'initial_allocation_bytes': 64}:
        raise ValueError('unexpected instruction constants')
    # The SIB index scale and shared base encode a three-times multiplication.
    sib = file_view(data, 0x251cac9, 4, True)[1]
    if sib[:3] != bytes.fromhex('488d0c') or sib[3] & 7 != 3 or (sib[3] >> 3) & 7 != 3:
        raise ValueError('result stride LEA changed')
    constants['result_row_stride'] = (1 + (1 << (sib[3] >> 6))) << constants['result_row_shift']
    location_va = 0x56f21c0
    location_lea = file_view(data, 0x21bc927, 7, True)[1]
    if location_lea[:3] != bytes.fromhex('488d3d') or 0x21bc927 + 7 + struct.unpack_from('<i', location_lea, 3)[0] != location_va:
        raise ValueError('location reference mismatch')
    _, location = file_view(data, location_va, 24)
    _, path_length, line, column = struct.unpack('<QQII', location)
    path_pointer = relocation(data, location_va)
    path = file_view(data, path_pointer, path_length)[1]
    if not path.endswith(b'l1/src/perp_meta.rs') or (line, column) != (194, 38):
        raise ValueError('location record mismatch')
    source = {'record_va': hex(location_va), 'reference_va': hex(0x21bc927),
              'reference_bytes': location_lea.hex(), 'path_pointer_va': hex(path_pointer),
              'path_suffix': 'l1/src/perp_meta.rs', 'line': line, 'column': column}
    result = {'target_sha256': DIGEST, 'coordinates': 'ELF virtual address; file offsets separately noted',
              'functions': out, 'edges': edges, 'constants': constants, 'source_location': source,
              'limits': ['FDE extents are unwind ranges, not proven complete source functions',
                         'indirect helper body, risk units, cross-component callers and runtime behavior are unresolved']}
    return result, rows, byte_lines


def generate(data, output):
    result, branches, byte_lines = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    (output / 'branches.tsv').write_text('site_va\tbytes\tcondition\ttarget_va\tdescription\n' +
        ''.join('\t'.join(row) + '\n' for row in branches), encoding='utf-8')
    (output / 'function-bytes.tsv').write_text('function\tstart_va\tbytes\n' +
        '\n'.join(byte_lines) + '\n', encoding='utf-8')
    windows = []
    for label, start, end in WINDOWS:
        if not any(lo <= start < end <= hi for _, lo, hi, _ in FUNCTIONS):
            raise ValueError('window outside subject extent')
        offset, raw = file_view(data, start, end - start, True)
        windows.append((label, hex(start), hex(end), hex(offset), raw.hex()))
    (output / 'decision-windows.tsv').write_text('label\tstart_va\tend_va\tfile_offset\tbytes\n' +
        ''.join('\t'.join(row) + '\n' for row in windows), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        generate(TARGET.read_bytes(), args.out)
    except (ValueError, OSError, struct.error) as error:
        print('positive risk scan:', error, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
