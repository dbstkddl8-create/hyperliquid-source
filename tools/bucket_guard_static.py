#!/usr/bin/env python3
"""Target94 bucket-guard family observations; static only."""
import argparse, hashlib, json, re, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from artifacts import ROOT, check
from elf_index import sections
from fde_extents import eh_frame_records

FILE_VA, FILE_LEN = 0x1e2490, 53
FILE_HEX = '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6275636b65745f67756172642e7273'
LOCATIONS = {0x5666b68: (66, 84, FILE_VA, FILE_LEN), 0x569e0a0: (118, 21, FILE_VA, FILE_LEN), 0x56e9e20: (118, 21, FILE_VA, FILE_LEN), 0x5718b20: (118, 21, FILE_VA, FILE_LEN), 0x572e848: (118, 21, FILE_VA, FILE_LEN)}
OTHER_LOCATIONS = {0x566ae58: (124, 13, 0x1f05d3, 49, '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 0x566aac8: (62, 44, 0x1de94e, 45, '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273')}
RANGES = {'update-body': (0x14027b0, 0x1403c29), 'line66-helper': (0x13c8e10, 0x13c8f53), 'time-source': (0x151cba0, 0x151cca5), 'container-index': (0x2879470, 0x287960b)}
GOT = {0x576efb0: 0x14027b0, 0x576e8a0: 0x151cba0, 0x576e8c0: 0x1447130, 0x576e930: 0x146a780, 0x576ec88: 0x13eda00, 0x576e010: 0x54c8cb0, 0x576e108: 0x157b7f0, 0x576e048: 0x157aa10}
LOCATION_PTR_SLOTS = dict.fromkeys(list(LOCATIONS) + list(OTHER_LOCATIONS))
STRINGS = {0x219f59: (30, '617373657274696f6e206661696c65643a2073656c662e30203e3d20302e'), 0x219daa: (43, '63616c6c65642060526573756c743a3a756e77726170282960206f6e20616e2060457272602076616c7565')}
CONTROLS = {0x14027e5: '39ab40020000', 0x14027f1: '660f118300020000', 0x1402840: 'b932000000', 0x140285e: '660f2ec8', 0x1402943: 'f20f110cc2', 0x14029b8: 'f2420f110cf0', 0x14029d1: 'f20f118390000000', 0x1402b4c: '48b9c3f5285c8fc2f52848f7', 0x1402bce: 'ba5f000000', 0x1403a75: '488d3ddd64e1fe', 0x1403adc: '488d3dc762e1fe', 0x1402a57: 'ff1563be3604', 0x13c8e22: '48f726', 0x13c8f16: '4c8d054bdc2904', 0x151cbef: '48b9572951cea0c84518'}
CONSTANTS = {0x20b080: '1656e79eaf03d23c', 0x20a448: '1656e79eaf03d2bc', 0x203e80: '0000304300003045', 0x202ea0: '00000000000030430000000000003045', 0x20a910: '0000000000000080'}
EXPECT_CENSUS = {0x5666b68: 1, 0x569e0a0: 11, 0x56e9e20: 10, 0x5718b20: 1, 0x572e848: 24}
MAGIC_DIV25 = 0x28f5c28f5c28f5c3
LIMITS = ('One shared update body, three reached helpers and 47 reference sites. Ring buffer element '
          'semantics, alert threshold field names, the alert sink, and the container type behind the '
          '0x260 stride are not decoded. The line-118 Location argument passed in rdx is not read by '
          'the update body under this compilation. No execution, networking, chain actions, signing, '
          'Rust reconstruction, or component gate claimed.')

def read_va(data, va, length):
    matches = [s for s in sections(data) if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('Expected one file-backed mapping')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, data[offset:offset + length]

def relocations(data):
    found = {}
    for section in sections(data):
        if section['type'] != 4:
            continue
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in GOT:
                if info != 8 or addend != GOT[slot]:
                    raise ValueError(f'Bucket-guard relocation changed at {slot:#x}')
                found[slot] = True
            if slot in LOCATIONS or slot in OTHER_LOCATIONS:
                expected = FILE_VA if slot in LOCATIONS else OTHER_LOCATIONS[slot][2]
                if info != 8 or addend != expected:
                    raise ValueError(f'Bucket-guard Location pointer changed at {slot:#x}')
                found[slot] = True
    if set(found) != set(GOT) | set(LOCATION_PTR_SLOTS):
        raise ValueError('Missing bucket-guard relocation')
    return sorted(hex(s) for s in found)

def controls(data):
    for va, expected in CONTROLS.items():
        if read_va(data, va, len(bytes.fromhex(expected)))[1] != bytes.fromhex(expected):
            raise ValueError(f'Bucket-guard control changed at {va:#x}')
    for va, expected in CONSTANTS.items():
        if read_va(data, va, len(bytes.fromhex(expected)))[1] != bytes.fromhex(expected):
            raise ValueError(f'Bucket-guard constant changed at {va:#x}')
    for va, (length, expected) in STRINGS.items():
        if read_va(data, va, length)[1] != bytes.fromhex(expected):
            raise ValueError(f'Bucket-guard string changed at {va:#x}')
    if read_va(data, FILE_VA, FILE_LEN)[1] != bytes.fromhex(FILE_HEX):
        raise ValueError('Bucket-guard file string changed')

def locations(data):
    result = {}
    for va, (line, col, file_va, file_len) in LOCATIONS.items():
        stored_len, = struct.unpack_from('<Q', data, read_va(data, va, 8)[0] + 8)
        stored_line, stored_col = struct.unpack_from('<II', data, read_va(data, va, 24)[0] + 16)
        if (stored_len, stored_line, stored_col) != (file_len, line, col):
            raise ValueError(f'Bucket-guard Location changed at {va:#x}')
        result[hex(va)] = {'line': line, 'col': col}
    for va, (line, col, file_va, file_len, file_hex) in OTHER_LOCATIONS.items():
        stored_len, = struct.unpack_from('<Q', data, read_va(data, va, 8)[0] + 8)
        stored_line, stored_col = struct.unpack_from('<II', data, read_va(data, va, 24)[0] + 16)
        if (stored_len, stored_line, stored_col) != (file_len, line, col) or read_va(data, file_va, file_len)[1] != bytes.fromhex(file_hex):
            raise ValueError(f'Bucket-guard reached Location changed at {va:#x}')
        result[hex(va)] = {'line': line, 'col': col, 'other_file': True}
    return result

def fde_bounds(data):
    _, fdes = eh_frame_records(data)
    pairs = sorted((f['start'], f['end']) for f in fdes)
    result = {}
    for name, (start, end) in RANGES.items():
        if sum(1 for s, e in pairs if (s, e) == (start, end)) != 1:
            raise ValueError(f'Exact bucket-guard FDE missing: {name}')
        result[name] = (start, end)
    return result, pairs

_MD = Cs(CS_ARCH_X86, CS_MODE_64)
_RIP_RE = re.compile(r'rip ([+-]) (0x[0-9a-f]+)')

def _rip_target(insn):
    m = _RIP_RE.search(insn.op_str)
    if not m:
        return None
    disp = int(m.group(2), 16)
    return insn.address + insn.size + (disp if m.group(1) == '+' else -disp)

def census(data, fdes):
    text = next(s for s in sections(data) if s['name'] == '.text')
    rela = {}
    for section in sections(data):
        if section['type'] != 4:
            continue
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if info == 8:
                rela[slot] = addend
    code = data[text['offset']:text['offset'] + text['size']]
    sites = {va: [] for va in EXPECT_CENSUS}
    matches = []
    for insn in _MD.disasm(code, text['address']):
        if insn.mnemonic == 'lea':
            target = _rip_target(insn)
            if target in sites:
                matches.append((target, insn.address, insn.bytes.hex()))
    for target, address, byte_hex in matches:
        got_slot = None
        for follower in _MD.disasm(read_va(data, address, 48)[1], address):
            if follower.address == address:
                continue
            if follower.mnemonic == 'call' and 'rip' in follower.op_str:
                got_slot = _rip_target(follower)
                break
        if got_slot is None or got_slot not in rela:
            raise ValueError(f'Bucket-guard site {address:#x} has no resolvable call')
        owner = next(((s, e) for s, e in fdes if s <= address < e), None)
        sites[target].append({'va': hex(address), 'bytes': byte_hex, 'got_slot': hex(got_slot), 'got_target': hex(rela[got_slot]), 'fde': [hex(owner[0]), hex(owner[1])] if owner else None})
    counts = {va: len(lst) for va, lst in sites.items()}
    if counts != EXPECT_CENSUS:
        raise ValueError(f'Bucket-guard census changed: {counts}')
    for va, lst in sites.items():
        expected_target = 0x157aa10 if va == 0x5666b68 else 0x14027b0
        if any(int(s['got_target'], 16) != expected_target for s in lst):
            raise ValueError(f'Bucket-guard site {va:#x} dispatch changed')
    return {hex(va): lst for va, lst in sorted(sites.items())}

def render(data, start, end):
    _, body = read_va(data, start, end - start)
    lines = []
    for insn in _MD.disasm(body, start):
        note = ''
        if 'rip' in insn.op_str:
            target = _rip_target(insn)
            if target is not None:
                note = f'  ; {target:#x}'
        lines.append(f'{insn.address:#x}: {insn.mnemonic} {insn.op_str}{note}')
    return lines

def generate(binary, output):
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == 'artifacts/node/94/hl-node')
    check(binary, identity)
    data = binary.read_bytes()
    controls(data)
    rela = relocations(data)
    locs = locations(data)
    bounds, fdes = fde_bounds(data)
    sites = census(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    for name, (start, end) in RANGES.items():
        (output / f'{name}.disasm.txt').write_bytes(('\n'.join(render(data, start, end)) + '\n').encode('ascii'))
    ranges_record = {name: {'start_va': hex(start), 'end_va': hex(end), 'bytes': end - start, 'sha256': hashlib.sha256(read_va(data, start, end - start)[1]).hexdigest()} for name, (start, end) in RANGES.items()}
    result = {'target_sha256': identity['sha256'], 'target_bytes': len(data), 'file_string': {'va': hex(FILE_VA), 'len': FILE_LEN, 'hex': FILE_HEX}, 'locations': locs, 'relocation_slots': rela, 'ranges': ranges_record, 'census': sites, 'census_total': sum(EXPECT_CENSUS.values()), 'percentile_magic': {'immediate': hex(MAGIC_DIV25), 'shift': 2, 'divisor': 25}, 'constants': {hex(va): expected for va, expected in sorted(CONSTANTS.items())}, 'controls': {hex(va): expected for va, expected in sorted(CONTROLS.items())}, 'captured_binary_executed': False, 'limits': LIMITS}
    (output / 'records.json').write_bytes((json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'research/work-items/RE-001-bucket-guard-94')
    args = parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output), indent=2, sort_keys=True))
