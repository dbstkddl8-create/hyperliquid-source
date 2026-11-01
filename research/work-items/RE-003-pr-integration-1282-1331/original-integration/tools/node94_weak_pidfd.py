"""Digest-bound node #94 weak-pidfd static evidence; never executes the target."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

TARGET = Path('artifacts/node/94/hl-node')
OUT = Path('research/work-items/RE-002-weak-pidfd-callpaths-94')
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BASE = '15f79350f790a04aed73b5fc9319f85b535f8282'
SLOTS = {'pidfd_getpid': 0x5777380, 'pidfd_spawnp': 0x57773f0}
SITES = {0x4ee3945, 0x4ee3955, 0x4ee76fa, 0x4ee8320, 0x4ee834d}
EXTENTS = [(0x4ee38d0, 0x4ee398c), (0x4ee64f0, 0x4ee8b89)]
EDGES = {
    0x4ee391e: 0x4ee3928, 0x4ee393e: 0x4ee3945,
    0x4ee3943: 0x4ee3972, 0x4ee394d: 0x4ee3972,
    0x4ee395e: 0x4ee3923, 0x4ee7702: 0x4ee772b,
    0x4ee770d: 0x4ee38d0, 0x4ee7719: 0x4ee78b2,
    0x4ee8304: 0x4ee83af, 0x4ee8313: 0x4ee83af,
    0x4ee8328: 0x4ee8753, 0x4ee836d: 0x4ee8499,
    0x4ee8389: 0x4ee8407, 0x4ee8392: 0x4ee8407,
    0x4ee83ad: 0x4ee840d, 0x4ee83ea: 0x4ee843d,
    0x4ee8760: 0x4ee877b,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args):
    p = subprocess.run(args, capture_output=True, text=True, check=True)
    return p.stdout


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('expected ELF64 little-endian x86-64')
    off = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    if size != 64 or not 0 < names_index < count or off + size * count > len(data):
        raise ValueError('invalid section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, off+i*size) for i in range(count)]
    h = headers[names_index]
    names = data[h[4]:h[4]+h[5]]
    result = []
    for h in headers:
        if h[1] != 8 and h[4]+h[5] > len(data):
            raise ValueError('section outside file')
        name = names[h[0]:names.index(0, h[0])].decode()
        result.append(dict(name=name, type=h[1], flags=h[2], va=h[3],
                           offset=h[4], size=h[5], link=h[6], entsize=h[9]))
    return result


def file_offset(secs, va):
    s = next(s for s in secs if s['type'] != 8 and s['va'] <= va < s['va']+s['size'])
    return s['offset']+va-s['va']


def bindings(data, secs):
    dyn = next(s for s in secs if s['name'] == '.dynsym')
    if dyn['entsize'] != 24 or dyn['size'] % 24:
        raise ValueError('invalid dynsym')
    st = secs[dyn['link']]
    strings = data[st['offset']:st['offset']+st['size']]
    symbols = {}
    for index, off in enumerate(range(dyn['offset'], dyn['offset']+dyn['size'], 24)):
        name, info, other, ndx, value, size = struct.unpack_from('<IBBHQQ', data, off)
        name = strings[name:strings.index(0, name)].decode()
        symbols[index] = dict(name=name, index=index, file_offset=off,
                              binding=info >> 4, section_index=ndx)
    found = []
    for s in secs:
        if s['type'] != 4 or s['link'] != secs.index(dyn):
            continue
        if s['entsize'] != 24 or s['size'] % 24:
            raise ValueError('invalid RELA')
        for off in range(s['offset'], s['offset']+s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            sym = symbols[info >> 32]
            if sym['name'] in SLOTS:
                found.append(dict(symbol=sym, slot_va=slot, type=info & 0xffffffff,
                                  addend=addend, record_offset=off, section=s['name']))
    return found


def check_bindings(found):
    if len(found) != 2 or {r['symbol']['name']: r['slot_va'] for r in found} != SLOTS:
        raise ValueError('pinned relocation slots differ')
    if any(r['type'] != 6 or r['addend'] != 0 or r['symbol']['binding'] != 2
           or r['symbol']['section_index'] != 0 for r in found):
        raise ValueError('expected weak undefined GLOB_DAT imports')


def scan(data, secs, found):
    """Byte candidates only: supported forms may occur inside other instructions."""
    slots = {r['slot_va']: r['symbol']['name'] for r in found}
    candidates, denominators = [], []
    pattern = re.compile(rb'(?=\xff[\x15\x25]|[\x40-\x4f][\x8b\x8d]|[\x40-\x4f]\x83\x3d)')
    for s in secs:
        if s['type'] != 1 or not s['flags'] & 4:
            continue
        buf = data[s['offset']:s['offset']+s['size']]
        denominators.append(dict(section=s, byte_offsets=len(buf),
            eligible_positions_by_length={str(n): max(0, len(buf)-n+1) for n in (6, 7, 8)}))
        for match in pattern.finditer(buf):
            off = match.start()
            if buf[off] == 0xff:
                n, disp = 6, off+2
            elif buf[off+1] in (0x8b, 0x8d):
                if off+3 > len(buf) or buf[off+2] & 0xc7 != 5:
                    continue
                n, disp = 7, off+3
            else:
                n, disp = 8, off+3
            if off+n > len(buf):
                continue
            dest = s['va']+off+n+struct.unpack_from('<i', buf, disp)[0]
            if dest in slots:
                candidates.append(dict(symbol=slots[dest], va=s['va']+off,
                    file_offset=s['offset']+off, bytes=buf[off:off+n].hex(), slot_va=dest))
    return candidates, denominators


def branch_target(va, raw):
    if len(raw) == 2 and raw[0] in (0x74, 0x75, 0xeb):
        return va+2+struct.unpack('<b', raw[1:])[0]
    if len(raw) == 6 and raw[:2] in (b'\x0f\x84', b'\x0f\x85'):
        return va+6+struct.unpack('<i', raw[2:])[0]
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return va+5+struct.unpack('<i', raw[1:])[0]
    raise ValueError('unsupported branch encoding')


def decode(text, data, secs, start, end):
    result, cursor = [], start
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', parts[0]):
            continue
        va = int(parts[0].strip().rstrip(':'), 16)
        raw = bytes.fromhex(parts[1].strip())
        asm = ' '.join(parts[2:]).strip()
        off = file_offset(secs, va)
        if va != cursor or not raw or '(bad)' in asm or asm.startswith('.byte'):
            raise ValueError('non-contiguous or invalid disassembly')
        if data[off:off+len(raw)] != raw:
            raise ValueError('disassembly bytes differ')
        result.append(dict(va=va, file_offset=off, bytes=raw.hex(), asm=asm))
        cursor += len(raw)
    if cursor != end:
        raise ValueError('incomplete FDE decode')
    return result


def check_observations(data, secs, candidates, instructions):
    if len(candidates) != 5 or {c['va'] for c in candidates} != SITES:
        raise ValueError('pinned candidate census differs')
    for c in candidates:
        if instructions[c['va']]['bytes'] != c['bytes']:
            raise ValueError('candidate is not a decoded instruction')
    for va, expected in EDGES.items():
        ins = instructions[va]
        raw = bytes.fromhex(ins['bytes'])
        off = file_offset(secs, va)
        # Validate below the target-hash gate, including branch opcode identity.
        if data[off:off+len(raw)] != raw or branch_target(va, raw) != expected:
            raise ValueError('pinned edge differs')
        if expected not in instructions or va+len(raw) not in instructions:
            raise ValueError('edge endpoint not decoded')


def produce():
    data = TARGET.read_bytes()
    if len(data) != 91774280 or sha(data) != DIGEST:
        raise ValueError('node #94 identity mismatch')
    secs = sections(data)
    found = bindings(data, secs)
    check_bindings(found)
    candidates, denominator = scan(data, secs, found)
    relocation_command = ['readelf', '-Wr', str(TARGET)]
    reltext = run(relocation_command)
    import_names = {}
    for line in reltext.splitlines():
        m = re.match(r'^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_GLOB_DAT\s+[0-9a-f]+\s+(\S+)', line)
        if m:
            import_names[int(m[1], 16)] = m[2]
    for r in found:
        if import_names.get(r['slot_va'], '').split('@')[0] != r['symbol']['name']:
            raise ValueError('readelf relocation disagreement')
    frame_command = ['readelf', '--debug-dump=frames', '-W', str(TARGET)]
    frames = run(frame_command)
    fdes = [(int(m[1], 16), int(m[2], 16), m[0]) for m in re.finditer(
        r'^.* FDE .*pc=([0-9a-f]+)\.\.([0-9a-f]+).*$', frames, re.M)]
    extents, instructions = [], {}
    for start, end in EXTENTS:
        header = next(text for a, b, text in fdes if (a, b) == (start, end))
        args = ['objdump', '-d', '-M', 'intel', '--insn-width=16',
                '--start-address='+hex(start), '--stop-address='+hex(end), str(TARGET)]
        text = run(args)
        decoded = decode(text, data, secs, start, end)
        for i in decoded:
            m = re.search(r'#\s+([0-9a-f]+)', i['asm'])
            if m and int(m[1], 16) in import_names:
                i['referenced_import'] = import_names[int(m[1], 16)]
        instructions.update({i['va']: i for i in decoded})
        begin = file_offset(secs, start)
        extents.append(dict(start_va=start, end_va=end, file_offset=begin,
            extent_sha256=sha(data[begin:begin+end-start]), instruction_count=len(decoded),
            fde_header=header, command=args, raw_sha256=sha(text.encode()), instructions=decoded))
    check_observations(data, secs, candidates, instructions)
    versions = []
    for name in ('python3', 'readelf', 'objdump'):
        versions.append(dict(tool=name, version=run([name, '--version']).splitlines()[0],
                             executable_sha256=sha(Path(shutil.which(name)).read_bytes())))
    return dict(target=dict(path=str(TARGET), sha256=DIGEST, bytes=len(data)),
        source_baseline=BASE, producer_sha256=sha(Path(__file__).read_bytes()),
        versions=versions, relocations=found, readelf=dict(command=relocation_command,
        sha256=sha(reltext.encode()), selected_lines=[s for s in reltext.splitlines() if 'pidfd_' in s]),
        frames=dict(command=frame_command, sha256=sha(frames.encode())),
        scan=dict(forms=['FF /2,/4 RIP disp32', 'REX MOV/LEA RIP disp32', 'REX 83 3D disp32 imm8'],
        limitation='byte candidates for these encodings only; no exhaustive xrefs/reachability',
        denominator=denominator, candidates=candidates), extents=extents,
        edges=[dict(instruction=instructions[va], taken_va=dest,
                    fallthrough_va=va+len(bytes.fromhex(instructions[va]['bytes'])))
               for va, dest in sorted(EDGES.items())])


if __name__ == '__main__':
    report = produce()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(candidate_count=len(report['scan']['candidates']),
        instruction_counts=[e['instruction_count'] for e in report['extents']],
        checked_edges=len(report['edges']))))
