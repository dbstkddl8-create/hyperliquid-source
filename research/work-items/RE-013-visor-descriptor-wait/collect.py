#!/usr/bin/env python3
"""Reproduce one static Visor wait contract; never execute captured instructions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
RANGES = {'descriptor-wait': (0x671e30, 0x671fe4),
          'wait-wrapper': (0x67f160, 0x67f290),
          'error-drop': (0x65f260, 0x65f32e)}
TABLE = 0xbcdf8
TABLE_TARGETS = [0x671f99, 0x671fa6, 0x671f92, 0x671ed0, 0x671ed0, 0x671fa1]
BOUND_SLOTS = {0x7e7d80: 'waitid', 0x7e70c8: 'ioctl',
               0x7e5900: '__errno_location', 0x7e7df8: 'waitpid',
               0x7e4c00: 0x49ae00}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


class Image:
    def __init__(self, data):
        # Admission precedes ELF parsing and all native-provider invocations.
        require(len(data) == SIZE and sha(data) == TARGET, 'Wrong complete Visor identity')
        self.data = data
        self.sections = sections(data)
        require(struct.unpack_from('<H', data, 18)[0] == 62, 'Expected x86-64 ELF')
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phsize, phnum = struct.unpack_from('<HH', data, 54)
        require(phsize == 56, 'Unexpected program-header size')
        self.loads = []
        for i in range(phnum):
            p = struct.unpack('<IIQQQQQQ', self.cut(phoff + i * phsize, phsize))
            if p[0] == 1:
                self.loads.append((p[2], p[3], p[5], p[1]))

    def cut(self, offset, size):
        require(offset >= 0 and size >= 0 and offset + size <= len(self.data), 'File range out of bounds')
        return self.data[offset:offset + size]

    def offset(self, va, size):
        offsets = [off + va - start for off, start, length, _ in self.loads
                   if start <= va and va + size <= start + length]
        require(len(offsets) == 1, 'Expected one file-backed PT_LOAD mapping')
        return offsets[0]

    def at(self, va, size):
        return self.cut(self.offset(va, size), size)

    def relocations(self):
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        shsize, shnum = struct.unpack_from('<HH', self.data, 58)
        require(shsize == 64, 'Unexpected section-header size')
        headers = [struct.unpack('<IIQQQQIIQQ', self.cut(shoff + i * shsize, shsize))
                   for i in range(shnum)]
        found = {slot: [] for slot in BOUND_SLOTS}
        for s in headers:
            if s[1] != 4:
                continue
            require(s[9] == 24 and s[5] % 24 == 0, 'Unexpected RELA size')
            for off in range(s[4], s[4] + s[5], 24):
                slot, info, addend = struct.unpack('<QQq', self.cut(off, 24))
                if slot not in found:
                    continue
                index, kind = info >> 32, info & 0xffffffff
                name = ''
                if index:
                    symbols = headers[s[6]]
                    require(symbols[9] == 24 and (index + 1) * 24 <= symbols[5], 'Invalid symbol index')
                    nameoff = struct.unpack('<I', self.cut(symbols[4] + index * 24, 4))[0]
                    strings = headers[symbols[6]]
                    table = self.cut(strings[4], strings[5])
                    end = table.find(b'\0', nameoff)
                    require(0 <= nameoff < len(table) and end >= 0, 'Invalid symbol name')
                    name = table[nameoff:end].decode('ascii')
                found[slot].append({'slot': hex(slot), 'type': kind, 'symbol': name,
                                    'symbolIndex': index, 'addend': addend,
                                    'fileOffset': hex(off), 'bytes': self.cut(off, 24).hex()})
        result = []
        for slot, expected in BOUND_SLOTS.items():
            require(len(found[slot]) == 1, 'Missing or ambiguous relocation')
            row = found[slot][0]
            if isinstance(expected, str):
                require(row['type'] == 6 and row['symbol'] == expected and row['addend'] == 0,
                        'Imported relocation binding differs')
            else:
                require(row['type'] == 8 and row['symbolIndex'] == 0 and row['addend'] == expected,
                        'Relative relocation binding differs')
            result.append(row)
        return result


def native(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=60,
                            env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0, 'Native parser failed: ' + args[0])
    return result.stdout.decode('utf-8')


def rows(text, image, start, end):
    result, cursor = [], start
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
        if not m:
            continue
        va, raw = int(m[1], 16), bytes.fromhex(m[2])
        require(va == cursor and raw and va + len(raw) <= end, 'Instruction tiling differs')
        require(raw == image.at(va, len(raw)), 'Native row differs from admitted bytes')
        require('(bad)' not in m[3] and '.byte' not in m[3], 'Incomplete native instruction decoding')
        result.append({'va': hex(va), 'bytes': raw.hex(), 'instruction': m[3].strip()})
        cursor += len(raw)
    require(cursor == end and result, 'Missing native instruction rows')
    return result


def edges(instructions):
    """Decode relative operands only, without evaluating any target instruction."""
    result = []
    for row in instructions:
        va, raw = int(row['va'], 16), bytes.fromhex(row['bytes'])
        kind, disp = None, None
        if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
            kind, disp = ('call' if raw[0] == 0xe8 else 'jump'), struct.unpack('<i', raw[1:])[0]
        elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
            kind, disp = ('jump' if raw[0] == 0xeb else 'conditional'), struct.unpack('<b', raw[1:])[0]
        elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            kind, disp = 'conditional', struct.unpack('<i', raw[2:])[0]
        elif len(raw) == 6 and raw[:2] == b'\xff\x15':
            kind, disp = 'indirect-call-slot', struct.unpack('<i', raw[2:])[0]
        if kind:
            result.append({'va': hex(va), 'kind': kind, 'target': hex(va + len(raw) + disp),
                           'bytes': raw.hex()})
    return result


def collect(binary):
    image = Image(Path(binary).read_bytes())
    cies, fdes = eh_frame_records(image.data, image.sections)
    relocations = image.relocations()
    table_bytes = image.at(TABLE, 24)
    destinations = [TABLE + offset for offset in struct.unpack('<6i', table_bytes)]
    require(destinations == TABLE_TARGETS, 'Status jump table differs')
    files, records = {}, []
    with tempfile.TemporaryDirectory(prefix='visor-descriptor-static-') as temporary:
        directory = Path(temporary)
        snapshot = directory / 'visor.elf'
        snapshot.write_bytes(image.data)
        snapshot.chmod(0o400)
        versions = {tool: native([tool, '--version'], directory).splitlines()[0]
                    for tool in ('objdump', 'readelf')}
        require(all('GNU' in v for v in versions.values()), 'GNU binutils required')
        frames = native(['readelf', '-W', '--debug-dump=frames', 'visor.elf'], directory)
        blocks = re.split(r'\n\s*\n', frames)
        for label, (start, end) in RANGES.items():
            fde = [f for f in fdes if f['start'] == start]
            require(len(fde) == 1 and fde[0]['end'] == end, 'Exact FDE extent differs')
            fde = fde[0]
            matching = [b for b in blocks if re.search(
                r'FDE cie=[0-9a-f]+ pc=0*' + f'{start:x}' + r'\.\.0*' + f'{end:x}' + r'\b', b)]
            require(len(matching) == 1, 'GNU/Python FDE disagreement')
            cie_offset = re.search(r'FDE cie=([0-9a-f]+)', matching[0])[1]
            cie_blocks = [b for b in blocks if re.match(r'^\s*' + cie_offset + r'\s+.*\bCIE\b', b)]
            require(len(cie_blocks) == 1, 'Missing native CIE')
            listing = native(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                              '--start-address=' + hex(start), '--stop-address=' + hex(end),
                              'visor.elf'], directory)
            instructions = rows(listing, image, start, end)
            files[label + '.objdump.txt'] = listing.encode()
            files[label + '.frames.txt'] = (cie_blocks[0] + '\n\n' + matching[0] + '\n').encode()
            raw_frames = {}
            for name, address in [('fde', fde['fde']), ('cie', fde['cie'])]:
                size = struct.unpack('<I', image.at(address, 4))[0] + 4
                raw_frames[name] = {'va': hex(address), 'fileOffset': hex(image.offset(address, size)),
                                    'bytes': image.at(address, size).hex()}
            records.append({'label': label, 'start': hex(start), 'end': hex(end),
                            'fileOffset': hex(image.offset(start, end - start)),
                            'size': end - start, 'sha256': sha(image.at(start, end - start)),
                            'frames': raw_frames, 'instructions': instructions,
                            'relativeEdges': edges(instructions)})
        reltext = native(['readelf', '-Wr', 'visor.elf'], directory)
        selected = []
        for slot in BOUND_SLOTS:
            lines = [line for line in reltext.splitlines() if re.match(r'^0*' + f'{slot:x}' + r'\s', line)]
            require(len(lines) == 1, 'Missing native relocation row')
            selected.extend(lines)
        files['relocations.txt'] = ('\n'.join(selected) + '\n').encode()
        require(snapshot.read_bytes() == image.data, 'Native provider changed snapshot')
    output = {'schema': 'visor-descriptor-wait-static-1', 'targetSha256': TARGET,
              'targetBytes': SIZE, 'tools': versions, 'ranges': records,
              'relocations': relocations,
              'jumpTable': {'va': hex(TABLE), 'fileOffset': hex(image.offset(TABLE, 24)),
                            'bytes': table_bytes.hex(), 'targets': [hex(x) for x in destinations]},
              'rangeBytes': sum(r['size'] for r in records),
              'instructionRows': sum(len(r['instructions']) for r in records),
              'scope': 'Static byte/CFI/relative-operand evidence; no instruction evaluation or gate claim.'}
    files['records.json'] = encoded(output)
    return files


def write_new(output, files):
    output = Path(output)
    require(not output.exists(), 'Preserve existing output')
    output.mkdir(parents=True)
    for name, data in files.items():
        (output / name).write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/visor/captured/hl-visor')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Preserve existing output')
        files = collect(args.binary)
        write_new(args.output, files)
        print(json.dumps({'files': len(files), 'targetSha256': TARGET}))
    except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
