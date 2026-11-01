#!/usr/bin/env python3
"""Authenticate static Visor NUL-admission evidence; never execute target code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

TARGET = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
# Complete FDEs: existing byte scope, not newly recovered function credit.
FDE_RANGES = {
    'cstring': (0x2bf100, 0x2bf27a),
    'cstring-finish': (0x2bea00, 0x2beae1),
    'command-arg': (0x67f290, 0x67f382),
    'command-new': (0x67f390, 0x67f705),
    'shell-command': (0x3d8d70, 0x3d97e9),
    'argv-grow': (0x675c90, 0x675cf7),
    'spawn-context': (0x66f280, 0x6718f9),
}
# Only three selected windows of the large spawn FDE are exported/argued.
RANGES = {key: value for key, value in FDE_RANGES.items() if key != 'spawn-context'}
RANGES.update({
    'spawn-entry': (0x66f280, 0x66f2c7),
    'spawn-nul-gate': (0x66f3e3, 0x66f40d),
    'spawn-return': (0x6702f2, 0x670319),
})
SLOTS = {
    0x7e6138: 0x67f390, 0x7e6140: 0x67f290,
    0x7e4c48: 0x2bf100, 0x7e4bd0: 0x2bea00,
    0x7e7c90: 0x675c90, 0x7e4bc8: 0x710ea0,
    0x7e4b60: 0x70bf30, 0x7e4b68: 'memcpy', 0x7e4b80: 0x714530,
    0x7e4b40: 0x2beaf4, 0x7e4b50: 0x49ac3f, 0x7e4be8: 0x2beae1,
    0x7dbfd0: 0xbe3c8,
}
DATA = {
    'program': (0x7a9c4, b'/bin/sh'),
    'first-argument': (0x7a9c2, b'-c'),
    'substitute': (0x6ade7, b'<string-with-nul>\0'),
    'nul-diagnostic': (0xbe3c8, b'nul byte found in provided data'),
    'diagnostic-record': (0x7dbfd0, bytes.fromhex('00000000000000001f000000000000001400000000000000')),
    'scan-high-mask-immediate': (0x2bf18e, bytes.fromhex('8080808080808080')),
    'scan-subtract-immediate': (0x2bf198, bytes.fromhex('0001010101010101')),
}
DIRECT = {0x3d9192: 0x66f280, 0x675cca: 0x6760d0}
GNU_READELF = os.environ.get('GNU_READELF', 'readelf')
GNU_OBJDUMP = os.environ.get('GNU_OBJDUMP', 'objdump')
LLVM_OBJDUMP = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')

class InvalidEvidence(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise InvalidEvidence(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()

class Image:
    def __init__(self, data):
        require(len(data) == SIZE and sha(data) == TARGET, 'Wrong full Visor identity')
        self.data = data
        require(data[:7] == b'\x7fELF\x02\x01\x01', 'Expected ELF64 little endian')
        require(struct.unpack_from('<H', data, 18)[0] == 62, 'Expected x86-64')
        phoff, shoff = struct.unpack_from('<QQ', data, 32)
        phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
        require(phsize == 56 and shsize == 64, 'Unexpected ELF table sizes')
        self.loads = []
        for i in range(phnum):
            entry = struct.unpack('<IIQQQQQQ', self.cut(phoff + i * phsize, phsize))
            if entry[0] == 1:
                self.loads.append((entry[2], entry[3], entry[5]))
        self.sections = [struct.unpack('<IIQQQQIIQQ', self.cut(shoff + i * shsize, shsize))
                         for i in range(shnum)]

    def cut(self, offset, length):
        require(offset >= 0 and length >= 0 and offset + length <= len(self.data),
                'ELF byte extent outside the admitted image')
        return self.data[offset:offset + length]

    def at(self, address, length):
        offsets = [offset + address - va for offset, va, size in self.loads
                   if va <= address and address + length <= va + size]
        require(len(offsets) == 1, 'VA lacks one file-backed PT_LOAD mapping')
        return self.cut(offsets[0], length)

    def relocations(self):
        result = {slot: [] for slot in SLOTS}
        for section in self.sections:
            if section[1] != 4:
                continue
            require(section[9] == 24 and section[5] % 24 == 0, 'Unexpected RELA records')
            for offset in range(section[4], section[4] + section[5], 24):
                slot, info, addend = struct.unpack('<QQq', self.cut(offset, 24))
                if slot not in result:
                    continue
                symbol_index, kind = info >> 32, info & 0xffffffff
                symbol = ''
                if symbol_index:
                    symbols = self.sections[section[6]]
                    require(symbols[9] == 24, 'Unexpected ELF symbol size')
                    symbol_offset = symbols[4] + symbol_index * 24
                    require(symbol_offset + 24 <= symbols[4] + symbols[5], 'Symbol outside table')
                    name = struct.unpack('<I', self.cut(symbol_offset, 4))[0]
                    strings = self.sections[symbols[6]]
                    require(name < strings[5], 'Symbol name outside string table')
                    table = self.cut(strings[4], strings[5])
                    end = table.find(b'\0', name)
                    require(end >= 0, 'Unterminated ELF symbol')
                    symbol = table[name:end].decode('utf-8')
                result[slot].append({'slot': hex(slot), 'type': kind, 'symbolIndex': symbol_index,
                                     'symbol': symbol, 'addend': addend})
        records = []
        for slot, expected in SLOTS.items():
            require(len(result[slot]) == 1, 'Relocation slot is absent or ambiguous')
            row = result[slot][0]
            if isinstance(expected, str):
                require(row['type'] == 6 and row['symbol'] == expected and row['addend'] == 0,
                        'Imported symbol binding differs')
            else:
                require(row['type'] == 8 and row['symbolIndex'] == 0 and row['addend'] == expected,
                        'Relative callee binding differs at ' + hex(slot))
            records.append(row)
        return records

def command(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=60,
                            env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0, 'Native provider failed: ' + args[0])
    return result.stdout.decode('utf-8')

def native_rows(text, image, start, end):
    rows = []
    cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
        if not match:
            continue
        address = int(match[1], 16)
        raw = bytes.fromhex(match[2])
        require(address == cursor and raw and cursor + len(raw) <= end,
                'Native export is not a complete contiguous range')
        require(raw == image.at(address, len(raw)), 'Native instruction bytes differ')
        require('(bad)' not in match[3], 'Native decoder reports a bad instruction')
        rows.append({'va': hex(address), 'bytes': raw.hex(), 'instruction': match[3].strip()})
        cursor += len(raw)
    require(cursor == end and rows, 'Native export leaves missing bytes')
    return rows

def collect(binary):
    image = Image(Path(binary).read_bytes())
    relocations = image.relocations()
    data_records = []
    for name, (va, expected) in DATA.items():
        raw = image.at(va, len(expected))
        require(raw == expected, 'Bound data differs: ' + name)
        data_records.append({'label': name, 'va': hex(va), 'bytes': raw.hex(),
                             'length': len(raw), 'sha256': sha(raw)})
    direct_records = []
    for va, expected in DIRECT.items():
        raw = image.at(va, 5)
        require(raw[0] == 0xe8 and va + 5 + struct.unpack('<i', raw[1:])[0] == expected,
                'Direct call binding differs')
        direct_records.append({'va': hex(va), 'bytes': raw.hex(), 'destination': hex(expected)})
    files = {}
    with tempfile.TemporaryDirectory(prefix='visor-nul-static-') as temporary:
        root = Path(temporary)
        snapshot = root / 'visor.elf'
        snapshot.write_bytes(image.data)
        snapshot.chmod(0o400)
        versions = {label: command([tool, '--version'], root).splitlines()[0]
                    for label, tool in [('readelf', GNU_READELF), ('objdump', GNU_OBJDUMP)]}
        require(all(value.startswith('GNU ') for value in versions.values()), 'GNU providers required')
        frames = command([GNU_READELF, '-W', '--debug-dump=frames', 'visor.elf'], root)
        blocks = re.split(r'\n\s*\n', frames)
        fdes = []
        for label, (start, end) in FDE_RANGES.items():
            matched = []
            for block in blocks:
                match = re.search(r'FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)', block)
                if match and int(match[2], 16) == start:
                    matched.append((int(match[3], 16), match[1], block))
            require(len(matched) == 1 and matched[0][0] == end, 'Exact FDE extent differs')
            _, cie, fde = matched[0]
            cies = [block for block in blocks if re.match(r'^\s*' + cie + r'\s+.*\bCIE\b', block)]
            require(len(cies) == 1, 'CIE record is missing or ambiguous')
            files['records/' + label + '.fde.txt'] = (fde + '\n').encode()
            files['records/cie-' + cie + '.txt'] = (cies[0] + '\n').encode()
            fdes.append({'label': label, 'start': hex(start), 'end': hex(end), 'bytes': end - start,
                         'sha256': sha(image.at(start, end - start)), 'cieOffset': cie})
        ranges = []
        for label, (start, end) in RANGES.items():
            containing = [fde for fde in fdes if int(fde['start'], 16) <= start and end <= int(fde['end'], 16)]
            require(len(containing) == 1, 'Selected window lacks unique containing FDE')
            listing = command([GNU_OBJDUMP, '-d', '-M', 'intel', '--insn-width=16',
                               '--start-address=' + hex(start), '--stop-address=' + hex(end),
                               'visor.elf'], root)
            rows = native_rows(listing, image, start, end)
            files['records/' + label + '.txt'] = listing.encode()
            ranges.append({'label': label, 'start': hex(start), 'end': hex(end), 'bytes': end - start,
                           'sha256': sha(image.at(start, end - start)),
                           'containingFde': containing[0]['label'], 'rows': rows})
        readelf_relocations = command([GNU_READELF, '-Wr', 'visor.elf'], root)
        selected = []
        for slot in SLOTS:
            found = [line for line in readelf_relocations.splitlines()
                     if re.match(r'^0*' + f'{slot:x}' + r'\s', line)]
            require(len(found) == 1, 'Native relocation record is missing or ambiguous')
            selected.extend(found)
        files['records/relocations.txt'] = ('\n'.join(selected) + '\n').encode()
        require(snapshot.read_bytes() == image.data, 'Private snapshot changed during analysis')
    summary = {'schema': 'visor-nul-nul-admission-static-1', 'targetSha256': TARGET, 'targetBytes': SIZE,
               'versions': versions, 'fdes': fdes, 'ranges': ranges, 'relocations': relocations,
               'data': data_records, 'directCalls': direct_records,
               'rangeBytes': sum(row['bytes'] for row in ranges),
               'instructionRows': sum(len(row['rows']) for row in ranges),
               'scope': 'Static native exports and bindings; three spawn windows only; no instruction evaluator, target execution, recovered function count or gate.'}
    files['summary.json'] = json_bytes(summary)
    return files

def write_new(output, files):
    output = Path(output)
    require(not output.exists(), 'Existing output must be preserved')
    output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Existing output must be preserved')
        files = collect(args.binary)
        write_new(args.output, files)
        print(json.dumps({'files': len(files), 'output': str(args.output)}))
    except (InvalidEvidence, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
