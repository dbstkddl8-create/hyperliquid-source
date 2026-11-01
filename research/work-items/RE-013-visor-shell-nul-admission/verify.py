#!/usr/bin/env python3
"""Regenerate static records twice and refuse corrupted captures/records."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from survey import Image, InvalidEvidence, collect, json_bytes, require, sha, write_new

HERE = Path(__file__).resolve().parent

def check_records(expected, directory):
    paths = list(directory.rglob('*'))
    require(not any(path.is_symlink() for path in paths), 'Symlink in retained records')
    names = {path.relative_to(directory).as_posix() for path in paths if path.is_file()}
    require(names == set(expected), 'Retained record inventory differs')
    for name, content in expected.items():
        require((directory / name).read_bytes() == content, 'Retained record differs: ' + name)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--records', type=Path, default=HERE / 'observed')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.receipt:
            require(not args.receipt.exists(), 'Preserve existing receipt')
        first = collect(args.binary)
        second = collect(args.binary)
        require(first == second, 'Two complete native regenerations differ')
        check_records(first, args.records)
        controls = []
        with tempfile.TemporaryDirectory(prefix='visor-nul-controls-') as temporary:
            root = Path(temporary)
            original = args.binary.read_bytes()
            image = Image(original)
            mutation_va = 0x2bf198
            offsets = [offset + mutation_va - va for offset, va, size in image.loads
                       if va <= mutation_va and mutation_va + 1 <= va + size]
            require(len(offsets) == 1, 'Mutation VA lacks unique file mapping')
            mutation_offset = offsets[0]
            require(original[mutation_offset:mutation_offset + 1] == image.at(mutation_va, 1),
                    'Mutation file offset does not map to the scan constant')
            changed = bytearray(original)
            changed[mutation_offset] ^= 1
            for name, data in [('truncated', original[:-1]),
                               ('lfs-pointer', b'version https://git-lfs.github.com/spec/v1\n'),
                               ('changed-scan-constant-image', bytes(changed))]:
                binary = root / (name + '.elf')
                binary.write_bytes(data)
                output = root / (name + '-output')
                result = subprocess.run([sys.executable, '-B', str(HERE / 'survey.py'),
                                         '--binary', str(binary), '--output', str(output)],
                                        capture_output=True, text=True, timeout=60)
                require(result.returncode == 1 and 'Wrong full Visor identity' in result.stderr
                        and not output.exists(), 'Capture control did not refuse as specified')
                control = {'case': name, 'result': 'refused before publishing output'}
                if name == 'changed-scan-constant-image':
                    control.update({'va': hex(mutation_va), 'fileOffset': hex(mutation_offset),
                                    'before': hex(original[mutation_offset]),
                                    'after': hex(changed[mutation_offset]),
                                    'scope': 'Whole-digest identity refusal, not a semantic check'})
                controls.append(control)
            for name in ['summary-substitute', 'summary-fde', 'summary-binding',
                         'native-byte', 'native-fde', 'native-relocation']:
                directory = root / name
                shutil.copytree(args.records, directory)
                if name.startswith('summary-'):
                    path = directory / 'summary.json'
                    value = json.loads(path.read_bytes())
                    if name == 'summary-substitute':
                        value['data'][2]['bytes'] = b'<string-with-xxx>\0'.hex()
                    elif name == 'summary-fde':
                        value['fdes'][0]['end'] = '0x2bf27b'
                    else:
                        value['relocations'][0]['addend'] += 1
                    path.write_bytes(json_bytes(value))
                else:
                    filename, old, new = {
                        'native-byte': ('cstring.txt', b'2bf100:\t55', b'2bf100:\t54'),
                        'native-fde': ('spawn-context.fde.txt', b'6718f9', b'6718fa'),
                        'native-relocation': ('relocations.txt', b'memcpy@', b'memcpx@'),
                    }[name]
                    path = directory / 'records' / filename
                    data = path.read_bytes()
                    require(old in data, 'Control mutation did not match retained evidence')
                    path.write_bytes(data.replace(old, new, 1))
                try:
                    check_records(first, directory)
                except InvalidEvidence:
                    controls.append({'case': name, 'result': 'corruption refused'})
                else:
                    raise InvalidEvidence('Corrupted retained evidence was accepted')
            directory = root / 'existing-output'
            directory.mkdir()
            sentinel = directory / 'sentinel'
            sentinel.write_bytes(b'keep-existing-output\n')
            try:
                write_new(directory, first)
            except InvalidEvidence:
                require(sentinel.read_bytes() == b'keep-existing-output\n'
                        and len(list(directory.iterdir())) == 1, 'Existing output changed')
                controls.append({'case': 'existing-output', 'result': 'preserved'})
            else:
                raise InvalidEvidence('Existing output was overwritten')
        receipt = {'regenerations': 2, 'files': len(first), 'controls': controls,
                   'recordSha256': {name: sha(data) for name, data in sorted(first.items())},
                   'capturedExecution': False, 'scope': 'Static evidence regeneration/integrity controls; not runtime equivalence.'}
        if args.receipt:
            args.receipt.write_bytes(json_bytes(receipt))
        print(json.dumps(receipt))
    except (InvalidEvidence, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
