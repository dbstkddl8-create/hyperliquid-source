#!/usr/bin/env python3
"""Cross-check GNU instruction boundaries against LLVM; no instruction evaluation."""
import argparse
import json
from pathlib import Path
import tempfile

import collect

HERE = Path(__file__).resolve().parent


def validate_scope(record):
    collect.require(record.get('targetSha256') == collect.TARGET and record.get('targetBytes') == collect.SIZE,
                    'GNU record target identity differs')
    ranges = record.get('ranges', [])
    collect.require(len(ranges) == len(collect.RANGES) and
                    {r.get('label') for r in ranges} == set(collect.RANGES),
                    'GNU record range membership differs')
    for row in ranges:
        start, end = collect.RANGES[row['label']]
        collect.require(row.get('start') == hex(start) and row.get('end') == hex(end) and
                        row.get('size') == end - start, 'GNU record range extent differs')


def crosscheck(binary, llvm):
    image = collect.Image(Path(binary).read_bytes())
    gnu = json.loads((HERE / 'observed/records.json').read_text())
    validate_scope(gnu)
    files, results = {}, []
    with tempfile.TemporaryDirectory(prefix='visor-wait-llvm-') as tmp:
        root = Path(tmp)
        snapshot = root / 'visor.elf'
        snapshot.write_bytes(image.data)
        snapshot.chmod(0o400)
        version = collect.native([llvm, '--version'], root).splitlines()[0]
        for expected in gnu['ranges']:
            start, end = int(expected['start'], 16), int(expected['end'], 16)
            listing = collect.native([llvm, '-d', '--x86-asm-syntax=intel',
                                      '--start-address=' + hex(start), '--stop-address=' + hex(end),
                                      'visor.elf'], root)
            actual = collect.rows(listing, image, start, end)
            fields = lambda rows: [(r['va'], r['bytes']) for r in rows]
            collect.require(fields(actual) == fields(expected['instructions']),
                            'GNU/LLVM instruction boundary mismatch')
            files[expected['label'] + '.llvm.txt'] = listing.encode()
            results.append({'label': expected['label'], 'rows': len(actual), 'bytes': end - start})
        collect.require(snapshot.read_bytes() == image.data, 'LLVM changed admitted snapshot')
    files['comparison.json'] = collect.encoded({'targetSha256': collect.TARGET, 'provider': version,
                                               'ranges': results, 'instructionBytesAndBoundaries': 'equal',
                                               'semanticProof': False, 'targetExecution': False})
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=collect.ROOT / 'artifacts/visor/captured/hl-visor')
    parser.add_argument('--llvm-objdump', default='llvm-objdump')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        collect.require(not args.output.exists(), 'Preserve existing output')
        files = crosscheck(args.binary, args.llvm_objdump)
        collect.write_new(args.output, files)
        print(files['comparison.json'].decode(), end='')
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
