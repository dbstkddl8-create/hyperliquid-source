#!/usr/bin/env python3
"""Regeneration and corruption controls for static records, not target execution."""
import argparse
import copy
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import collect
import crosscheck

HERE = Path(__file__).resolve().parent


def compare(expected, actual):
    collect.require(expected.keys() == actual.keys(), 'Retained file membership differs')
    for name in expected:
        collect.require(expected[name] == actual[name], 'Retained record differs: ' + name)


def rejects(action, label):
    try:
        action()
    except ValueError:
        return label
    raise ValueError('Corruption was accepted: ' + label)


def verify(binary):
    first = collect.collect(binary)
    second = collect.collect(binary)
    compare(first, second)
    retained = {p.name: p.read_bytes() for p in (HERE / 'observed').iterdir() if p.is_file()}
    compare(first, retained)
    controls = []
    original = Path(binary).read_bytes()
    changed = bytearray(original)
    changed[0x671e30 - 0x1000] ^= 1
    # If any bad capture reaches the native boundary this control fails loudly.
    with tempfile.TemporaryDirectory(prefix='visor-wait-admission-') as tmp:
        for name, data in [('truncated', original[:-1]), ('extended', original + b'\0'),
                           ('one-byte-change', changed)]:
            path = Path(tmp) / name
            path.write_bytes(data)
            with patch.object(collect, 'native', side_effect=RuntimeError('Native called before admission')):
                controls.append(rejects(lambda: collect.collect(path), name + '-before-native'))

    def altered_record(label, mutate):
        data = json.loads(retained['records.json'])
        mutate(data)
        altered = dict(retained, **{'records.json': collect.encoded(data)})
        controls.append(rejects(lambda: compare(first, altered), label))

    altered_record('status-table-destination', lambda d: d['jumpTable']['targets'].__setitem__(0, '0x671fa6'))
    altered_record('relocation-callee', lambda d: d['relocations'][0].__setitem__('symbol', 'waitpid'))
    altered_record('frame-end', lambda d: d['ranges'][0].__setitem__('end', '0x671fe5'))
    altered_record('branch-destination', lambda d: d['ranges'][0]['relativeEdges'][0].__setitem__('target', '0x0'))
    altered_record('instruction-immediate', lambda d: next(
        r for r in d['ranges'][0]['instructions'] if r['va'] == '0x671eef').__setitem__('bytes', '83f904'))
    removed = dict(retained)
    removed.pop('relocations.txt')
    controls.append(rejects(lambda: compare(first, removed), 'missing-native-relocations'))
    modified = dict(retained)
    modified['descriptor-wait.objdump.txt'] += b'changed\n'
    controls.append(rejects(lambda: compare(first, modified), 'raw-export-corruption'))

    image = collect.Image(original)
    listing = first['descriptor-wait.objdump.txt'].decode()
    changed_listing = listing.replace('89 d1', '89 d0', 1)
    controls.append(rejects(lambda: collect.rows(changed_listing, image, 0x671e30, 0x671fe4),
                            'decoder-row-byte-mismatch'))
    lines = listing.splitlines(keepends=True)
    missing_row = ''.join(line for line in lines if not line.lstrip().startswith('671e42:'))
    controls.append(rejects(lambda: collect.rows(missing_row, image, 0x671e30, 0x671fe4),
                            'decoder-row-gap'))
    with tempfile.TemporaryDirectory(prefix='visor-wait-output-') as tmp:
        output = Path(tmp) / 'existing'
        output.mkdir()
        sentinel = output / 'keep'
        sentinel.write_bytes(b'preserve')
        controls.append(rejects(lambda: collect.write_new(output, first), 'preserve-existing-output'))
        collect.require(sentinel.read_bytes() == b'preserve' and len(list(output.iterdir())) == 1,
                        'Existing output was changed')
    result = json.loads(first['records.json'])
    crosscheck.validate_scope(result)
    for label, mutate in [
            ('crosscheck-missing-range', lambda d: d['ranges'].pop()),
            ('crosscheck-wrong-target', lambda d: d.__setitem__('targetSha256', '0' * 64)),
            ('crosscheck-shortened-range', lambda d: d['ranges'][0].__setitem__('end', '0x671e31'))]:
        altered = copy.deepcopy(result)
        mutate(altered)
        controls.append(rejects(lambda: crosscheck.validate_scope(altered), label))
    return {'status': 'PASS', 'regenerations': 2, 'retainedFiles': len(first),
            'rangeBytes': result['rangeBytes'], 'instructionRows': result['instructionRows'],
            'rejectedControls': controls,
            'targetExecution': False, 'instructionEvaluation': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=collect.ROOT / 'artifacts/visor/captured/hl-visor')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.binary), indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
