#!/usr/bin/env python3
"""Node 94: static byte-backed side allowance and position lookup evidence."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (0x2a1e9e0, 0x370e870)
TAIL = bytes.fromhex('4885c90f98c0400f9fc64028c6400fb6c684c0742e83f8017520b0014438e875204889c848f7d8480f48c14885c078404885d2783b4829d0eb0931c04438e874e031c04885db78284d85f678234839d8480f4fd84c39f04c0f4ff04889d84c89f2')
LOOKUP_END = bytes.fromhex('31d231c04883c4105b415c415d415e415fc349f7da49c1e2064c01d10fb6d3488b44d1c8488b54d1d8ebd9')
BODY_HASHES = ('dac0bbb930db7390d86a089a4eedec16f4eed25a04691593ce90c941ffa8514c', '0f322d3fd25855b9ad14de7a948c99abef174a6e68edf9aca04c9c268de207f7')
BRANCHES = ((0x2a1ea94, 'zero_position'), (0x2a1ea99, 'nonpositive_position'),
            (0x2a1eaa0, 'positive_side_mismatch'), (0x2a1eaaf, 'absolute_value_negative'),
            (0x2a1eab4, 'selected_word_negative'), (0x2a1eac0, 'negative_side_match'),
            (0x2a1eac7, 'first_cap_negative'), (0x2a1eacc, 'second_cap_negative'),
            (0x370e887, 'outer_map_empty'), (0x370e933, 'outer_key_equal'),
            (0x370e95c, 'outer_key_missing'), (0x370e978, 'inner_map_empty'),
            (0x370e9f5, 'inner_key_equal'), (0x370ea10, 'inner_key_missing'))


def check_digest(data, expected=SHA):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('target SHA-256 mismatch')


def read_va(data, secs, va, length):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va and
               va + length <= s['address'] + s['size']]
    if len(matches) != 1 or length < 0:
        raise ValueError('range does not have one file-backed section')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return data[off:off + length], off


def short_branch(data, secs, va):
    raw, _ = read_va(data, secs, va, 2)
    if 0x70 <= raw[0] <= 0x7f:
        return raw, va + 2 + struct.unpack('<b', raw[1:])[0]
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        raw, _ = read_va(data, secs, va, 6)
        return raw, va + 6 + struct.unpack('<i', raw[2:])[0]
    raise ValueError('unsupported conditional branch')


def validate_anchors(data, secs):
    if read_va(data, secs, 0x2a1ea81, len(TAIL))[0] != TAIL:
        raise ValueError('allowance arithmetic changed')
    if read_va(data, secs, 0x370ea1f, len(LOOKUP_END))[0] != LOOKUP_END:
        raise ValueError('lookup result paths changed')
    for va, opcode in ((0x2a1ea3e, 'ff15545ed502'), (0x2a1ea74, 'ff15c668d502'),
                       (0x370e972, '4b837c0ce0000f84a1000000')):
        expected = bytes.fromhex(opcode)
        if read_va(data, secs, va, len(expected))[0] != expected:
            raise ValueError('call or lookup anchor changed')


def allowance(position, side, first, second, selected):
    """Scalar model of the checked tail, with helper results supplied by the caller."""
    if side not in (0, 1):
        raise ValueError('side must be 0 or 1')
    low, high = -(1 << 63), (1 << 63) - 1
    if any(x < low or x > high for x in (position, first, second, selected)):
        raise ValueError('signed word out of range')
    matched = (position > 0 and side == 1) or (position < 0 and side == 0)
    reduction = 0
    if matched:
        if position == low or selected < 0:
            return 'panic', None, None
        reduction = abs(position) - selected
    if first < 0 or second < 0:
        return 'panic', None, None
    return 'return', max(first, reduction), max(second, reduction)


def cases():
    m = (1 << 63) - 1
    inputs = [
        ('zero', 0, 0, 3, 7, 4), ('long_matching', 10, 1, 3, 7, 4),
        ('long_opposite', 10, 0, 3, 7, 4), ('short_matching', -10, 0, 3, 7, 4),
        ('short_opposite', -10, 1, 3, 7, 4), ('equal_words', 10, 1, 3, 7, 10),
        ('reserved_exceeds_position', 10, 1, 3, 7, 12),
        ('both_caps_raised', 20, 1, 3, 7, 4), ('only_first_raised', 10, 1, 3, 7, 4),
        ('negative_selected_matching', 10, 1, 3, 7, -1),
        ('negative_selected_opposite', 10, 0, 3, 7, -1),
        ('min_matching', -(1 << 63), 0, 3, 7, 0),
        ('min_opposite', -(1 << 63), 1, 3, 7, 0),
        ('negative_first', 0, 0, -1, 7, 0), ('negative_second', 0, 0, 3, -1, 0),
        ('max_position', m, 1, 0, 1, 0), ('max_selected', 1, 1, 0, 1, m),
    ]
    for name, position, side, first, second, selected in inputs:
        status, out0, out1 = allowance(position, side, first, second, selected)
        yield dict(name=name, position=position, side=side, first=first, second=second,
                   selected=selected, result=status, out0=out0, out1=out1)


def generate(data):
    check_digest(data)
    secs = sections(data)
    validate_anchors(data, secs)
    _, frames = eh_frame_records(data, secs)
    functions = []
    for start, expected in zip(FUNCTIONS, BODY_HASHES):
        rows = [f for f in frames if f['start'] == start]
        if len(rows) != 1:
            raise ValueError('FDE start is missing or ambiguous')
        f = rows[0]
        raw, off = read_va(data, secs, start, f['end'] - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('function bytes changed')
        functions.append(dict(start=hex(start), end=hex(f['end']), fde=hex(f['fde']),
                              file_offset=hex(off), length=len(raw), sha256=digest, bytes=raw.hex()))
    branches = []
    for va, label in BRANCHES:
        raw, target = short_branch(data, secs, va)
        owner = next((int(f['start'], 16) for f in functions
                      if int(f['start'], 16) <= va < int(f['end'], 16)), None)
        if owner is None or not owner <= target < next(int(f['end'], 16) for f in functions if int(f['start'], 16) == owner):
            raise ValueError('branch outside selected extent')
        branches.append(dict(site=hex(va), bytes=raw.hex(), target=hex(target), label=label))
    call_bytes, _ = read_va(data, secs, 0x2a1ea74, 6)
    slot = 0x2a1ea74 + 6 + struct.unpack('<i', call_bytes[2:])[0]
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    if rela['type'] == 8 or rela['size'] % 24:
        raise ValueError('invalid relocation section')
    matches = []
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        rslot, info, addend = struct.unpack_from('<QQq', data, off)
        if rslot == slot and info == 8:
            matches.append(addend)
    if matches != [FUNCTIONS[1]]:
        raise ValueError('lookup relocation mismatch')
    first_call, _ = read_va(data, secs, 0x2a1ea3e, 6)
    first_slot = 0x2a1ea3e + 6 + struct.unpack('<i', first_call[2:])[0]
    return dict(binary_sha256=SHA, coordinate_system='ELF virtual addresses; file_offset is in the input file',
                functions=functions, branches=branches,
                calls=[dict(site=hex(0x2a1ea3e), bytes=first_call.hex(), slot=hex(first_slot), role='external cap provider; body outside scope'),
                       dict(site=hex(0x2a1ea74), bytes=call_bytes.hex(), slot=hex(slot), target=hex(matches[0]), role='two-key side lookup')],
                limitations=['FDE extents are unwind ranges, not proven complete function boundaries.',
                             'No target execution; samples are an independently stated scalar model, not differential results.',
                             'The first call and the lookup hash and allocator helpers are outside the semantic scope.']), list(cases())


def render_tsv(rows):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        evidence, rows = generate(args.binary.read_bytes())
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
        (args.out / 'cases.tsv').write_bytes(render_tsv(rows))
    except (OSError, ValueError, StopIteration, struct.error) as exc:
        print('risk size allowance:', exc, file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
