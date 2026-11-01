#!/usr/bin/env python3
"""Bind the complete node94 remainder leaf, proof and named official candidates.

Immutable bytes and mathematical certificate only; no captured-code execution,
instruction interpreter, compiler or download. Inspect seams do not admit origin.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

from libcore_fmt_correspondence import Elf, ar_members
from node115_field_adapter_drift import Image, selected_frame

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-u128-remainder-94'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARCHIVE_SHA256 = 'f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6'
BODY_SHA256 = '12f5828bd833666b6023e761036da32c29aeb7d1e7eedbb93d734f730f391e26'
BEGIN, SIZE, SLOT = 0x565f7f0, 197, 0x576e518
PREFIX = 'compiler_builtins-58c8d4715a55733a.compiler_builtins.b67a5f131a5b1bd5-cgu.'
MANGLED = '_ZN17compiler_builtins3int4udiv9__umodti317h71015285dabb8b3eE'
DEFINITIONS = {
    PREFIX + '019.rcgu.o': (MANGLED, 'cef03767df991d42e3ad613ff963a7878ea17d2962d038f40774bcd80fee826d'),
    PREFIX + '217.rcgu.o': ('__umodti3', '3a24f3d66042f1797b20ac029e6ae187d594919334a28afaecda160211d44369'),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prove_body(body):
    """Complete fixed-row transfer certificate, not a CPU/PC evaluator."""
    need(type(body) is bytes and len(body) == SIZE, 'Complete immutable 197-byte body required')
    rows = json.loads((PACKET / 'native/rows.json').read_text(encoding='utf-8'))
    cursor = 0
    for row in rows:
        raw = bytes.fromhex(row['bytes_hex'])
        need(row['address'] == BEGIN + cursor and body[cursor:cursor + len(raw)] == raw,
             'Complete native instruction encoding differs')
        cursor += len(raw)
    need(cursor == SIZE and len(rows) == 68 and sha(body) == BODY_SHA256,
         'Complete 68-row body identity differs')
    # Raw immediate positions derived from the complete retained disassembly.
    constants = {'word_bits': 64, 'input_bits': 128, 'count_mask': body[0x11],
                 'normalization_bias': body[0x13], 'endpoint_test': body[0x29],
                 'numerator_join_shift': body[0x35], 'predecessor': body[0x4d],
                 'small_digit_bits': body[0x9f]}
    need(constants == {'word_bits': 64, 'input_bits': 128, 'count_mask': 63,
                       'normalization_bias': 64, 'endpoint_test': 64,
                       'numerator_join_shift': 63, 'predecessor': 1, 'small_digit_bits': 32},
         'Native arithmetic obligations differ')
    return {'kind': 'COMPLETE_FIXED_NATIVE_TRANSFER_CERTIFICATE',
            'constants': constants, 'rows': len(rows), 'bytes': SIZE,
            'body_sha256': sha(body), 'proof_sha256': sha((PACKET / 'PROOF.md').read_bytes()),
            'returns': [0x565f875, 0x565f8b4],
            'domain': 'all u128 dividends and nonzero u128 divisors, under the explicit ordinary-return domain',
            'output': 'RAX + 2^64*RDX = dividend mod divisor',
            'data_callees_explicit_memory': 'none; RET requires a usable ordinary return word',
            'zero_divisor_runtime': 'OUTSIDE_CONTRACT', 'instruction_execution': False}


def inspect_target(data):
    """Unqualified structural seam; only analyze admits the full target."""
    image = Elf(data, 3)
    body, mapping = image.va_bytes(BEGIN, SIZE, executable=True)
    frame = selected_frame(Image(data, 3), BEGIN, SIZE)
    need(frame['body_sha256'] == sha(body), 'Selected code/FDE views disagree')
    slot = image.relative(SLOT)
    need(slot['addend'] == BEGIN, 'Selected remainder slot resolves elsewhere')
    slot_bytes, slot_mapping = image.va_bytes(SLOT, 8)
    writes = []
    for table in image.sections:
        need(table['type'] != 9, 'Unsupported captured REL encoding')
        if table['type'] != 4:
            continue
        need(table['entsize'] == 24 and table['size'] % 24 == 0, 'Invalid captured RELA table')
        for off in range(table['offset'], table['offset'] + table['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', data, off)
            if address < SLOT + 8 and address + 8 > SLOT:
                need(address == SLOT and info == 8 and addend == BEGIN,
                     'Conflicting or partial selected-slot RELA write')
                writes.append(off)
            need(not (address < BEGIN + SIZE and address + 8 > BEGIN),
                 'A captured relocation may overlap the leaf')
    need(writes == [slot['record_file_offset']], 'Selected slot writes are not globally unique')
    return {'origin': 'UNQUALIFIED', 'body_hex': body.hex(), 'body_sha256': sha(body),
            'mapping': mapping, 'selected_frame': frame, 'slot': slot,
            'slot_mapping': slot_mapping, 'unrelocated_slot_hex': slot_bytes.hex(),
            'body_relocations': [], 'proof': prove_body(body)}


def inspect_archive(data):
    """Enumerate every matching symbol, retaining the complete definition set."""
    members = ar_members(data)
    declarations, definitions = [], []
    for member, raw in members.items():
        if raw[:4] != b'\x7fELF':
            continue
        image = Elf(raw, 1)
        for table in image.sections:
            if table['type'] != 2:
                continue
            for symbol in image.symbols(table['index']):
                if '__umodti3' not in symbol['name']:
                    continue
                declarations.append({'member': member, 'member_sha256': sha(raw), 'symbol': symbol})
                if not symbol['section']:
                    continue
                need(member in DEFINITIONS and symbol['name'] == DEFINITIONS[member][0],
                     'Unexpected defined remainder candidate')
                need(symbol['info'] == (34 if symbol['name'] == '__umodti3' else 18)
                     and symbol['other'] == 2, 'Source binding/type/visibility differs')
                function = image.function(symbol['section'], symbol['name'])
                section = image.section(symbol['section'])
                need(function['size'] == SIZE and section['flags'] & 2, 'Complete source extent differs')
                need(not any(t['type'] == 9 and t['info'] == section['index'] for t in image.sections),
                     'Source remainder code uses unsupported REL encoding')
                need(not image.relocations(section['index']), 'Official remainder body has code RELA')
                body = image.section_bytes(section['index'])
                definitions.append({'member': member, 'member_sha256': sha(raw), 'member_bytes': len(raw),
                                    'symbol': function, 'section': section, 'body_hex': body.hex(),
                                    'body_sha256': sha(body), 'code_relocations': []})
    need(len(definitions) == 2 and {r['member'] for r in definitions} == set(DEFINITIONS),
         'Complete two-definition source candidate set differs')
    return {'origin': 'UNQUALIFIED', 'members_scanned': len(members),
            'declarations': declarations, 'definitions': definitions}


def analyze(target, archive):
    need(type(target) is bytes and len(target) == 91774280 and sha(target) == TARGET_SHA256,
         'Target identity differs')
    need(type(archive) is bytes and len(archive) == 4400606 and sha(archive) == ARCHIVE_SHA256,
         'Official compiler-builtins archive identity differs')
    native, official = inspect_target(target), inspect_archive(archive)
    body = bytes.fromhex(native['body_hex'])
    comparisons = []
    for row in official['definitions']:
        need(row['member_sha256'] == DEFINITIONS[row['member']][1], 'Official member identity differs')
        source = bytes.fromhex(row['body_hex'])
        need(len(source) == len(body) == SIZE, 'Complete comparison lengths differ')
        different = [i for i, (a, b) in enumerate(zip(body, source)) if a != b]
        comparisons.append({'member': row['member'], 'symbol': row['symbol']['name'],
                            'bytes': SIZE, 'raw_equal': not different,
                            'different_offsets': different, 'normalization_fields': []})
    need(all(row['raw_equal'] for row in comparisons), 'Actual complete source bodies differ from target')
    return {'target': {**native, 'origin': 'FULL_SHA256_ADMITTED_TARGET', 'sha256': TARGET_SHA256},
            'official': {**official, 'origin': 'FULL_SHA256_ADMITTED_ARCHIVE', 'sha256': ARCHIVE_SHA256},
            'comparison': comparisons, 'selected_interval_denominator': 1,
            'raw_equal_selected_intervals': 1, 'raw_equal_bytes': SIZE,
            'limits': ['Named artifact correspondence and complete manual numerical proof are separate evidence.',
                       'One interval counted once; both published definitions retained without masks.',
                       'No original compiler/source-build/ABI/caller/zero-fault/whole-component equivalence.',
                       'No captured program, instruction evaluator or compiler executes in this collector.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--builtins', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'Output already exists')
    record = analyze(args.binary.read_bytes(), args.builtins.read_bytes())
    args.output.mkdir(parents=False, mode=0o700)
    (args.output / 'record.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    (args.output / 'target-197.bin').write_bytes(bytes.fromhex(record['target']['body_hex']))
    for row in record['official']['definitions']:
        suffix = 'unmangled' if row['symbol']['name'] == '__umodti3' else 'mangled'
        (args.output / ('official-' + suffix + '-197.bin')).write_bytes(bytes.fromhex(row['body_hex']))
    print(json.dumps({'status': 'PASS', 'complete_native_rows': 68,
                      'selected_intervals': 1, 'raw_equal_bytes': SIZE, 'official_definitions': 2}))


if __name__ == '__main__':
    main()
