#!/usr/bin/env python3
"""Recover selected node 94 nested lattice-state reader decisions from ELF bytes."""
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

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FNS = (0x2dba370, 0x2bb0b50, 0x2b0cd60, 0x37a4a90, 0x37a4b30,
       0x2fe3140, 0x30c2a20, 0x300ad20, 0x315f920, 0x3094730)
PINS = (
    ('outer_classifier', 0x37a4a90, '4889f84883fa0c74624883fa0e74334883fa0d757248b96163636f756e747348330e48ba6374735f686173684883c20b483356054809ca754e31c9884801c60009c348b9636f6e747261637448330e48ba6374735f68617368483356064809ca7525b101884801c60009c348b973746f726167655f48330e8b56084881f2686173684809ca7409b103884801c60009c3b102884801c60009c3'),
    ('inner_classifier', 0x37a4b30, '4889f84883fa04744e4883fa07742c4883fa0a754a48b96e5f656c656d656e48330e0fb756084881f2747300004809ca752d31c9884801c60009c3b96e5f6279330eba7974657333560309ca7511b101884801c60009c3813e686173687409b103884801c60009c3b102884801c60009c3'),
    ('outer_sequence', 0x2dba85d, '80f9a00f83b103000080e10f0fb6e90fb746226685c00f846113000066ffc8668946220f846804000085ed0f84c6020000488dbc24306100004989f631d2'),
    ('outer_count', 0x2dbab30, '83fd03753c488dbc2468080000488db424b0280000ba30180000ff1590349b0231c0eb35488dbc24f0400000488d1545bc9102488d0d4eba910231f6e915010000c684246808000004c784246c08000003000000b8010000'),
    ('outer_map_dispatch', 0x2dbb6a4, '0fb64424503c090f85d6fdffff0fb6442451488d0d037d76fd486304814801c8ffe048837c2448010f8466040000488dbc24'),
    ('outer_duplicate_accounts', 0x2dbb6c6, '48837c2448010f8466040000488dbc24600800004d89fc4c89fe31d2e86954dfff'),
    ('outer_duplicate_contracts', 0x2dbb812, '48837c2440010f8454030000488dbc24600800004d89fc4c89fe'),
    ('outer_duplicate_storage', 0x2dbb754, '48837c2438010f84f5030000488dbc24600800004d89'),
    ('inner_sequence', 0x2bb116a, '80f9a00f837202000080e10f0fb6e90fb746226685c00f84150c000066ffc8668946220f84b803000085ed0f84a2010000488dbc24581000004989f6e8854bebff0fb68424581000003c090f858400000083fd010f84040200004c8bac2460100000488dbc24581000004c89f6e8544bebff0fb68424581000003c09755783fd020f84d70200004c8ba42460100000488dbc24581000004c89f6e8e7a8c30080bc245810000000747f0f108424601000'),
    ('inner_count', 0x2bb1319, '83fd037539488dbc2468200000488db42448080000ba10080000ff15a7ccbb0231c0eb32488d7c2438488d159f55b202488d0d6852b20231f6e989010000c684246820000004c784246c20000003000000b8010000'),
    ('inner_map_dispatch', 0x2bb1e56, '0fb68424601800003c090f85bc0200000fb6842461180000488d0d63178dfd486304814801c8ffe048837c2418010f847b030000'),
    ('inner_hash_branch', 0x2bb1ec9, '40f6c5010f8515030000488dbc24480800004d89fe4c89feba01000000e875aef5ff80bc244808000001'),
    ('inner_success', 0x2bb10de, 'ba000800004c89f741ffd5488b4424284889842438080000488b44242048898424400800'),
    ('array_loop', 0x2b0d370, '4539ef0f84930100004c89e74889dee80c85f5ff0fb64c24100fb644241180f9090f85980100004288842ca008000049ffc54981fd0008000075c5'),
    ('array_exact', 0x2b0d458, '4981ff00080000756f8b4424088b4c240b898c249c000000898424990000004088ac24a00000000fb6442406888424a10000000fb64424058884'),
    ('array_failure', 0x2b0d4d0, 'c68424a000000004c78424a400000000080000b001'),
    ('json_trailing', 0x2fe318c, '803b00755d488b4c2428488b5424304839ca7349488b74242048f7d948ffc248bf002600000100000031c0660f1f840000000000440fb64416ff4983f82077424c0fa3c7733c48895424304c8d041149ffc048ffc24983f80175d9eb0231c0488903488b'),
    ('json_outer_missing', 0x30c2fcf, '41f6c7010f8416020000f6442418010f8428020000f6442410010f843a020000'),
    ('json_outer_duplicate', 0x30c2e00, '48837c2410010f844b060000'),
    ('json_inner_duplicate', 0x315fd00, 'f6442420010f8572070000'),
    ('json_inner_hash', 0x315fd54, '4883fe3a0f85c70600004885c00f848107000049894628488d7c24504c89f6e8b849f3ff807c2450010f843b060000'),
    ('json_inner_stores', 0x316031b, 'dc6002488b44243848898308080000488b44243048898310080000'),
    ('json_root_call', 0x2fe3182, '488d742408e894f80d00'),
    ('json_hash_forms', 0x30947cf, '4183f82274744183f85b0f85a9020000'),
    ('json_hash_array', 0x30948f0, '4c89e74c89eee87565f9ff807c2420000f858e000000807c2421010f855b0100000fb64424224288443c4049ffc74981ff0008000075c9'),
    ('json_hash_string_length', 0x3094958, '488b7c24504881ff000800000f855b010000'),
 )


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'node 94 digest mismatch')


def at(data, secs, va, size):
    require(size > 0 and va >= 0, 'invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'unmapped or ambiguous file-backed VA')
    s = matches[0]
    off = s['offset'] + va - s['address']
    require(off + size <= len(data), 'section exceeds file')
    return bytes(data[off:off + size])


def check_pin(raw, expected):
    require(raw == bytes.fromhex(expected), 'selected instruction bytes differ')


def call(data, secs, va, target):
    raw = at(data, secs, va, 5)
    require(raw[0] == 0xe8, 'not a direct call')
    actual = va + 5 + struct.unpack_from('<i', raw, 1)[0]
    require(actual == target, 'call target differs')
    return {'site': hex(va), 'target': hex(actual), 'bytes': raw.hex()}


def table(data, secs, va, expected):
    raw = at(data, secs, va, 4 * len(expected))
    targets = [va + struct.unpack_from('<i', raw, 4 * i)[0] for i in range(len(expected))]
    require(targets == list(expected), 'dispatch entries differ')
    return {'base': hex(va), 'bytes': raw.hex(), 'targets': [hex(x) for x in targets]}


def rip_lea(data, secs, va, target):
    raw = at(data, secs, va, 7)
    require(raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and raw[2] & 0xc7 == 0x05,
            'not a RIP-relative lea')
    actual = va + 7 + struct.unpack_from('<i', raw, 3)[0]
    require(actual == target, 'RIP target differs')
    return {'site': hex(va), 'target': hex(actual), 'bytes': raw.hex()}


def conditional(data, secs, va, opcode, target):
    raw = at(data, secs, va, 6)
    require(raw[:2] == opcode, 'conditional opcode differs')
    actual = va + 6 + struct.unpack_from('<i', raw, 2)[0]
    require(actual == target, 'conditional target differs')
    return {'site': hex(va), 'target': hex(actual), 'bytes': raw.hex()}


def classify(key, names):
    return names.index(key) if key in names else len(names)


def extract(data):
    verify_digest(data)
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    selected = [f for f in fdes if f['start'] in FNS]
    require(len(selected) == len(FNS) and len({f['start'] for f in selected}) == len(FNS),
            'missing or duplicate FDE')
    selected.sort(key=lambda f: f['start'])
    funcs = []
    for f in selected:
        raw = at(data, secs, f['start'], f['end'] - f['start'])
        funcs.append({'start': hex(f['start']), 'end': hex(f['end']),
                      'fde': hex(f['fde']), 'body_sha256': hashlib.sha256(raw).hexdigest()})
    pins = []
    for name, va, expected in PINS:
        raw = at(data, secs, va, len(bytes.fromhex(expected)))
        check_pin(raw, expected)
        require(any(f['start'] <= va and va + len(raw) <= f['end'] for f in selected),
                'pin outside selected FDE')
        pins.append({'name': name, 'va': hex(va), 'bytes': raw.hex()})
    outer = [at(data, secs, va, n).decode('ascii') for va, n in
             ((0x5768c8, 13), (0x5768d5, 14), (0x5768e3, 12))]
    inner = [at(data, secs, va, n).decode('ascii') for va, n in
             ((0x576efd, 10), (0x576f07, 7), (0x209dbc, 4))]
    require(outer == ['accounts_hash', 'contracts_hash', 'storage_hash'] and
            inner == ['n_elements', 'n_bytes', 'hash'], 'field literals changed')
    edges = [(0x2dba89b, 0x2bb0b50), (0x2dba948, 0x2bb0b50),
             (0x2dba9e6, 0x2bb0b50), (0x2dbb6e2, 0x2bb0b50),
             (0x2dbb770, 0x2bb0b50), (0x2dbb82e, 0x2bb0b50),
             (0x2dbb653, 0x37a4a90), (0x2bb1c62, 0x37a4b30),
             (0x2bb1ee6, 0x2b0cd60), (0x2fe3187, 0x30c2a20),
             (0x30c2e74, 0x315f920), (0x30c2ed4, 0x315f920),
             (0x30c2f34, 0x315f920), (0x30c2fab, 0x300ad20),
             (0x30c3077, 0x300ad20), (0x30c30c6, 0x300ad20),
             (0x3c1606e, 0x2fe3140), (0x3c1615c, 0x2dba370),
             (0x315fd73, 0x3094730)]
    dispatch = [table(data, secs, 0x5233c0, (0x2dbb6c6, 0x2dbb812, 0x2dbb754, 0x2dbb7c7)),
                table(data, secs, 0x4835d8, (0x2bb1e7e, 0x2bb1fbc, 0x2bb1ec9, 0x2bb1f85))]
    references = [(0x2dbb99c, 0x5768c8), (0x2dbbafc, 0x5768d5),
                  (0x2dbbb1e, 0x5768e3), (0x2dbb9cd, 0x1df8f3),
                  (0x2dbbbb4, 0x1e0fd5), (0x2bb1043, 0x576efd),
                  (0x2bb177e, 0x576f07), (0x2bb16f0, 0x209dbc),
                  (0x2bb2261, 0x1e0fd5), (0x3160204, 0x57d879),
                  (0x3160221, 0x57d883), (0x316023e, 0x209dbc),
                  (0x3160272, 0x1df8f3), (0x31604ce, 0x1e0fd5),
                  (0x30c31ef, 0x57d247), (0x30c320c, 0x57d254),
                  (0x30c3229, 0x57d262), (0x30c3491, 0x57d247),
                  (0x30c3474, 0x57d254), (0x30c3457, 0x57d262)]
    for va, n, expected in ((0x57d247, 13, outer[0]), (0x57d254, 14, outer[1]),
                            (0x57d262, 12, outer[2]), (0x57d879, 10, inner[0]), (0x57d883, 7, inner[1]),
                            (0x1df8f4, 13, 'missing field'), (0x1e0fd6, 15, 'duplicate field')):
        require(at(data, secs, va, n).decode('ascii') == expected, 'diagnostic literal changed')
    path_ref = rip_lea(data, secs, 0x3269b8a, 0x201e63)
    path_bytes = at(data, secs, 0x201e63, 17)
    require(path_bytes == b'\xc0\x0f/lt_hashes.json', 'path template changed')
    loader_raw = at(data, secs, 0x3269bc2, 5)
    require(loader_raw[:1] == b'\xe8', 'loader call changed')
    loader_target = 0x3269bc2 + 5 + struct.unpack_from('<i', loader_raw, 1)[0]
    owner = [f for f in fdes if f['start'] == loader_target and
             f['start'] <= 0x3c1606e < 0x3c1615c < f['end']]
    require(len(owner) == 1, 'loader does not contain both contextual call sites')
    context = {'path_reference': path_ref, 'template_bytes': path_bytes.hex(),
               'loader_call_site': '0x3269bc2', 'loader_call_bytes': loader_raw.hex()}
    branches = [(0x2dbb6cc, b'\x0f\x84', 0x2dbbb38),
                (0x2dbb818, b'\x0f\x84', 0x2dbbb72),
                (0x2dbb75a, b'\x0f\x84', 0x2dbbb55),
                (0x2bb1e84, b'\x0f\x84', 0x2bb2205),
                (0x2bb1fc2, b'\x0f\x84', 0x2bb2222),
                (0x2bb1ecd, b'\x0f\x85', 0x2bb21e8)]
    payload_len = int.from_bytes(at(data, secs, 0x2b0d3a5, 4), 'little')
    require(payload_len == int.from_bytes(at(data, secs, 0x3094921, 4), 'little')
            == int.from_bytes(at(data, secs, 0x3094960, 4), 'little') == 2048,
            'selected payload widths differ')
    inner_copy = int.from_bytes(at(data, secs, 0x2bb110c, 4), 'little')
    outer_copy = int.from_bytes(at(data, secs, 0x2dbab46, 4), 'little')
    require(inner_copy == payload_len + 16 and outer_copy == inner_copy * 3,
            'selected record widths differ')
    mask_bytes = at(data, secs, 0x2fe31ad, 8)
    mask = int.from_bytes(mask_bytes, 'little')
    require(mask == 0x100002600, 'whitespace mask changed')
    whitespace = [i for i in range(33) if (mask >> i) & 1]
    return {'context': context, 'payload_bytes': payload_len, 'inner_copy_bytes': inner_copy,
            'outer_copy_bytes': outer_copy, 'json_trailing_whitespace_bytes': whitespace, 'target_sha256': DIGEST, 'coordinate': 'ELF linked virtual address',
            'functions': funcs, 'field_names': {'outer': outer, 'inner': inner},
            'pins': pins, 'calls': [call(data, secs, *edge) for edge in edges],
            'rip_references': [rip_lea(data, secs, *ref) for ref in references],
            'dispatch': dispatch,
            'duplicate_branches': [conditional(data, secs, *branch) for branch in branches]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record = extract(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
