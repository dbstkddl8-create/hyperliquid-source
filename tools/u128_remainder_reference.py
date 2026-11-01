#!/usr/bin/env python3
"""Recheck independently frozen mathematical inputs against the native theorem.

Pure integer equations and authenticated bytes; no instruction evaluator.
"""
import gzip
import hashlib
import json
from pathlib import Path

import u128_remainder_contract as native

ROOT = Path(__file__).resolve().parents[1]
PREP = native.PACKET / 'preparation'
COMPONENT = ROOT / 'src/node94-u128-remainder'
EXPECTED_HASHES = {
    'umod197-authority.json': 'cd32cecfc28639873b8148e2e79e7de3180dc943d6c8f0b1bcc82297650f735e',
    'umod197-input.txt': 'a80b660cb1b6433fb4ee54c4fea09cbc26ba2b678f7c785f98b809a045dced87',
    'umod197-expected.txt': '6e0c8b72bb42e4fd6689954be0daef9346d20fd4e0bc02c26b60b52b41ec29e6',
}


def fresh(binary):
    data = Path(binary).read_bytes()
    native.need(len(data) == 91774280 and native.sha(data) == native.TARGET_SHA256,
                'Full target identity differs')
    certificate = native.inspect_target(data)['proof']
    raw = {name: gzip.decompress((PREP / (name + '.gz')).read_bytes()) for name in EXPECTED_HASHES}
    for name, digest in EXPECTED_HASHES.items():
        native.need(native.sha(raw[name]) == digest, 'Pre-source mathematical authority differs: ' + name)
    authority = json.loads(raw['umod197-authority.json'])
    cases = authority['cases']
    native.need(len(cases) == 53366, 'Frozen case denominator differs')
    inputs, expected = [], []
    partitions = {}
    word_base = 1 << 64
    for case in cases:
        identifier = case['id']
        n, d, wanted = (int(case[key], 16) for key in ('n', 'd', 'remainder'))
        native.need(0 <= n < 1 << 128 and 0 < d < 1 << 128, 'Frozen arithmetic domain differs')
        q, mathematical = divmod(n, d)
        native.need(mathematical == wanted and n == q*d + wanted and 0 <= wanted < d,
                    'Independent divmod expectation differs')
        a, b = n % word_base, n // word_base
        low, high = d % word_base, d // word_base
        if high:
            shift = high.bit_length()
            normalized = d // (1 << shift)
            estimate = (n // (2*normalized)) // (1 << (shift-1))
            predecessor = max(estimate-1, 0)
            residual = n-predecessor*d
            actual = residual-d if residual >= d else residual
            key = 'high-correction' if residual >= d else 'high-no-correction'
        else:
            actual = ((b % low)*word_base+a) % low
            key = ('low-direct-div64' if b < low else
                   'low-first-div32' if (b | low) < 1 << 32 else 'low-first-div64')
        native.need(actual == wanted, 'Bound native integer equations disagree with independent authority')
        partitions[key] = partitions.get(key, 0) + 1
        inputs.append(f"{identifier}|{n:032x}|{d:032x}\n")
        expected.append(f"{identifier}|{wanted:032x}\n")
    encoded_inputs, encoded_expected = ''.join(inputs).encode(), ''.join(expected).encode()
    native.need(encoded_inputs == raw['umod197-input.txt'] and encoded_expected == raw['umod197-expected.txt'],
                'Frozen input/expectation transcripts differ')
    native.need(partitions == authority['native_mathematical_partitions'], 'Native partition denominator differs')
    fixture = (COMPONENT / 'unit-vectors.tsv').read_bytes()
    frozen_fixture = json.loads((PREP / 'UNIT-FIXTURE-FREEZE.json').read_text())
    native.need(native.sha(fixture) == frozen_fixture['fixture_sha256'] and not frozen_fixture['lib_rs_existed'],
                'Compact pre-Rust ordinary-unit fixture differs')
    by_id = {case['id']: case for case in cases}
    for line in fixture.decode().splitlines()[1:]:
        identifier, n, d, r = line.split('\t')
        case = by_id[identifier]
        native.need((n, d, r) == (case['n'], case['d'], case['remainder']), 'Unit fixture is outside frozen authority')
    return {'cases': cases, 'inputs': encoded_inputs, 'expected': encoded_expected,
            'fixture': fixture, 'native_proof': certificate,
            'metadata': {'case_count': len(cases), 'ordinary_unit_fixture_cases': frozen_fixture['cases'],
                         'pre_Rust_hashes': EXPECTED_HASHES, 'native_equations_matches': len(cases),
                         'native_mathematical_partitions': partitions,
                         'normalization_shifts': authority['normalization_shifts'],
                         'target_sha256': native.TARGET_SHA256, 'native_body_sha256': native.BODY_SHA256,
                         'independent_method': 'Pre-source big-integer divmod plus Euclidean identity; fresh native integer equations',
                         'native_instruction_execution': False}}
