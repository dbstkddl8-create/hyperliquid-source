#!/usr/bin/env python3
"""Independent big-integer mathematical remainder corpus, before new Rust."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
B = 1 << 64
LIMIT = 1 << 128
MAX = LIMIT - 1
cases = []
seen = set()
def add(n, d, reason):
    if not (0 <= n < LIMIT and 0 < d < LIMIT) or (n, d) in seen:
        return
    seen.add((n, d))
    quotient, remainder = divmod(n, d)
    assert n == quotient * d + remainder and 0 <= remainder < d
    cases.append({'id': f'u{len(cases):06d}', 'n': f'{n:032x}', 'd': f'{d:032x}',
                  'remainder': f'{remainder:032x}', 'reason': reason})

edge = {0, 1, 2, 3, MAX, MAX-1}
for exponent in (1, 2, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 95, 96, 97, 126, 127):
    edge.update((1 << exponent) + delta for delta in (-1, 0, 1))
for n in sorted(edge):
    for d in sorted(edge - {0}):
        add(n, d, 'edge-cross-product')

for exponent in range(128):
    for delta in (-1, 0, 1):
        d = (1 << exponent) + delta
        if d <= 0 or d >= LIMIT:
            continue
        for n in (0, 1, d-1, d, d+1, MAX, MAX-1):
            add(n, d, f'divisor-exponent-{exponent}')
        for q in (1, 2, 3, 7, 255, (1 << 32)-1, 1 << 32, (1 << 64)-1):
            for difference in (-1, 0, 1):
                add(q*d + difference, d, f'quotient-boundary-{exponent}')

for bit in range(64):
    for delta in (-1, 0, 1):
        h = (1 << bit) + delta
        if not 0 < h < B:
            continue
        for low in (0, 1, (1 << 32)-1, 1 << 32, B//2, B-1):
            d = h*B + low
            for high_n in sorted({0, 1, h-1, h, min(h+1, B-1), B-1}):
                for low_n in sorted({0, 1, max(low-1, 0), low, min(low+1, B-1), B-1}):
                    add(high_n*B + low_n, d, f'normalization-shift-{bit+1}')

for low_d in (1, 2, 3, (1 << 31)-1, 1 << 31, (1 << 32)-1,
              1 << 32, (1 << 32)+1, (1 << 63)-1, 1 << 63, B-1):
    for high_n in sorted({0, 1, low_d-1, low_d, min(low_d+1, B-1),
                          (1 << 32)-1, 1 << 32, B-1}):
        for low_n in (0, 1, (1 << 32)-1, 1 << 32, B//2, B-1):
            add(high_n*B + low_n, low_d, 'low-limb-division-partition')

for ordinal in range(10000):
    raw = hashlib.sha256(b'umod197-independent-math-v1:' + str(ordinal).encode()).digest()
    n = int.from_bytes(raw[:16], 'big')
    d = int.from_bytes(raw[16:], 'big') or 1
    add(n, d, 'deterministic-hash-sample')

partition = {}
normalization_shifts = set()
for case in cases:
    n, d = int(case['n'], 16), int(case['d'], 16)
    a, high_n = n % B, n // B
    low_d, h = d % B, d // B
    if h == 0:
        if high_n < low_d:
            key = 'low-direct-div64'
        else:
            key = 'low-first-div32' if (high_n | low_d) < (1 << 32) else 'low-first-div64'
    else:
        s = h.bit_length()
        normalization_shifts.add(s)
        A = (d // (1 << s)) * (1 << s)
        q0 = n // A
        q = n // d
        assert q0 in (q, q+1)
        estimate = max(q0-1, 0)
        assert estimate in (q, q-1)
        residual = n-estimate*d
        assert 0 <= residual < 2*d
        key = 'high-correction' if residual >= d else 'high-no-correction'
    partition[key] = partition.get(key, 0) + 1

authority = {'schema': 'umod197-pre-source-mathematical-v1',
             'target_sha256': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
             'range': ['0x565f7f0', '0x565f8b5'], 'cases': cases,
             'native_mathematical_partitions': partition,
             'normalization_shifts': sorted(normalization_shifts),
             'limits': ['Mathematical divmod expectations frozen before new Rust/source review.',
                        'No captured native execution or instruction evaluator.',
                        'd=0 excluded by NonZeroU128; native hardware divide fault is not a normal remainder result.',
                        'No ABI padding, surrounding signals, whole-build or code-identity claim.']}
payload = (json.dumps(authority, sort_keys=True, indent=2) + '\n').encode()
(ROOT / 'umod197-authority.json').write_bytes(payload)
(ROOT / 'umod197-input.txt').write_text('\n'.join(f"{case['id']}|{case['n']}|{case['d']}" for case in cases) + '\n')
(ROOT / 'umod197-expected.txt').write_text('\n'.join(f"{case['id']}|{case['remainder']}" for case in cases) + '\n')
receipt = {'cases': len(cases), 'native_mathematical_partitions': partition,
           'normalization_shifts': sorted(normalization_shifts)}
for filename in ('umod197-authority.json', 'umod197-input.txt', 'umod197-expected.txt', 'generate_umod.py'):
    receipt[filename + '_sha256'] = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
(ROOT / 'umod197-freeze.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt, sort_keys=True))
