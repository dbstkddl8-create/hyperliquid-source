"""Static node94 arithmetic projection; captured code is never executed."""
import hashlib
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[3]
MASK = (1 << 64) - 1
MULTIPLIER = 0x5851f42d4c957f2d
ADDEND = 0x14057b7ef767814f
MAGIC = 0x0c9714fbcda3ac11
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TABLE = bytes.fromhex(
    'fed3bba99c90877f78716b66615d5955514d4a4744413e3c39373532302e2c2a28'
    '27252321201e1d1b1a181715141312100f0e0d0c0a09080706050403020100')


def admit(binary):
    sys.path.insert(0, str(ROOT / 'tools'))
    from foundation_multiply_mix_div61 import inspect, TABLE as retained_table
    if retained_table != TABLE:
        raise ValueError('Table interpretation changed')
    result = inspect(binary)
    return {'window': list(result['window']), 'body_sha256': result['body_sha256'],
            'direct_callers': result['call_sites'], 'table_va': 0x801180,
            'table_sha256': hashlib.sha256(TABLE).hexdigest()}


def native_contract(words):
    """Register-order multiply-high division and low-word store."""
    state, raw = words
    rax = (MULTIPLIER * state) & MASK
    r8 = raw - (1 << 32) if raw & (1 << 31) else raw
    rax = (rax + ADDEND) & MASK
    updated = rax
    index = rax >> 58
    rsi = (TABLE[index] * r8) & MASK
    rdx = (MAGIC * rsi) >> 64
    rsi = (rsi - rdx) & MASK
    rsi >>= 1
    rdx = (rdx + rsi) & MASK
    rdx >>= 5
    return [updated, rdx & 0xffffffff, 1]


def mathematical_contract(words):
    state, raw = words
    updated = (MULTIPLIER * state + ADDEND) % (1 << 64)
    signed = (raw + (1 << 31)) % (1 << 32) - (1 << 31)
    product = (TABLE[updated // (1 << 58)] * signed) % (1 << 64)
    return [updated, (product // 61) % (1 << 32), 1]


def division_lemma():
    """Constants for the all-u64 integer argument documented in the packet."""
    assert 61 * ((1 << 64) + MAGIC) == (1 << 70) + 13
    assert 13 * ((1 << 64) - 1) < (1 << 70)
    return {'magic': hex(MAGIC), 'identity_remainder': 13,
            'maximum_correction_numerator': str(13 * ((1 << 64) - 1)),
            'correction_denominator_without_61': str(1 << 70),
            'scope': 'integer division-tail argument, not formal Rust/compiler equivalence'}


def corpus():
    inverse = pow(MULTIPLIER, -1, 1 << 64)
    fields = [-(1 << 31), -(1 << 31) + 1, -61, -1, 0, 1, 60, 61, 62,
              (1 << 31) - 2, (1 << 31) - 1]
    result = []
    for index in range(64):
        for low in [0, 1, (1 << 58) - 1]:
            mixed = (index << 58) | low
            state = ((mixed - ADDEND) * inverse) & MASK
            for field in fields:
                result.append([state, field % (1 << 32)])
    rng = random.Random(0x5553fe0)
    result += [[rng.getrandbits(64), rng.getrandbits(32)] for _ in range(1024)]
    return result


def vector_bytes():
    division_lemma()
    rows = []
    for index, words in enumerate(corpus()):
        expected = mathematical_contract(words)
        if native_contract(words) != expected:
            raise ValueError(f'Static equations disagree at case {index}')
        rows.append('\t'.join([str(index), *[f'{value:016x}' for value in words + expected]]))
    return ('\n'.join(rows) + '\n').encode()
