"""Static numeric equations for node94 0x399c600; no captured execution."""
import hashlib
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[3]
MASK = (1 << 64) - 1
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def admit(binary):
    data = Path(binary).read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('Wrong complete node94 capture')
    sys.path.insert(0, str(ROOT / 'tools'))
    from foundation_keyed_multiply_xor_mixer import analyze, START, END, CALLERS
    body = analyze(data)
    return {'window': [START, END], 'body_sha256': hashlib.sha256(body).hexdigest(),
            'direct_callers': [row[4] for row in CALLERS],
            'runtime_key_words': 'GOT-indirected values supplied explicitly; initialization unknown'}


def block_bytes(words):
    return b''.join(word.to_bytes(4, 'little') for word in words[:5])


def native_contract(words):
    """Register-order arithmetic read from the retained straight-line instructions."""
    block = block_bytes(words)
    seed, key0, key1 = words[5:]
    r9 = key0
    rax = int.from_bytes(block[12:20], 'little') ^ r9
    r10 = int.from_bytes(block[0:8], 'little')
    rdx = int.from_bytes(block[8:16], 'little') ^ key1
    product = rax * rdx
    rcx, r8 = product & MASK, product >> 64
    rax = int.from_bytes(block[4:12], 'little') ^ r9
    r10 ^= seed
    product = rax * r10
    r8 ^= product >> 64
    rax = (product & MASK) ^ rcx ^ r8 ^ 0x14
    product = rax * r9
    return [(product & MASK) ^ (product >> 64)]


def mathematical_contract(words):
    """Whole-integer byte-window model, independent of register assignments."""
    stream = sum(value << (32 * index) for index, value in enumerate(words[:5]))
    seed, key0, key1 = words[5:]
    q = [(stream >> (32 * index)) & MASK for index in range(4)]
    products = [(q[3] ^ key0) * (q[2] ^ key1), (q[1] ^ key0) * (q[0] ^ seed)]
    folded = 20
    for product in products:
        low, high = product % (1 << 64), product // (1 << 64)
        folded ^= low ^ high
    final = folded * key0
    return [(final ^ (final >> 64)) & MASK]


def corpus():
    result = []
    edges = [0, 1, 1 << 63, MASK - 1, MASK]
    for fill in [0, 0xffffffff, 0xaaaaaaaa, 0x55555555]:
        for seed in edges:
            for key0 in edges:
                for key1 in edges:
                    result.append([fill] * 5 + [seed, key0, key1])
    for bit in range(160):
        words = [0] * 5
        words[bit // 32] = 1 << (bit % 32)
        result += [words + [0, 1, MASK], words + [MASK, MASK, 1]]
    rng = random.Random(0x399c600)
    result += [[rng.getrandbits(32) for _ in range(5)] +
               [rng.getrandbits(64) for _ in range(3)] for _ in range(1024)]
    return result


def vector_bytes():
    rows = []
    for index, words in enumerate(corpus()):
        expected = mathematical_contract(words)
        if native_contract(words) != expected:
            raise ValueError(f'Static equations disagree at case {index}')
        rows.append('\t'.join([str(index), *[f'{value:016x}' for value in words + expected]]))
    return ('\n'.join(rows) + '\n').encode()
