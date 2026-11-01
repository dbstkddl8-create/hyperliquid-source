#!/usr/bin/env python3
"""Manually derived, static numeric projection; never executes captured code."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[3]
MASK = (1 << 64) - 1


def native_contract(words):
    left, right = words[:4], words[4:]
    out, borrow = [], 0
    for a, b in zip(left[:3], right[:3]):
        value = a - b - borrow
        out.append(value & MASK)
        borrow = int(value < 0)
    # The captured top limb uses SUB, restores the incoming CF through ADD CL,FF,
    # then SBB RAX,0. Its two outgoing borrows are ORed and masked to one bit.
    temporary = (left[3] - right[3]) & MASK
    first = left[3] < right[3]
    last = temporary < borrow
    out.append((temporary - borrow) & MASK)
    return out + [int(first or last)]


def mathematical_contract(words):
    a = sum(word << (64 * i) for i, word in enumerate(words[:4]))
    b = sum(word << (64 * i) for i, word in enumerate(words[4:]))
    difference = (a - b) % (1 << 256)
    return [(difference >> (64 * i)) & MASK for i in range(4)] + [int(a < b)]


def proof():
    import z3
    words = z3.BitVecs('a0 a1 a2 a3 b0 b1 b2 b3', 64)
    left, right = words[:4], words[4:]
    zero = z3.BitVecVal(0, 64)
    one = z3.BitVecVal(1, 64)
    borrow, native = z3.BoolVal(False), []
    for a, b in zip(left[:3], right[:3]):
        incoming = z3.If(borrow, one, zero)
        native.append(a - b - incoming)
        borrow = z3.Or(z3.ULT(a, b), z3.And(a == b, borrow))
    temporary = left[3] - right[3]
    first = z3.ULT(left[3], right[3])
    last = z3.And(temporary == 0, borrow)
    native.append(temporary - z3.If(borrow, one, zero))
    native.append(z3.If(z3.Or(first, last), one, zero))
    a = z3.Concat(*reversed(left))
    b = z3.Concat(*reversed(right))
    difference = a - b
    expected = [z3.Extract(64 * i + 63, 64 * i, difference) for i in range(4)]
    expected.append(z3.If(z3.ULT(a, b), one, zero))
    checks = {}
    for name, candidate, wanted in [
        ('full_512_bit_numeric_domain', native, 'unsat'),
        ('top_borrow_and_control', native[:4] + [z3.If(z3.And(first, last), one, zero)], 'sat'),
        ('drop_incoming_top_borrow_control', native[:3] + [temporary, native[4]], 'sat'),
    ]:
        solver = z3.Solver()
        solver.set(timeout=30000)
        solver.add(z3.Or(*[x != y for x, y in zip(expected, candidate)]))
        status = str(solver.check())
        if status != wanted:
            raise ValueError(f'{name}: expected {wanted}, got {status}')
        result = {'result': status}
        if status == 'sat':
            model = solver.model()
            values = [model.eval(word, model_completion=True).as_long() for word in words]
            result['counterexample'] = [hex(value) for value in values]
            result['native_output'] = [hex(value) for value in native_contract(values)]
        checks[name] = result
    return {'solver': z3.get_version_string(), 'checks': checks}


def corpus():
    cases = [[0] * 8, [MASK] * 8, [0] * 4 + [MASK] * 4, [MASK] * 4 + [0] * 4]
    for i in range(8):
        for edge in [0, 1, 2, (1 << 63) - 1, 1 << 63, MASK - 1, MASK]:
            words = [0] * 8
            words[i] = edge
            cases.append(words)
    for i in range(4):
        for top in [0, 1, MASK]:
            a, b = [0] * 4, [0] * 4
            a[3], b[i] = top, 1
            cases.append(a + b)
    rng = random.Random(20261102)
    cases += [[rng.getrandbits(64) for _ in range(8)] for _ in range(1024)]
    for _ in range(256):
        a = [rng.getrandbits(64) for _ in range(4)]
        cases.append(a + a)
    for words in cases:
        if native_contract(words) != mathematical_contract(words):
            raise ValueError('Native equations disagree with whole-integer oracle')
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / 'tools'))
    from foundation_wrapping_subtract_borrow_out import analyze
    admitted = analyze(args.binary.read_bytes())
    results = proof()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = [str(i) + '\t' + '\t'.join(f'{x:016x}' for x in words + mathematical_contract(words))
            for i, words in enumerate(corpus())]
    vectors = ('\n'.join(rows) + '\n').encode()
    (args.output / 'target-vectors.tsv').write_bytes(vectors)
    results.update({'target_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                    'admitted_static_facts': admitted, 'capture_executed': False,
                    'new_rust_exists_at_freeze': (ROOT / 'src/node94-wide-subtract/lib.rs').exists(),
                    'vector_count': len(rows), 'vectors_sha256': hashlib.sha256(vectors).hexdigest(),
                    'contract_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    (args.output / 'ORACLE-FREEZE.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
