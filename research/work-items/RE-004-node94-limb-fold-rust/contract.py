#!/usr/bin/env python3
"""Static numeric contract for the admitted 123-byte node94 limb-fold leaf.

No captured instruction is executed. These manually derived equations are not
an emulator or a general decoder. Calling the pure equations alone is unqualified;
the CLI first authenticates the complete capture and existing FDE/byte packet.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[3]
MASK64 = (1 << 64) - 1
MASK52 = (1 << 52) - 1
MASK48 = (1 << 48) - 1
COEFFICIENT = (1 << 32) + 977


def native_contract(words):
    """Register data flow derived from the locked instruction listing."""
    a, b, c, d, high = words
    r8 = high & MASK48
    rdx = (((high >> 48) * COEFFICIENT) + a) & MASK64
    r9 = ((rdx >> 52) + b) & MASK64
    out0 = rdx & MASK52
    rdi = ((r9 >> 52) + c) & MASK64
    out1 = r9 & MASK52
    rcx = ((rdi >> 52) + d) & MASK64
    out2 = rdi & MASK52
    rsi = rcx & MASK52
    rcx = ((rcx >> 52) + r8) & MASK64
    return [out0, out1, out2, rsi, rcx]


def proof():
    import z3
    words = z3.BitVecs('a b c d high', 64)
    a, b, c, d, high = words
    r8 = high & MASK48
    rdx = z3.LShR(high, 48) * COEFFICIENT + a
    r9 = z3.LShR(rdx, 52) + b
    rdi = z3.LShR(r9, 52) + c
    rcx = z3.LShR(rdi, 52) + d
    native = [rdx & MASK52, r9 & MASK52, rdi & MASK52,
              rcx & MASK52, z3.LShR(rcx, 52) + r8]

    def reconstruction(discard_wrap=True, coefficient=COEFFICIENT):
        carry = z3.LShR(high, 48) * coefficient
        result = []
        for value in words[:4]:
            wide = z3.ZeroExt(64, value) + z3.ZeroExt(64, carry)
            wrapped = z3.Extract(63, 0, wide)
            result.append(wrapped & MASK52)
            carry = (z3.LShR(wrapped, 52) if discard_wrap
                     else z3.Extract(63, 0, z3.LShR(wide, 52)))
        return result + [carry + (high & MASK48)]

    checks = {}
    for name, candidate, wanted in [
        ('full_320_bit_numeric_domain', reconstruction(), 'unsat'),
        ('wrong_coefficient_control', reconstruction(coefficient=COEFFICIENT + 1), 'sat'),
        ('keep_discarded_bit64_control', reconstruction(discard_wrap=False), 'sat'),
    ]:
        solver = z3.Solver()
        solver.set(timeout=30000)
        solver.add(z3.Or(*[left != right for left, right in zip(native, candidate)]))
        status = str(solver.check())
        if status != wanted:
            raise ValueError(f'{name}: expected {wanted}, observed {status}')
        row = {'result': status}
        if status == 'sat':
            model = solver.model()
            inputs = [model.eval(word, model_completion=True).as_long() for word in words]
            row['counterexample'] = [hex(value) for value in inputs]
            row['native_output'] = [hex(value) for value in native_contract(inputs)]
        checks[name] = row
    return {'solver': z3.get_version_string(), 'checks': checks}


def corpus():
    cases = [[0] * 5, [MASK64] * 5]
    values = [0, 1, MASK52 - 1, MASK52, 1 << 52, MASK64 - 1, MASK64]
    for index in range(5):
        for value in values:
            item = [0] * 5
            item[index] = value
            cases.append(item)
    for high in [0, 1, MASK48, 1 << 48, (1 << 48) + 1, 1 << 63, MASK64]:
        cases.append([MASK52] * 4 + [high])
        cases.append([MASK64] * 4 + [high])
    random_source = random.Random(20261101)
    cases += [[random_source.getrandbits(64) for _ in range(5)] for _ in range(1024)]
    cases += [[random_source.getrandbits(52) for _ in range(5)] for _ in range(256)]
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / 'tools'))
    from foundation_multi_limb_multiply_accumulate import inspect
    admitted = inspect(args.binary)
    results = proof()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = corpus()
    rows = [str(index) + '\t' + '\t'.join(f'{value:016x}' for value in
            words + native_contract(words)) for index, words in enumerate(cases)]
    vectors = ('\n'.join(rows) + '\n').encode()
    (args.output / 'target-vectors.tsv').write_bytes(vectors)
    results.update({
        'target_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        'admitted_static_facts': admitted,
        'capture_executed': False,
        'new_rust_exists_at_freeze': (ROOT / 'src/node94-limb-fold/lib.rs').exists(),
        'vector_count': len(cases),
        'vectors_sha256': hashlib.sha256(vectors).hexdigest(),
        'contract_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'interpretation': 'Static equation proof and finite numeric cases; not dynamic target equivalence.',
    })
    (args.output / 'ORACLE-FREEZE.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
