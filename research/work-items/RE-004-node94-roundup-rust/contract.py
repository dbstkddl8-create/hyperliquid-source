"""Pre-Rust static value contract, not a target-execution oracle."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
FOUNDATION = ROOT / 'research/work-items/foundation-round-up-division-94'
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1


def admit(binary):
    path = ROOT / 'tools/foundation_round_up_division.py'
    spec = importlib.util.spec_from_file_location('roundup_admission', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = json.loads((FOUNDATION / 'evidence.json').read_text())
    data = Path(binary).read_bytes()
    module.run_evidence(evidence, data, module.elf_sections(data), str(FOUNDATION))
    return {'target_sha256': hashlib.sha256(data).hexdigest(),
            'target_bytes': len(data),
            'function': evidence['function'], 'callee': evidence['callee'],
            'incoming': evidence['incoming'],
            'foundation_evidence_sha256': digest(FOUNDATION / 'evidence.json'),
            'checker_sha256': digest(path)}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def registers(field, x):
    """32-bit getter, zeroed RDX, LEA EAX, ADD RAX without ADC, unsigned DIV."""
    eax = (field + 1) & U32
    ecx = eax
    eax = (eax - 1) & U32
    rax = (eax + x) & U64
    if ecx == 0:
        return None
    return divmod(rax, ecx)[0]


def integers(field, x):
    """Independent whole-integer expression, including the non-ceiling wrap."""
    if field == U32:
        return None
    numerator = x + field
    if numerator >= 1 << 64:
        numerator -= 1 << 64
    return numerator // (field + 1)


def corpus():
    pairs = set()
    fields = [0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 65535,
              (1 << 31) - 1, 1 << 31, U32 - 1, U32]
    for field in fields:
        xs = {0, 1, 2, 3, U32 - 1, U32, U32 + 1, U64 - 1, U64}
        for center in [U64 - field, (1 << 64) - field,
                       field + 1, 2 * (field + 1), (field + 1) * U32]:
            xs.update(x for x in range(center - 2, center + 3) if 0 <= x <= U64)
        pairs.update((field, x) for x in xs)
    rng = random.Random(20261101)
    pairs.update((rng.getrandbits(32), rng.getrandbits(64)) for _ in range(2048))
    return sorted(pairs)


def vector_bytes():
    rows = []
    for index, (field, x) in enumerate(corpus()):
        value = registers(field, x)
        if value != integers(field, x):
            raise ValueError('Independent equations disagree')
        rows.append(f'{index}\t{field}\t{x}\t' + ('fault' if value is None else str(value)))
    return ('\n'.join(rows) + '\n').encode()


def freeze(binary):
    if (ROOT / 'src/node94-roundup/lib.rs').exists():
        raise ValueError('Freeze must precede the new Rust source')
    preparation = PACKET / 'preparation'
    preparation.mkdir()
    facts = admit(binary)
    vectors = vector_bytes()
    (preparation / 'target-vectors.tsv').write_bytes(vectors)
    manifest = {'method': 'static admitted instructions; register-order vs integer equations',
                'new_rust_exists_at_freeze': False, 'cases': len(corpus()),
                'equation_mismatches': 0, 'full_domain_proof': False,
                'contract_source_sha256': digest(__file__),
                'vectors_sha256': hashlib.sha256(vectors).hexdigest(),
                'admitted_static_facts': facts}
    (preparation / 'ORACLE-FREEZE.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    print(json.dumps(freeze(Path(sys.argv[1])), indent=2))
