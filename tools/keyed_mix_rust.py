#!/usr/bin/env python3
"""Qualify only our Rust keyed-mix code against admitted static equations.

The captured executable is read as data, never launched or loaded for execution.
The linked clients receive only synthetic inputs, not their expected answers.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-keyed-mix-rust'
SOURCE = ROOT / 'src/node94-keyed-mix'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_contract():
    path = PACKET / 'contract.py'
    spec = importlib.util.spec_from_file_location('keyed_mix_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def qualify(binary, rustc, output):
    require(not output.exists(), 'Use a fresh output directory; prior results are immutable')
    contract = load_contract()
    freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
    require(digest(PACKET / 'contract.py') == freeze['contract_source_sha256'],
            'Pre-Rust contract source changed')
    require(freeze['new_rust_exists_at_freeze'] is False, 'Missing pre-Rust freeze')
    sys.path.insert(0, str(ROOT / 'tools'))
    admitted = contract.admit(binary)
    require(digest(binary) == freeze['target_sha256'], 'Target identity changed')
    require(admitted == freeze['admitted_static_facts'], 'Static admission changed')
    fresh_proof = {'cases': len(contract.corpus()), 'equation_mismatches': 0,
                   'full_domain_proof': False, 'method': 'fresh register-order and whole-integer equations'}
    vectors = (PACKET / 'preparation/target-vectors.tsv').read_bytes()
    require(hashlib.sha256(vectors).hexdigest() == freeze['vectors_sha256'],
            'Frozen expectations changed')
    require((SOURCE / 'target-vectors.tsv').read_bytes() == vectors, 'Rust fixtures changed')
    cases = contract.corpus()
    require(contract.vector_bytes() == vectors, 'Frozen vectors disagree with fresh equations')
    rows = vectors.decode().splitlines()
    stimuli = ('\n'.join('\t'.join(row.split('\t')[:9]) for row in rows) + '\n').encode()
    expected = ['\t'.join([row.split('\t')[0], row.split('\t')[9]]) for row in rows]
    source_before = {name: digest(SOURCE / name) for name in
                     ('lib.rs', 'client.rs', 'target-vectors.tsv')}
    output.mkdir(parents=True)
    commands = []
    private_commands = []

    def normalize_paths(value):
        # Keep original streams locally; public evidence omits personal paths.
        return (value.replace(str(output), '$WORK')
                .replace(str(ROOT), '$REPO').replace(str(Path.home()), '$HOME'))

    def run(label, argv, data=None, wanted=0):
        process = subprocess.run([str(value) for value in argv], cwd=ROOT,
                                 input=data, capture_output=True, timeout=120)
        private_commands.append({'label': label, 'argv': [str(value) for value in argv],
                                 'exit': process.returncode,
                                 'stdin_sha256': hashlib.sha256(data).hexdigest() if data else None,
                                 'stdout': process.stdout.decode('utf-8'),
                                 'stderr': process.stderr.decode('utf-8')})
        commands.append({'label': label, 'argv': [normalize_paths(str(value)) for value in argv],
                         'exit': process.returncode,
                         'stdin_sha256': hashlib.sha256(data).hexdigest() if data else None,
                         'stdout': normalize_paths(process.stdout.decode('utf-8')),
                         'stderr': normalize_paths(process.stderr.decode('utf-8'))})
        require(process.returncode == wanted, f'{label}: unexpected exit {process.returncode}')
        return process.stdout

    version = run('compiler-identity', [rustc, '-vV']).decode()
    require('release: 1.94.1\n' in version, 'Research compiler must be pinned Rust 1.94.1')
    production = (SOURCE / 'lib.rs').read_text()
    variants = [
        ('production-o0', production, 0, False),
        ('production-o3', production, 3, False),
        ('wrong-overlap', production.replace('word(12) ^ keys[0]', 'word(8) ^ keys[0]'), 3, True),
        ('drop-high-half', production.replace('(first >> 64) as u64', '0'), 3, True),
        ('wrong-length-constant', production.replace('^ 0x14;', '^ 0x10;'), 3, True),
    ]
    results = []
    for label, text, optimization, mutant in variants:
        require(not mutant or text != production, f'{label}: mutation was not applied')
        directory = output / label
        directory.mkdir()
        source = directory / 'lib.rs'
        source.write_text(text)
        shutil.copyfile(SOURCE / 'target-vectors.tsv', directory / 'target-vectors.tsv')
        library = directory / 'libnode94_keyed_mix.rlib'
        profile = ['--edition=2021', '-C', f'opt-level={optimization}',
                   '-C', 'overflow-checks=yes']
        run(label + '-library', [rustc, *profile, '--crate-name', 'node94_keyed_mix',
                               '--crate-type', 'rlib', '--emit=link,llvm-ir', source,
                               '-o', library])
        ir = directory / 'libnode94_keyed_mix.ll'
        definitions = [line for line in ir.read_text().splitlines()
                       if line.startswith('define ') and '9keyed_mix17h' in line]
        require(len(definitions) == 1, f'{label}: production function missing from emitted IR')
        client = directory / 'client'
        run(label + '-link', [rustc, *profile, SOURCE / 'client.rs', '--extern',
                            f'node94_keyed_mix={library}', '-o', client])
        actual = run(label + '-client', [client], data=stimuli).decode().splitlines()
        require(len(actual) == len(expected), f'{label}: incomplete client output')
        mismatches = sum(left != right for left, right in zip(actual, expected))
        require((mismatches > 0) == mutant, f'{label}: unexpected semantic comparison')
        unit = directory / 'unit-test'
        run(label + '-unit-build', [rustc, *profile, '--test', source, '-o', unit])
        run(label + '-unit', [unit], wanted=101 if mutant else 0)
        results.append({'variant': label, 'optimization': optimization,
                        'cases': len(actual), 'mismatches': mismatches,
                        'library_sha256': digest(library),
                        'library_bytes': library.stat().st_size,
                        'llvm_ir_sha256': digest(ir),
                        'own_function_ir_definition': definitions[0],
                        'mutant': mutant})
    require(source_before == {name: digest(SOURCE / name) for name in source_before},
            'Production sources changed during qualification')
    contract.admit(binary)
    result = {'target_sha256': freeze['target_sha256'], 'target_bytes': binary.stat().st_size,
              'admitted_static_facts': admitted, 'fresh_proof': fresh_proof,
              'production_sources_sha256': source_before, 'compiler_identity': version,
              'analysis_sources_sha256': {
                  str(path.relative_to(ROOT)): digest(path) for path in
                  (PACKET / 'contract.py', ROOT / 'tools/keyed_mix_rust.py',
                   ROOT / 'tools/foundation_keyed_multiply_xor_mixer.py',
                   ROOT / 'tools/elf_index.py')},
              'variants': results, 'captured_binary_executed': False,
              'production_client_received_expected_answers': False,
              'comparison_kind': 'own-Rust results versus fresh admitted static equations',
              'public_log_normalization': 'Paths only: output -> $WORK, repository -> $REPO, home -> $HOME; no numeric outputs or exits edited.',
              'raw_or_normalized_target_code_identity_claimed': False,
              'full_component_gate_requested': False}
    (output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    private_raw = json.dumps(private_commands, indent=2).encode() + b'\n'
    (output / 'RAW-LOGS-PRIVATE.json.gz').write_bytes(gzip.compress(private_raw, mtime=0))
    raw = json.dumps(commands, indent=2).encode() + b'\n'
    (output / 'RAW-LOGS.json.gz').write_bytes(gzip.compress(raw, mtime=0))
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        qualify(args.binary.resolve(), args.rustc.resolve(), args.output.resolve())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Keyed-mix qualification refused: {error}\n')


if __name__ == '__main__':
    main()
