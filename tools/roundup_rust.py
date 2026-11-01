#!/usr/bin/env python3
"""Compile only our Rust value projection; read captured node94 strictly as data."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-roundup-rust'
SOURCE = ROOT / 'src/node94-roundup'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def qualify(binary, rustc, output):
    require(not output.exists(), 'Use a fresh output directory')
    spec = importlib.util.spec_from_file_location('roundup_contract', PACKET / 'contract.py')
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
    require(digest(PACKET / 'contract.py') == freeze['contract_source_sha256'], 'Frozen contract changed')
    require(freeze['new_rust_exists_at_freeze'] is False, 'Missing pre-Rust freeze')
    require(contract.admit(binary) == freeze['admitted_static_facts'], 'Target admission changed')
    vectors = contract.vector_bytes()
    require(hashlib.sha256(vectors).hexdigest() == freeze['vectors_sha256'], 'Frozen expectations changed')
    require(vectors == (SOURCE / 'target-vectors.tsv').read_bytes(), 'Rust fixtures changed')
    require(vectors == (PACKET / 'preparation/target-vectors.tsv').read_bytes(), 'Preparation changed')
    rows = [row.split('\t') for row in vectors.decode().splitlines()]
    stimuli = ('\n'.join('\t'.join(row[:3]) for row in rows) + '\n').encode()
    expected = [row[0] + '\t' + row[3] for row in rows]
    output.mkdir(parents=True)
    commands = []
    def run(argv, stdin=None, allowed=(0,)):
        result = subprocess.run([str(x) for x in argv], input=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=ROOT, timeout=90)
        record = {'argv': [str(x) for x in argv], 'exit': result.returncode,
                  'stdout': result.stdout.decode(errors='replace'),
                  'stderr': result.stderr.decode(errors='replace')}
        commands.append(record)
        require(result.returncode in allowed, f'Command failed: {argv[0]}')
        return result
    version = run([rustc, '-Vv']).stdout.decode()
    source_hashes = {name: digest(SOURCE / name) for name in ('lib.rs', 'client.rs', 'target-vectors.tsv')}
    results = {'cases': len(rows), 'capture_executed': False, 'compiler': version,
               'source_sha256': source_hashes, 'target_sha256': digest(binary),
               'optimizations': {}, 'mutants': {}, 'full_domain_proof': False,
               'component_gates': [False, False, False, False]}
    def build_client(source, stem, opt):
        library = output / f'lib{stem}.rlib'
        common = [rustc, '--edition=2021', '-C', 'overflow-checks=yes', '-C', f'opt-level={opt}']
        run([*common, '--crate-name', 'node94_roundup', '--crate-type', 'rlib', source, '-o', library])
        client = output / stem
        run([*common, SOURCE / 'client.rs', '--extern', f'node94_roundup={library}', '-o', client])
        return client, common
    for opt in (0, 3):
        client, common = build_client(SOURCE / 'lib.rs', f'normal_O{opt}', opt)
        observed = run([client], stimuli).stdout
        actual = observed.decode().splitlines()
        require(len(actual) == len(expected), 'Client output count changed')
        mismatches = sum(a != b for a, b in zip(actual, expected))
        require(mismatches == 0, 'Rust/static-equation mismatch')
        ir = output / f'normal_O{opt}.ll'
        run([*common, '--crate-name', 'node94_roundup', '--crate-type', 'lib', '--emit=llvm-ir',
             SOURCE / 'lib.rs', '-o', ir])
        definitions = re.findall(r'^define [^\n]*8quotient17h[^\n]*\n.*?^}', ir.read_text(), re.M | re.S)
        require(len(definitions) == 1, 'Missing unique actual quotient definition')
        unit = output / f'unit_O{opt}'
        run([*common, '--test', SOURCE / 'lib.rs', '-o', unit])
        run([unit])
        (output / f'output_O{opt}.tsv').write_bytes(observed)
        results['optimizations'][str(opt)] = {'mismatches': mismatches, 'client_exit': 0,
            'client_sha256': digest(client), 'ir_definition_sha256': hashlib.sha256(definitions[0].encode()).hexdigest(),
            'output_sha256': hashlib.sha256(observed).hexdigest(), 'fixture_test_exit': 0}
    original = (SOURCE / 'lib.rs').read_text()
    (output / 'target-vectors.tsv').write_bytes(vectors)
    variants = {
        'wide_getter': original.replace('field.wrapping_add(1) as u64', 'field as u64 + 1'),
        'saturating_add': original.replace('x.wrapping_add(field as u64)', 'x.saturating_add(field as u64)'),
        'unadjusted_dividend': original.replace('x.wrapping_add(field as u64)', 'x'),
    }
    for name, source in variants.items():
        require(source != original, 'Mutant did not change source')
        path = output / f'{name}.rs'
        path.write_text(source)
        client, common = build_client(path, name, 3)
        observed = run([client], stimuli).stdout
        actual = observed.decode().splitlines()
        require(len(actual) == len(expected), 'Mutant count changed')
        count = sum(a != b for a, b in zip(actual, expected))
        require(count > 0, 'Compiled mutant survived')
        unit = output / f'{name}_test'
        run([*common, '--test', path, '-o', unit])
        unit_result = run([unit], allowed=(101,))
        results['mutants'][name] = {'mismatches': count, 'client_exit': 0,
                                   'fixture_test_exit': unit_result.returncode,
                                   'client_sha256': digest(client)}
    require(source_hashes == {name: digest(SOURCE / name) for name in source_hashes}, 'Source changed during qualification')
    (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    raw = json.dumps(commands, indent=2)
    (output / 'commands.private.json').write_text(raw + '\n')
    for old, new in ((str(ROOT), '$REPO'), (str(Path.home()), '$HOME')):
        raw = raw.replace(old, new)
    with gzip.GzipFile(filename=str(output / 'commands.json.gz'), mode='wb', mtime=0) as stream:
        stream.write((raw + '\n').encode())
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.binary, args.rustc, args.output_dir), indent=2))
