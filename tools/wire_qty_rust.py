#!/usr/bin/env python3
"""Validate an independent Rust projection of the established node115 scalar cut.

Only newly authored Rust is executed. Target expectations use the accepted
split-limb equations and authenticated instruction operands, not target calls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import wire_qty_normal_form as native

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'src/node115-quantity-preparation'
PACKET = ROOT / 'research/work-items/RE-004-node115-quantity-preparation-rust'
FIXTURE = COMPONENT / 'target-vectors.tsv'
SOURCE = COMPONENT / 'lib.rs'
CRATE = 'node115_quantity_preparation'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    values = set(range(1001)) | {(1 << 63)-1, (1 << 63)-2}
    for edge in [1 << bit for bit in range(64)] + [10**n for n in range(19)]:
        values.update(n for n in range(edge-2, edge+3) if 0 <= n < 1 << 63)
    # Every exit scale, limb carry, maximal admitted multiple and eight-step cap.
    for zeros in range(10):
        unit = 10**zeros
        for coefficient in (1, 7, 9, 11, (1 << 32)-1, 1 << 32,
                            (1 << 32)+1, ((1 << 63)-1)//unit):
            n = coefficient*unit
            values.update(x for x in (n-1, n, n+1) if 0 <= x < 1 << 63)
    state = 0xb576a092e0341df7
    for _ in range(1024):
        state = (state*6364136223846793005+1442695040888963407) & native.U64
        values.add(state >> 1)
    return sorted(values)


def row(n, coefficient, scale):
    words = (scale << 16, 0, coefficient & native.U32, coefficient >> 32)
    return '\t'.join(map(str, (n, coefficient, scale, *words)))+'\n'


def oracle(binary=native.TARGET):
    data = Path(binary).read_bytes()
    need(len(data) == 105896032 and digest(data) == native.SHA,
         'pinned node115 identity mismatch')
    record = native.analyze(data)
    need(record == json.loads((native.PACKET/'records.json').read_text()),
         'accepted static records differ')
    parameters = native.parameters(data)
    lines = []
    for n in cases():
        coefficient, scale = native.limb_relation(n, parameters)
        # Independent decimal-string specification, not a second divide loop.
        text = str(n)
        removed = 0 if n == 0 else min(8, len(text)-len(text.rstrip('0')))
        reference = (0, 0) if n == 0 else (int(text[:len(text)-removed]), 8-removed)
        need((coefficient, scale) == reference, 'native equations disagree with decimal specification')
        lines.append(row(n, coefficient, scale))
    fixture = ''.join(lines).encode('ascii')
    inputs = ''.join(f'{n}\n' for n in cases()).encode('ascii')
    # Inputs outside the proven native normal-return cut are own-API refusals.
    policy = ''.join(f'{n}\n' for n in ((1 << 63), (1 << 63)+1, native.U64)).encode('ascii')
    return {'fixture': fixture, 'inputs': inputs, 'policy_inputs': policy,
            'parameters': parameters, 'record': record,
            'count': len(lines), 'fixture_sha256': digest(fixture)}


def target_controls(binary=native.TARGET):
    data = Path(binary).read_bytes()
    need(len(data) == 105896032 and digest(data) == native.SHA,
         'pinned node115 identity mismatch')
    params = native.parameters(data)
    results = []
    for name, address, replacement, witness in (
        ('inverse-five', 0x41c5861, 0xce, 5),
        ('low-reciprocal', 0x41c5858, 0, 10)):
        changed = bytearray(data)
        offset, _ = native.read(data, address, 1)
        changed[offset] = replacement
        observed = native.limb_relation(witness, native.parameters(changed))
        expected = native.limb_relation(witness, params)
        need(observed != expected, 'actual operand mutation lacks a semantic witness')
        try:
            native.analyze(changed)
        except ValueError as error:
            reason = str(error)
        else:
            raise ValueError('actual operand mutation was accepted')
        results.append({'name': name, 'address': hex(address), 'input': witness,
                        'expected': expected, 'mutated_relation': observed,
                        'rejected': reason, 'captured_program_executed': False})
    return results


DRIVER = '''extern crate node115_quantity_preparation;
use node115_quantity_preparation::prepare_quantity;
use std::io::{self, Write};
fn main() {
    let input = std::fs::read_to_string(std::env::args().nth(1).expect("input file"))
        .expect("read input-only corpus");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let n: u64 = line.parse().expect("u64 input");
        match prepare_quantity(n) {
            Ok(p) => {
                let w = p.prepared_words();
                writeln!(output, "{}\\t{}\\t{}\\t{}\\t{}\\t{}\\t{}",
                    n, p.coefficient, p.scale, w[0], w[1], w[2], w[3]).unwrap();
            }
            Err(_) => writeln!(output, "{}\\tunsupported", n).unwrap(),
        }
    }
}
'''


def build(binary, rustc, output, controls=False):
    output = Path(output).absolute()
    need(not output.exists(), 'output directory must be new')
    expected = oracle(binary)
    need(FIXTURE.read_bytes() == expected['fixture'], 'frozen fixture differs')
    rustc = Path(rustc).absolute()
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    need(version.startswith('rustc 1.94.1 '), 'repository research compiler must be Rust 1.94.1')
    linker = os.environ.get('RECONSTRUCTION_LINKER') or shutil.which('cc')
    need(linker is not None, 'host linker driver required')
    paths = (SOURCE, FIXTURE, Path(__file__), rustc, Path(linker))
    before = [digest(path.read_bytes()) for path in paths]
    output.mkdir(parents=True)
    (output/'inputs.txt').write_bytes(expected['inputs'])
    (output/'policy-inputs.txt').write_bytes(expected['policy_inputs'])
    (output/'driver.rs').write_text(DRIVER)
    (output/'expected.tsv').write_bytes(expected['fixture'])
    calls = []

    def execute(label, args, fail=False):
        process = subprocess.run(list(map(str, args)), cwd=ROOT, capture_output=True,
                                 stdin=subprocess.DEVNULL)
        for kind, raw in [('stdout', process.stdout), ('stderr', process.stderr)]:
            (output/(label+'.'+kind)).write_bytes(raw)
        calls.append({'label': label, 'exit': process.returncode,
                      'argv': [str(a).replace(str(output), '$OUTPUT').replace(str(ROOT), '$REPO')
                               .replace(str(rustc), '$RUSTC').replace(linker, '$LINKER') for a in args],
                      'stdout_sha256': digest(process.stdout),
                      'stderr_sha256': digest(process.stderr)})
        need(process.returncode != 0 if fail else process.returncode == 0,
             label+' unexpected exit; raw logs retained')
        return process.stdout

    def compile_and_compare(name, source, opt):
        folder = output/name
        folder.mkdir()
        library = folder/('lib'+CRATE+'.rlib')
        flags = ['--edition=2021', '-D', 'warnings', '-C', f'opt-level={opt}',
                 '-C', 'overflow-checks=on', '-C', 'codegen-units=1',
                 '-C', 'linker='+linker, '--remap-path-prefix', str(ROOT)+'=/reconstruction']
        execute(name+'-library', [rustc, '--crate-name', CRATE, '--crate-type=rlib',
                                source, '-o', library, *flags])
        driver = folder/'driver'
        execute(name+'-link', [rustc, output/'driver.rs', '--extern', CRATE+'='+str(library),
                             '-o', driver, *flags])
        actual = execute(name+'-run', [driver, output/'inputs.txt'])
        policy = execute(name+'-policy', [driver, output/'policy-inputs.txt'])
        need(policy == b''.join(line+b'\tunsupported\n' for line in expected['policy_inputs'].splitlines()),
             'own API refusal differs')
        return {'name': name, 'opt_level': opt, 'library_sha256': digest(library.read_bytes()),
                'actual_sha256': digest(actual), 'matches': actual == expected['fixture'],
                'mismatches': sum(a != b for a, b in zip(actual.splitlines(), expected['fixture'].splitlines())),
                'output_lines': len(actual.splitlines())}, flags, folder

    profiles = []
    for name, opt in [('debug', 0), ('optimized', 3)]:
        result, flags, folder = compile_and_compare(name, SOURCE, opt)
        need(result['matches'], name+' disagrees with authenticated split-limb equations')
        unit = folder/'tests'
        execute(name+'-test-build', [rustc, '--crate-name', CRATE, '--test', SOURCE, '-o', unit, *flags])
        actual = execute(name+'-tests', [unit])
        need(b'2 passed; 0 failed' in actual, 'both ordinary Rust tests must run')
        profiles.append(result)
    # Same source, same optimized recipe, distinct output directories.
    repeat, _, _ = compile_and_compare('optimized-repeat', SOURCE, 3)
    need(repeat['library_sha256'] == profiles[1]['library_sha256'], 'own library is not reproducible')
    mutants = []
    if controls:
        source = SOURCE.read_text()
        for name, old, new in [
            ('zero-scale', 'scale: 0,', 'scale: 8,'),
            ('seven-place-cap', 'let mut scale = 8;', 'let mut scale = 7;'),
            ('low-word-truncation', 'self.coefficient as u32', '(self.coefficient as u16) as u32')]:
            need(source.count(old) == 1, 'ambiguous Rust mutation site')
            folder = output/('source-'+name)
            folder.mkdir()
            path = folder/'lib.rs'
            path.write_text(source.replace(old, new))
            (folder/'target-vectors.tsv').write_bytes(expected['fixture'])
            result, flags, built = compile_and_compare('mutant-'+name, path, 0)
            need(not result['matches'] and result['mismatches'] > 0 and result['output_lines'] == expected['count'],
                 'compiled Rust mutant escaped value comparator')
            unit = built/'tests'
            execute(name+'-test-build', [rustc, '--crate-name', CRATE, '--test', path, '-o', unit, *flags])
            execute(name+'-tests', [unit], fail=True)
            mutants.append(result)
    need(before == [digest(path.read_bytes()) for path in paths], 'source/compiler/linker changed')
    data = Path(binary).read_bytes()
    need(digest(data) == native.SHA, 'target changed during comparison')
    result = {'status': 'PASS', 'target_sha256': native.SHA, 'compiler': version,
              'host_linker_version': subprocess.check_output([linker, '--version'], text=True),
              'sdkroot': os.environ.get('SDKROOT'),
              'source_compiler_linker_sha256': before, 'case_count': expected['count'],
              'expected_sha256': expected['fixture_sha256'], 'profiles': profiles,
              'own_optimized_library_raw_reproducible': True, 'rust_mutants': mutants,
              'target_controls': target_controls(binary) if controls else [], 'commands': calls,
              'captured_program_executed_or_emulated': False,
              'limits': 'Pure scalar/observed-word projection only; no original type, ABI, formatter, runtime or byte equivalence.'}
    (output/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=native.TARGET)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    try:
        result = build(args.binary, args.rustc, args.output, args.controls)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error)+'\n')
    print(json.dumps({'status': result['status'], 'cases_per_profile': result['case_count']}))
