#!/usr/bin/env python3
"""Build the real selector/decimal components and compare frozen requests.

Only our independently authored Rust, its input-only client and Rust unit tests
execute. Existing static parsing/objdump authenticates the native relation.
No captured target or PC/register/opcode evaluator executes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

import integer_digit_span_static as native

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-numeric-selector-94'
FROZEN = PACKET / 'independent-pre-source'
SOURCE = ROOT / 'src/node94-numeric-selector/lib.rs'
DRIVER = SOURCE.with_name('input_only_driver.rs')
DEPENDENCY = ROOT / 'src/node94-integer-digit-span/lib.rs'
TARGET = ROOT / 'artifacts/node/94/hl-node'
INPUT_SHA = 'fe077a7eb6d40ac36ee5b1f3c46dcf0941c5e766fddbfb66403f9ca39ce77b12'
EXPECTED_SHA = '23927ea2bddffcb7a29e75e7aef91ad94e949654519273dab5e1d167b602a9aa'
FREEZE_SHA = 'c43062c57d80907c3710ac18788f43c33359218a230ed6dd877163fef2ab994c'
DEPENDENCY_SHA = '51fbf04c59f82f4654bfcd9d1946e5a9792f13079a339dc0e675c1fd86472d83'
CASES = 8892
CRATE = 'node94_numeric_selector'
DECIMAL = 'node94_integer_digit_span'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def physical(path):
    path = Path(path)
    if path.is_symlink():
        raw = os.readlink(path).encode()
        return {'kind': 'symlink', 'bytes': len(raw), 'sha256': sha(raw)}
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(1 << 20), b''):
            h.update(raw)
            size += len(raw)
    return {'kind': 'file', 'bytes': size, 'sha256': h.hexdigest()}


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True,
                          capture_output=True).stdout


def audit(prefix, provider, provider_path, linker, ld):
    """Hash actual tracked files, seven actual repositories, source and provider."""
    files, pins = {}, {}
    def repository(repo, label):
        tracked = git(repo, 'ls-files', '--stage', '-z').split(b'\0')
        for row in tracked:
            if not row:
                continue
            metadata, raw_name = row.split(b'\t', 1)
            mode, oid, stage = metadata.decode().split(' ')
            need(stage == '0', 'Unmerged tracked input')
            name = raw_name.decode()
            relative = label + name
            path = repo / name
            if mode == '160000':
                actual = git(path, 'rev-parse', 'HEAD').decode().strip()
                state = git(path, 'status', '--porcelain=v1', '--untracked-files=all').decode()
                need(actual == oid and not state, 'Actual imported repository/pin changed: ' + relative)
                pins[relative] = {'index_oid': oid, 'actual_head': actual, 'actual_clean': True}
                repository(path, relative + '/')
            else:
                files[relative] = physical(path)
    repository(ROOT, '')
    need(len(pins) == 7, 'Expected the seven genuine pinned repositories')
    owned = [SOURCE, DRIVER, SOURCE.with_name('README.md'), Path(__file__),
             *sorted(FROZEN.iterdir())]
    for path in owned:
        files[str(path.relative_to(ROOT))] = physical(path)
    payloads = {}
    for item in provider['payloads']:
        record = physical(prefix / item['path'])
        need(record['sha256'] == item['sha256'] and record['bytes'] == item['bytes'],
             'Installed provider payload differs: ' + item['path'])
        payloads[item['path']] = record
    need(len(payloads) == 103, 'Expected103 authenticated provider payloads')
    return {'head': git(ROOT, 'rev-parse', 'HEAD').decode().strip(),
            'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'status': git(ROOT, 'status', '--porcelain=v1', '--untracked-files=all').decode(),
            'tracked_and_owned_physical_files': files, 'physical_file_count': len(files),
            'pins': pins, 'provider_payloads': payloads, 'provider_audit': physical(provider_path),
            'linker_driver': physical(linker), 'linker_ld_bfd': physical(ld)}


def compare(actual, expected):
    rows, answers = actual.splitlines(), expected.splitlines()
    need(len(rows) == len(answers) == CASES, 'Not a complete normal output denominator')
    differences = []
    for row, wanted in zip(rows, answers):
        fields, answer = row.split(b'\t'), wanted.split(b'\t')
        need(len(fields) == 10 and fields[0] == answer[0], 'Malformed/reordered output case')
        for index in (1, 2, 5, 6, 7, 8):
            need(fields[index].isdigit(), 'Malformed numeric output field')
        for index in (3, 4, 9):
            text = fields[index]
            need(text == b'-' or (len(text) % 2 == 0 and all(c in b'0123456789abcdef' for c in text)),
                 'Malformed hex output field')
        need(len(fields[3]) == 40, 'Incomplete final20-byte observation')
        if row != wanted:
            differences.append(answer[0].decode())
    return differences


def mutations(text):
    result = [
        ('both-flags-upper', 'if selection & LOWER != 0 {',
         'if selection & LOWER != 0 && selection & UPPER == 0 {', 'Both bits must select lower hex.'),
        ('uppercase-lower-alphabet', 'Some(b"0123456789ABCDEF")',
         'Some(b"0123456789abcdef")', 'Uppercase arm must use the actual upper alphabet.'),
        ('hex-prefix-empty', '(start, 16, b"0x")',
         '(start, 16, b"")', 'Both hexadecimal arms request lowercase0x.'),
        ('hex-end20', '(start, 16, b"0x")',
         '(start, 20, b"0x")', 'Hex digit slice ends at B+16, distinct from decimal B+20.'),
        ('zero-hex-empty', '        loop {\n            start -= 1;',
         '        while remaining != 0 {\n            start -= 1;', 'Zero emits one hexadecimal digit.'),
        ('raw-sign-zero', '            raw_sign: 1,',
         '            raw_sign: 0,', 'Sink raw sign is1 in every local arm.'),
        ('boolean-status', '    status\n}',
         '    u8::from(status != 0)\n}', 'Every lowAL byte is forwarded without boolean normalization.'),
        ('skip-callback-bit0', '    let status = sink(',
         '    if flags & 1 != 0 { return 0; }\n    let status = sink(', 'Other flag bits cannot bypass the one opaque sink.'),
        ('decimal-divided-input', 'write_decimal_suffix(value, buffer)',
         'write_decimal_suffix(value / 10, buffer)', 'Decimal dependency receives the original unsigned64 value.'),
    ]
    for name, needle, _, _ in result:
        need(text.count(needle) == 1, 'Mutation no longer uniquely matches source: ' + name)
    return result


def qualify(rustc, output, provider_path, controls):
    rustc, output, provider_path = (Path(p).absolute() for p in (rustc, output, provider_path))
    need(not output.exists(), 'Preserve existing outputs; choose a new output directory')
    need(sha((FROZEN / 'FREEZE.json').read_bytes()) == FREEZE_SHA, 'Pre-source seal changed')
    inputs, expected = ((FROZEN / name).read_bytes() for name in ('inputs.tsv', 'expected.tsv'))
    need(sha(inputs) == INPUT_SHA and sha(expected) == EXPECTED_SHA, 'Independent corpus identity changed')
    need(physical(DEPENDENCY)['sha256'] == DEPENDENCY_SHA, 'Real accepted decimal dependency changed')
    need(len(inputs.splitlines()) == CASES and not compare(expected, expected), 'Frozen denominator malformed')
    input_fields = [row.split(b'\t') for row in inputs.splitlines()]
    distinct_inputs = len({tuple(fields[1:]) for fields in input_fields})
    need(all(len(fields) == 6 for fields in input_fields) and distinct_inputs == CASES
         and len({fields[0] for fields in input_fields}) == CASES, 'Complete input tuples or IDs are not distinct')
    provider_raw = provider_path.read_bytes()
    need(sha(provider_raw) == '56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6',
         'Official103-payload provider admission changed')
    provider = json.loads(provider_raw)
    prefix = rustc.parent.parent
    linker = Path(shutil.which('cc')).resolve()
    ld = Path(shutil.which('ld.bfd')).resolve()
    before = audit(prefix, provider, provider_path, linker, ld)
    output.mkdir(parents=True)
    (output / 'BEFORE.json').write_text(json.dumps(before, indent=2, sort_keys=True) + '\n')
    proof = native.analyze(TARGET.read_bytes())
    need(proof['selector_context']['body_sha256'] == 'a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf',
         'Fresh full native selector body changed')
    (output / 'NATIVE-PROOF.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    (output / 'inputs.tsv').write_bytes(inputs)
    calls = []
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', NODE94_SELECTOR_FIXTURES=str(FROZEN))
    environment['PATH'] = '/usr/bin:/bin'
    for name in ('GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH'):
        environment.pop(name, None)
    def execute(label, argv, expected_exit=0):
        start = time.monotonic()
        command = [str(v) for v in argv]
        result = subprocess.run(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL, capture_output=True)
        streams = {}
        for kind, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            name = label + '.' + kind
            (output / name).write_bytes(raw)
            streams[kind] = {'file': name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': command, 'cwd': str(ROOT),
                      'build_variable_NODE94_SELECTOR_FIXTURES': str(FROZEN),
                      'PATH': '/usr/bin:/bin', 'removed_variables': ['GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH'],
                      'exit_code': result.returncode, 'seconds': round(time.monotonic() - start, 3), 'streams': streams})
        (output / 'CALLS.json').write_text(json.dumps(calls, indent=2) + '\n')
        need(result.returncode == expected_exit, label + ' unexpected exit; original streams preserved')
        return result
    try:
        identity = execute('rustc-identity', [rustc, '-vV']).stdout.decode()
        need('commit-hash: e408947bfd200af42db322daf0fadfe7e26d3bd1' in identity and 'release: 1.94.1' in identity,
             'Unexpected research compiler identity')
        linker_identity = execute('linker-identity', [linker, '--version']).stdout.decode()
        ld_identity = execute('ld-bfd-identity', [ld, '--version']).stdout.decode()
        def flags(opt):
            return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1', '-C', f'opt-level={opt}',
                    '-C', 'overflow-checks=on', '-C', 'linker=' + str(linker),
                    '-C', 'link-arg=-fuse-ld=bfd',
                    '--remap-path-prefix', str(ROOT) + '=/reconstruction']
        def library(label, source, crate, opt, folder, externs=()):
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / ('lib' + crate + '.rlib')
            execute(label, [rustc, '--crate-name', crate, '--crate-type=rlib', source, '-o', path,
                            '-C', 'metadata=node94-' + crate, *flags(opt), *externs])
            return path
        def ordinary(label, source, crate, opt, folder, externs=(), failure=False):
            program = folder / (crate + '-tests')
            execute(label + '-build', [rustc, '--crate-name', crate, '--test', source, '-o', program,
                                      *flags(opt), *externs])
            result = execute(label + '-run', [program, '--nocapture', '--test-threads=1'], 101 if failure else 0)
            need((b'panicked at' in result.stderr and b'FAILED' in result.stdout) if failure
                 else b'test result: ok.' in result.stdout, 'Actual ordinary unit result missing')
            return {'program': str(program), 'exit': result.returncode, 'semantic_assertion_failure': failure}
        def production(label, lib, decimal, opt, folder):
            program = folder / 'input-only-client'
            execute(label + '-link', [rustc, '--crate-name', 'selector_input_only_client', DRIVER,
                                     '--extern', CRATE + '=' + str(lib), '--extern', DECIMAL + '=' + str(decimal),
                                     '-L', 'dependency=' + str(decimal.parent), '-o', program, *flags(opt)])
            raw = execute(label + '-run', [program, output / 'inputs.tsv']).stdout
            return program, raw
        profiles = []
        for label, opt in [('debug', 0), ('optimized', 3)]:
            folder = output / label
            decimal = library(label + '-actual-decimal-library', DEPENDENCY, DECIMAL, opt, folder)
            dependency_tests = ordinary(label + '-actual-decimal', DEPENDENCY, DECIMAL, opt, folder)
            externs = ['--extern', DECIMAL + '=' + str(decimal)]
            lib = library(label + '-selector-library', SOURCE, CRATE, opt, folder, externs)
            units = ordinary(label + '-selector', SOURCE, CRATE, opt, folder, externs)
            program, raw = production(label + '-production', lib, decimal, opt, folder)
            need(not compare(raw, expected), label + ' differs from independent native-grounded requests')
            profiles.append({'name': label, 'opt_level': opt, 'cases': CASES, 'actual_sha256': sha(raw),
                             'selector_library': physical(lib), 'actual_decimal_library': physical(decimal),
                             'program': physical(program), 'dependency_units': dependency_tests, 'selector_units': units})
        reproducibility = [{'decimal': profiles[1]['actual_decimal_library'],
                            'selector': profiles[1]['selector_library'], 'client': profiles[1]['program']}]
        for label in ('repro-b',):
            folder = output / label
            decimal = library(label + '-actual-decimal', DEPENDENCY, DECIMAL, 3, folder)
            lib = library(label + '-selector', SOURCE, CRATE, 3, folder,
                          ['--extern', DECIMAL + '=' + str(decimal)])
            program, raw = production(label + '-production', lib, decimal, 3, folder)
            need(not compare(raw, expected), 'Own reproducibility output mismatch')
            reproducibility.append({'decimal': physical(decimal), 'selector': physical(lib), 'client': physical(program)})
        need(reproducibility[0] == reproducibility[1], 'Own two builds differ without normalization')
        semantic_controls = []
        text = SOURCE.read_text()
        if controls:
            decimal = output / 'debug' / ('lib' + DECIMAL + '.rlib')
            for name, needle, replacement, relation in mutations(text):
                folder = output / ('mutant-' + name)
                folder.mkdir()
                changed = folder / 'lib.rs'
                changed.write_text(text.replace(needle, replacement))
                externs = ['--extern', DECIMAL + '=' + str(decimal)]
                lib = library('mutant-' + name + '-library', changed, CRATE, 0, folder, externs)
                _, raw = production('mutant-' + name, lib, decimal, 0, folder)
                differences = compare(raw, expected)
                need(differences, 'Semantic mutant survived: ' + name)
                units = ordinary('mutant-' + name + '-ordinary', changed, CRATE, 0, folder, externs, failure=True)
                semantic_controls.append({'name': name, 'relation': relation, 'mutant_source': physical(changed),
                                          'cases': CASES, 'different_rows': len(differences), 'witnesses': differences[:8],
                                          'client_exit': 0, 'unit': units})
        comparator_controls = []
        lines = expected.splitlines(keepends=True)
        malformed = {'missing-row': b''.join(lines[:-1]), 'reordered': lines[1] + lines[0] + b''.join(lines[2:]),
                     'duplicate-id': lines[0] + lines[0] + b''.join(lines[2:])}
        for name, changed in malformed.items():
            rejected = False
            try:
                compare(changed, expected)
            except ValueError:
                rejected = True
            need(rejected, 'Comparator failed malformed control: ' + name)
            comparator_controls.append({'name': name, 'rejected': True, 'changed_sha256': sha(changed)})
        for name, index in [('status-byte', 8), ('digit-byte', 9), ('scratch-byte', 3)]:
            fields = lines[0].rstrip(b'\n').split(b'\t')
            fields[index] = b'1' if index == 8 else (b'1' if fields[index][:1] != b'1' else b'2') + fields[index][1:]
            changed = b'\t'.join(fields) + b'\n' + b''.join(lines[1:])
            differences = compare(changed, expected)
            need(differences == ['s00000'], 'Comparator missed selected byte control')
            comparator_controls.append({'name': name, 'different_rows': 1, 'changed_sha256': sha(changed)})
        after = audit(prefix, provider, provider_path, linker, ld)
        (output / 'AFTER.json').write_text(json.dumps(after, indent=2, sort_keys=True) + '\n')
        need(before == after, 'Actual tracked/source/pins/head/status/provider/linker inputs changed')
        result = {'status': 'PASS', 'schema': 'node94-selector-rust-qualification/1',
                  'target_sha256': native.SHA256, 'selector_bytes': 235, 'selector_rows': 63,
                  'compiler_identity': identity, 'provider_audit': physical(provider_path), 'linker_identity': linker_identity,
                  'ld_bfd_identity': ld_identity, 'python': sys.version, 'platform': platform.platform(),
                  'frozen_input_sha256': INPUT_SHA, 'independent_expected_sha256': EXPECTED_SHA,
                  'cases': CASES, 'distinct_complete_inputs': distinct_inputs,
                  'distinct_values_across_full_corpus': len({row.split(b'\t')[1] for row in inputs.splitlines()}),
                  'base_component_tree_lookup': git(ROOT, 'ls-tree', '3324e50333042b391312515e542279ca21f63dc8',
                                                    '--', 'src/node94-numeric-selector').decode(),
                  'profiles': profiles, 'own_reproducibility': {'builds': reproducibility, 'raw_equal': True,
                                                                'normalization': 'none', 'target_byte_equality_claimed': False},
                  'semantic_controls': semantic_controls, 'comparator_controls': comparator_controls,
                  'audit': {'unchanged': True, 'physical_files': before['physical_file_count'], 'pins': 7, 'provider_payloads': 103},
                  'calls': calls, 'full_current_repository_suite': 'NOT_RUN', 'captured_execution_or_evaluation': False,
                  'limits': ['Chosen safe scalar/request API, not original ABI/layout/pointer identity.',
                             'Opaque sink, fullG/rendering/padding/fill and hidden registers remain unqualified.',
                             'Input-only protocol is a data-flow constraint, not a filesystem sandbox.',
                             'All component gates remain false; no target-byte equivalence is claimed.']}
        (output / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        return result
    except Exception as error:
        (output / 'FAILURE.json').write_text(json.dumps({'error': str(error), 'calls': calls}, indent=2) + '\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--provider-audit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    result = qualify(args.rustc, args.output, args.provider_audit, args.controls)
    print(json.dumps({'status': result['status'], 'cases': result['cases'], 'commands': len(result['calls']),
                      'semantic_controls': len(result['semantic_controls']), 'audit': result['audit']}, sort_keys=True))


if __name__ == '__main__':
    main()
