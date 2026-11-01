#!/usr/bin/env python3
"""Independently inspect actual compiled outputs and optionally run own Rust."""
import argparse
import gzip
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = HERE.parent / 'formatter-build-c2'
REPO = HERE.parent / 'formatter'
PACKET = REPO / 'research/work-items/RE-001-format-request-controller-94'
sha = lambda data: hashlib.sha256(data).hexdigest()
read_json = lambda path: json.loads(path.read_bytes())
parser = argparse.ArgumentParser()
parser.add_argument('--rerun-own-client', action='store_true')
args = parser.parse_args()
expected_raw = (HERE / 'formatter448-expected.jsonl').read_bytes()
expected = [json.loads(line) for line in expected_raw.splitlines()]
inputs = (HERE / 'formatter448-input.tsv').read_bytes()
assert sha(inputs) == '103fe7f7011bce8e17530c81fa04cdcba3cfc6807a075d4c3b6cdad51c224e6f'
assert sha(expected_raw) == '28a522a485af79a8c54f93fc5a702e21012b9466d3476ff64c97e9f1a8d5358e'
assert len(expected) == 1066
result = read_json(RUN / 'result.json')
before = read_json(RUN / 'before.json')
after = read_json(RUN / 'after.json')
assert before == after and before['head'] == '63621fb578c1dd717722f2ddb5f6e937b53f469c'
assert before['status'] == ''
for relative, expected_sha in before['sources'].items():
    assert sha((REPO / relative).read_bytes()) == expected_sha, relative
assert before['sources']['tools/format_request_protocol.py'] == '153c1e79be2e59859ebf9605e90d6b58bf67b37b45e66c6fa7bb59a1b27d06a2'
ledger = read_json(RUN / 'commands.json')
labels = {command['label']: command for command in ledger}
assert len(labels) == len(ledger)
raw = {}
for command in ledger:
    assert command['exit'] == (128 if command['label'] == 'base-production-absent' else 0)
    for stream in ('stdout', 'stderr'):
        stream_raw = gzip.decompress((RUN / (command['label'] + '.' + stream + '.gz')).read_bytes())
        assert sha(stream_raw) == command[stream + '_sha256']
        raw[command['label'], stream] = stream_raw
    if command['stdin_sha256'] is not None:
        assert command['stdin_sha256'] == sha(inputs)

profiles = []
for profile in result['profiles']:
    level = profile['opt_level']
    prefix = RUN / ('opt' + str(level))
    library = prefix / 'libnode94_format_request_protocol.rlib'
    driver = prefix / 'input-only'
    assert sha(library.read_bytes()) == profile['rlib_sha256']
    assert sha(driver.read_bytes()) == profile['driver_sha256']
    assert library.read_bytes() == (prefix / 'rebuild' / library.name).read_bytes()
    actual = [json.loads(line) for line in raw[f'opt{level}-observations', 'stdout'].splitlines()]
    assert actual == expected
    test_output = raw[f'opt{level}-tests-run', 'stdout']
    assert b'3 passed; 0 failed' in test_output
    profiles.append({'opt_level': level, 'matched_full_transcripts': len(actual),
                     'native_domain_cases': sum(case['status'] != 'refused' for case in actual),
                     'safe_refusals': sum(case['status'] == 'refused' for case in actual),
                     'raw_rlib_rebuild_equal': True, 'rlib_sha256': sha(library.read_bytes()),
                     'driver_sha256': sha(driver.read_bytes())})

mutants = []
for mutant in result['mutants']:
    name = mutant['name']
    assert sha((RUN / name / 'lib.rs').read_bytes()) == mutant['source_sha256']
    actual = [json.loads(line) for line in raw[name + '-observations', 'stdout'].splitlines()]
    assert len(actual) == len(expected)
    mismatch_ids = [want['id'] for got, want in zip(actual, expected) if got != want]
    assert mismatch_ids == mutant['mismatch_ids'] and len(mismatch_ids) == mutant['mismatches'] > 0
    mutants.append({'name': name, 'mismatches': len(mismatch_ids), 'source_sha256': mutant['source_sha256']})
assert [mutant['mismatches'] for mutant in mutants] == [254, 66, 98, 4]

audit_raw = (PACKET / 'provider/PROVIDER-AUDIT.json').read_bytes()
assert sha(audit_raw) == '56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6'
audit = json.loads(audit_raw)
prefix = HERE.parent / 'toolchain/prefix'
assert len(audit['payloads']) == 103
for record in audit['payloads']:
    relative = Path(record['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    payload = (prefix / relative).read_bytes()
    assert sha(payload) == record['sha256'] and len(payload) == record['bytes']
for filename, expected_sha in audit['installed_manifest_sha256'].items():
    assert sha((prefix / 'lib/rustlib' / filename).read_bytes()) == expected_sha
assert sha((prefix / 'bin/rustc').read_bytes()) == result['provider_identity']['rustc_sha256']
for key in ('cc', 'ld'):
    assert sha(Path(result['linker'][key]).resolve().read_bytes()) == result['linker'][key + '_sha256']
target = (REPO / 'artifacts/node/94/hl-node').read_bytes()
assert sha(target) == result['target']['sha256']
assert sha(target[22482320:22482320+448]) == result['target']['body_sha256']

python_stderr = (HERE.parent / 'formatter-python-c2.stderr').read_bytes()
assert b'Ran 3 tests' in python_stderr and python_stderr.rstrip().endswith(b'OK')
receipt = {'schema': 'formatter448-independent-actual-artifact-review-v1', 'status': 'PASS',
           'source_head': before['head'], 'result_sha256': sha((RUN / 'result.json').read_bytes()),
           'commands_sha256': sha((RUN / 'commands.json').read_bytes()),
           'commands_verified': len(ledger), 'raw_streams_verified': len(ledger) * 2,
           'source_before_after_equal': True, 'source_files_checked': len(before['sources']),
           'current_source_hashes_match_build_snapshot': True, 'provider_payloads_independently_checked': 103,
           'full_target_and_body_reauthenticated': True, 'profiles': profiles, 'mutants': mutants,
           'python_test_methods': 3, 'python_stdout_sha256': sha((HERE.parent / 'formatter-python-c2.stdout').read_bytes()),
           'python_stderr_sha256': sha(python_stderr),
           'own_reruns': [],
           'limitations': ['All executed binaries are independently authored Rust/input clients; no captured target or instruction evaluator.',
                           'The 12 checked refusals are chosen safe behavior outside the qualified native domain.',
                           'Original callback renderer/private ABI, native unwind/faults, new Rust machine-code identity, whole-node and acceptance gates remain unclaimed.',
                           'Full current suite and CI remain pending explicit authorization; this receipt covers scoped checks only.']}
if args.rerun_own_client:
    for profile in profiles:
        level = profile['opt_level']
        driver = RUN / ('opt' + str(level)) / 'input-only'
        assert sha(driver.read_bytes()) == profile['driver_sha256']
        process = subprocess.run([str(driver)], input=inputs, capture_output=True, check=False)
        assert process.returncode == 0 and not process.stderr
        actual = [json.loads(line) for line in process.stdout.splitlines()]
        assert actual == expected
        for stream, data in (('stdout', process.stdout), ('stderr', process.stderr)):
            (HERE / f'independent-opt{level}.{stream}.gz').write_bytes(gzip.compress(data, mtime=0))
        receipt['own_reruns'].append({'argv': [str(driver)], 'exit': process.returncode,
                                     'stdin_sha256': sha(inputs), 'stdout_sha256': sha(process.stdout),
                                     'stderr_sha256': sha(process.stderr), 'matched_full_transcripts': len(actual)})
filename = 'FORMATTER-ACTUAL-ARTIFACT-REVIEW.json' if args.rerun_own_client else 'FORMATTER-RETAINED-ARTIFACT-REVIEW.json'
output = HERE / filename
output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
print(json.dumps({'receipt_sha256': sha(output.read_bytes()), 'commands': len(ledger),
                  'raw_streams': 2*len(ledger), 'profiles': profiles, 'mutants': mutants,
                  'own_reruns': receipt['own_reruns']}, sort_keys=True))
