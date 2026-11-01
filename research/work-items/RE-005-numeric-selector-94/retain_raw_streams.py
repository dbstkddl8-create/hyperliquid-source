#!/usr/bin/env python3
"""Losslessly retain exact raw streams once per content digest; no normalization.

Creation reads only the observed own-build directory and frozen public answers.
Verification decodes every member and checks its original size and SHA256.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(path):
    record = json.loads(Path(path).read_text())
    blobs = {}
    for digest, item in record['blobs'].items():
        raw = (ROOT / item['public_file']).read_bytes() if 'public_file' in item else base64.b64decode(item['base64'], validate=True)
        assert sha(raw) == digest and len(raw) == item['bytes']
        blobs[digest] = raw
    for name, item in record['files'].items():
        assert len(blobs[item['sha256']]) == item['bytes'], name
    return {'files': len(record['files']), 'unique_contents': len(blobs),
            'total_original_bytes': sum(x['bytes'] for x in record['files'].values()),
            'round_trip_exact': True}


def create(directory, output):
    directory, output = Path(directory), Path(output)
    assert not output.exists(), 'Preserve previous evidence'
    result = json.loads((directory / 'RESULT.json').read_text())
    assert result['status'] == 'PASS'
    public = (ROOT / 'independent-pre-source/expected.tsv').read_bytes()
    public_digest = sha(public)
    files, blobs = {}, {}
    for call in result['calls']:
        for item in call['streams'].values():
            name = item['file']
            assert Path(name).name == name
            raw = (directory / name).read_bytes()
            digest = sha(raw)
            assert digest == item['sha256'] and len(raw) == item['bytes']
            files[name] = {'sha256': digest, 'bytes': len(raw)}
            if digest not in blobs:
                blobs[digest] = {'bytes': len(raw), 'public_file': 'independent-pre-source/expected.tsv'} if digest == public_digest else {'bytes': len(raw), 'base64': base64.b64encode(raw).decode('ascii')}
    calls = (directory / 'CALLS.json').read_bytes()
    digest = sha(calls)
    files['CALLS.json'] = {'sha256': digest, 'bytes': len(calls)}
    blobs[digest] = {'bytes': len(calls), 'base64': base64.b64encode(calls).decode('ascii')}
    record = {'schema': 'lossless-own-command-streams/1', 'normalization': 'none',
              'commands': len(result['calls']), 'stdout_stderr_streams': 2 * len(result['calls']),
              'original_result_sha256': sha((directory / 'RESULT.json').read_bytes()),
              'files': files, 'blobs': blobs}
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return verify(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-directory', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'RAW-STREAMS.json')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.output) if args.verify else create(args.run_directory, args.output), sort_keys=True))
