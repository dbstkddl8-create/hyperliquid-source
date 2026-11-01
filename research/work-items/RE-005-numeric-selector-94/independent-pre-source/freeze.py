#!/usr/bin/env python3
"""Independently authored scalar/request oracle; no repository imports or Rust.

This computes a mathematical output relation from nonnegative integer spelling.
It is not a PC/register/opcode/memory evaluator and does not execute captured code.
"""
from pathlib import Path
import hashlib
import json
import datetime

ROOT = Path(__file__).resolve().parent
MAX = (1 << 64) - 1
LOW = 1 << 25
UP = 1 << 26
MODES = (0, LOW, UP, LOW | UP)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def number_string(n, flags):
    if flags & LOW:
        return format(n, 'x').encode('ascii'), 16, b'0x'
    if flags & UP:
        return format(n, 'X').encode('ascii'), 16, b'0x'
    return str(n).encode('ascii'), 20, b''

cases = []
families = {}
def add(family, n, flags, status, marker=None, context=None):
    ordinal = len(cases)
    identity = f'{family}:{ordinal}:{n}:{flags}:{status}'.encode()
    marker = hashlib.sha256(b'scratch:' + identity).digest()[:20] if marker is None else marker
    context = int.from_bytes(hashlib.sha256(b'context:' + identity).digest()[:8], 'little') if context is None else context
    assert 0 <= n <= MAX and 0 <= flags <= MAX and 0 <= status < 256
    assert len(marker) == 20 and 0 <= context <= MAX
    cases.append((f's{ordinal:05d}', n, flags, marker, context, status))
    families[family] = families.get(family, 0) + 1

values = set(range(256))
for base in (2, 10, 16):
    power = 1
    while power <= MAX + 1:
        for delta in (-2, -1, 0, 1, 2):
            if 0 <= power + delta <= MAX:
                values.add(power + delta)
        power *= base
for i in range(96):
    values.add(int.from_bytes(hashlib.sha256(f'selector-independent-value:{i}'.encode()).digest()[:8], 'little'))
values.update((MAX, MAX - 1, MAX - 2, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555,
               0x0123456789abcdef, 0xfedcba9876543210, 10**19, 10**19 - 1))
for index, n in enumerate(sorted(values)):
    for mode in MODES:
        add('numeric-boundaries-and-samples', n, mode, (index * 73 + mode // LOW) % 256)

# Complete 256-status Cartesian product with four selectors and five distinct values.
for n in (0, 10, 15, 16, MAX):
    for flags in MODES:
        for status in range(256):
            add('all-raw-u8-statuses', n, flags, status)

# Every unselected bit is toggled on the same semantic probe relative to a
# separately retained baseline, including bits above native DWORD width.
for n in (0, 0x123456789abcdef, MAX):
    for flags in MODES:
        marker = bytes((19 * i + 61) % 256 for i in range(20))
        context = (n ^ 0xc37a50e912f0846b) & MAX
        add('flag-invariance-baselines', n, flags, 219, marker, context)
        for bit in range(64):
            if bit not in (25, 26):
                add('other-bit-invariance', n, flags | (1 << bit), 219, marker, context)

# Distinct sentinel shapes independently corroborate prefix and hex final4 preservation.
for marker in (bytes(20), bytes([255])*20, bytes(range(20)), bytes(range(255,235,-1))):
    for n in (0, 9, 10, 15, 16, 255, 256, MAX):
        for flags in MODES:
            add('marker-patterns', n, flags, 165, marker, 0x1fedcba987654320)

inputs = []
expected = []
semantic_inputs = set()
for ident, n, flags, marker, context, status in cases:
    semantic_inputs.add((n, flags, marker, context, status))
    digits, end, prefix = number_string(n, flags)
    start = end - len(digits)
    output = marker[:start] + digits + marker[end:]
    assert 0 <= start < end <= 20 and len(output) == 20
    inputs.append(f'{ident}\t{n}\t{flags}\t{marker.hex()}\t{context}\t{status}\n')
    expected.append(f'{ident}\t{start}\t{end}\t{output.hex()}\t{prefix.hex() or "-"}\t1\t{context}\t1\t{status}\t{digits.hex()}\n')

assert len(semantic_inputs) == len(cases), 'case IDs do not hide duplicate complete inputs'
input_raw = ''.join(inputs).encode()
expected_raw = ''.join(expected).encode()
(ROOT / 'inputs.tsv').write_bytes(input_raw)
(ROOT / 'expected.tsv').write_bytes(expected_raw)
manifest = {
  'schema': 'node94-selector-independent-pre-source/1',
  'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'target_sha256': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
  'main_commit': '3324e50333042b391312515e542279ca21f63dc8',
  'primary': {'elf_va_start': '0x14f7660', 'elf_va_end': '0x14f774b', 'bytes':235,
              'rows':63, 'body_sha256':'a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf'},
  'fresh_native_target_revalidation': False,
  'native_basis': 'Accepted1128 immutable full actual native listing and records at main commit, freshly read. Root target restoration still pending.',
  'cases':len(cases), 'complete_distinct_input_tuples':len(semantic_inputs),
  'numeric_family_distinct_values':len(values), 'families':families,
  'all_status_product': {'raw_u8_statuses':256, 'selector_modes':4, 'values':5, 'rows':5120},
  'invariance': {'native_selection_bits':[25,26], 'other_bits_each':62, 'value_probes':3, 'modes':4,
                 'probe_rows':744, 'baseline_rows':12, 'source_high32':'convenience ignored bits beyond native DWORD'},
  'input_protocol':'id value_decimal flags_u64_decimal initial20_hex context_u64_decimal callback_u8_decimal; tab-separated',
  'output_protocol':'id start end final20_hex prefix_hex_or_dash raw_sign1 context_u64 call_count1 raw_status digits_hex; tab-separated',
  'source_independence': {'new_Rust_read_or_authored':False, 'repository_imports':False,
                         'target_execution':False, 'PC_register_opcode_interpreter':False,
                         'oracle':'Python integer str/format scalar spelling only, independent of production implementation'},
  'observed_vs_chosen': {'native':'same context, rawsign1, exact digit/prefix slices and rawlowAL status normal return',
                         'chosen_safe_projection':'initialized B20 array, u64 context label, one supplied FnOnce sink; coordinates are B-relative metadata'},
  'unqualified':['full G/rendering/padding/fill','original ABI/type/layout/compiler/machine bytes',
                 'raw pointer identity/invalid aliases','opaque callee hidden register effects','fault/unwind/concurrent mutation',
                 'all full-component gates'],
  'files':{'freeze.py':{'sha256':digest(Path(__file__).read_bytes()), 'bytes':len(Path(__file__).read_bytes())},
           'inputs.tsv':{'sha256':digest(input_raw),'bytes':len(input_raw)},
           'expected.tsv':{'sha256':digest(expected_raw),'bytes':len(expected_raw)}}
}
(ROOT / 'FREEZE.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
print(json.dumps({'cases':len(cases),'distinct':len(semantic_inputs),'values':len(values),
                  'families':families,'freeze_sha256':digest((ROOT/'FREEZE.json').read_bytes()),
                  'input_sha256':digest(input_raw),'expected_sha256':digest(expected_raw)},sort_keys=True))
