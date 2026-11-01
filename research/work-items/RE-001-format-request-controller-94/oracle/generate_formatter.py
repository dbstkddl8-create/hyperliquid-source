#!/usr/bin/env python3
"""New independent plan oracle and separate serializer, authored before Rust."""
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT = 0x60000020
ROWS = [[10000 + index, 0x10000 * (index + 1) + 0x4000 + index] for index in range(8)]

def literal(data, extended=False):
    return {'kind': 'literal', 'hex': data.hex(), 'extended': extended}

def value(tag=192, **overrides):
    if tag == 192:
        result = {'kind': 'value', 'tag': tag, 'options': None,
                  'q0': None, 'q1': None, 'index': None, 'dynamic0': False, 'dynamic1': False}
    else:
        control = tag & 63
        result = {'kind': 'value', 'tag': tag,
                  'options': 0xDEADBEEF if control & 1 else None,
                  'q0': 1 if control & 2 else None,
                  'q1': 2 if control & 4 else None,
                  'index': 3 if control & 8 else None,
                  'dynamic0': bool(control & 16), 'dynamic1': bool(control & 32)}
    result.update(overrides)
    return result

def serialize(plan):
    out = bytearray()
    for operation in plan:
        if operation['kind'] == 'literal':
            data = bytes.fromhex(operation['hex'])
            if operation['extended']:
                out.extend(b'\x80' + len(data).to_bytes(2, 'little'))
            else:
                assert 1 <= len(data) <= 127
                out.append(len(data))
            out.extend(data)
        else:
            out.append(operation['tag'])
            if operation['tag'] != 192:
                for key, count in (('options', 4), ('q0', 2), ('q1', 2), ('index', 2)):
                    if operation[key] is not None:
                        out.extend(operation[key].to_bytes(count, 'little'))
    return bytes(out) + b'\x00'

def answer(case):
    # This oracle never reads case['raw']; semantic plans are its sole control.
    rows = copy.deepcopy(case['rows'])
    current_method = case['method']
    events = []
    ordinal = 0

    def callback(kind, data, second=None, context=None):
        nonlocal ordinal, current_method
        entry = case['script'][ordinal] if ordinal < len(case['script']) else {}
        ordinal += 1
        reply = entry.get('return', 0)
        if kind == 'write':
            event = {'kind': 'write', 'method': second, 'destination': data[0],
                     'bytes': data[1], 'return': None}
        else:
            event = {'kind': 'value', 'data': data, 'second': second,
                     'before': context[:], 'after': None, 'return': None}
        events.append(event)
        for action in entry.get('actions', []):
            if 'method' in action:
                current_method = action['method']
            elif 'row' in action:
                index, first, last = action['row']
                rows[index] = [first, last]
            elif 'context' in action:
                assert context is not None
                context[:] = action['context']
            elif 'write' in action:
                assert context is not None
                data_hex, propagate = action['write']
                method = current_method if context[1] == case['table'] else 202
                assert context[1] in (case['table'], 2)
                nested_reply = callback('write', (context[0], data_hex), method)
                if propagate and nested_reply:
                    reply = nested_reply
                    break
            else:
                raise ValueError(action)
        if context is not None:
            event['after'] = context[:]
        event['return'] = reply
        return reply

    cached_method = current_method
    if case['route'] == 'direct':
        status = callback('write', (case['destination'], case['direct_hex']), cached_method)
    else:
        next_index = 0
        status = 0
        for operation in case['plan']:
            if operation['kind'] == 'literal':
                reply = callback('write', (case['destination'], operation['hex']), cached_method)
            else:
                q0 = operation['q0'] if operation['q0'] is not None else 0
                q1 = operation['q1'] if operation['q1'] is not None else 0
                if operation['dynamic0']:
                    q0 = rows[q0][1] % 65536
                if operation['dynamic1']:
                    q1 = rows[q1][1] % 65536
                index = operation['index'] if operation['index'] is not None else next_index
                options = operation['options'] if operation['options'] is not None else DEFAULT
                context = [case['destination'], case['table'], options, q0, q1]
                first, second = rows[index]
                reply = callback('value', first, second, context)
                if reply == 0:
                    next_index = index + 1
            if reply:
                status = 1
                break
        else:
            status = 'refused' if case.get('refuse_after_plan') else 0
    return {'id': case['id'], 'status': status, 'events': events,
            'method': current_method, 'rows': rows}

cases = []
def add(name, plan=None, route='encoded', script=None, raw=None, rows=None, direct=b''):
    case = {'id': name, 'route': route, 'destination': 11, 'table': 1,
            'method': 101, 'rows': copy.deepcopy(ROWS if rows is None else rows),
            'script': [] if script is None else script,
            'plan': [] if plan is None else plan}
    if route == 'direct':
        case['direct_hex'] = direct.hex()
        case['raw'] = direct.hex()
    else:
        case['raw'] = (serialize(case['plan']) if raw is None else raw).hex()
    cases.append(case)
    return case

add('compact-empty')
add('compact-zero-ignores-trailing', raw=b'\x00\xff')
for length in range(1, 128):
    add(f'literal-tag-{length}', [literal(bytes((index * 17 + 3) % 256 for index in range(length)))])
for length in (0, 1, 127, 128, 255, 256, 1024, 65535):
    add(f'extended-length-{length}', [literal(bytes((index * 29 + 5) % 256 for index in range(length)), True)])
for tag in range(128, 256):
    if tag == 128:
        continue
    add(f'high-tag-{tag}', [value(tag), value()])
for reply in range(256):
    add(f'direct-raw-reply-{reply}', route='direct', direct=b'\x00A\xff', script=[{'return': reply}])
    add(f'compact-w-reply-{reply}', [literal(b'A'), value()], script=[{'return': reply}])
    add(f'compact-g-reply-{reply}', [value(), literal(b'B')], script=[{'return': reply}])
for payload_index, data in enumerate((b'', b'\x00', b'\xff', b'hello', bytes(range(256)))):
    add(f'direct-size-{len(data)}-payload-{payload_index}', route='direct', direct=data)
add('explicit-index-rebases', [value(136, index=4), value(), value(200, index=1), value()])
add('explicit-maximum-u16-index', [value(136, index=65535)],
    rows=[[index, (index << 16) + (index % 65536)] for index in range(65536)])
add('zero-widths-still-value', [value(134, q0=0, q1=0), literal(b'', True), value()])
add('options-quantities-endian', [value(143, options=0x89ABCDEF, q0=0x1234, q1=0x5678, index=2)])
add('dynamic-low16-second-words', [value(182, q0=1, q1=2), value(240)])
add('outer-method-cached-after-literal', [literal(b'A'), literal(b'B'), value(), literal(b'C')],
    script=[{'actions': [{'method': 999}]}])
add('outer-method-cached-after-G', [value(), literal(b'A'), value(), literal(b'B')],
    script=[{'actions': [{'method': 888}]}])
add('all24-context-reset', [value(143), value(), value(134, q0=0, q1=0)],
    script=[{'actions': [{'context': [999, 2, 0x11223344, 65535, 54321]}]},
            {'actions': [{'context': [777, 2, 0x88776655, 12345, 23456]}]}])
add('live-row-data-and-method', [literal(b'change'), value(), value()],
    script=[{'actions': [{'row': [0, 7654321, 0xBEEF1234]}, {'row': [1, 1234567, 0xCAFEABCD]}]}])
add('live-quantity-after-G', [value(), value(182, q0=2, q1=3)],
    script=[{'actions': [{'row': [2, 200, 0x12345678]}, {'row': [3, 300, 0x89ABCDEF]}]}])
add('nested-write-original-context', [value(), literal(b'after')],
    script=[{'actions': [{'write': ['6e6573746564', True]}]}])
add('nested-write-context-and-method-mutation', [value(), literal(b'outer'), value()],
    script=[{'actions': [{'method': 303}, {'context': [909, 1, 123, 456, 789]},
                        {'write': ['00ff41', True]}, {'context': [808, 2, 987, 654, 321]},
                        {'write': ['', True]}]}])
add('nested-failure-propagates', [value(), literal(b'unreached')],
    script=[{'actions': [{'write': ['78', True]}, {'method': 404}]}, {'return': 254}])
add('nested-failure-ignored', [value(), literal(b'outer')],
    script=[{'actions': [{'write': ['78', False]}, {'method': 505}]}, {'return': 255}])
add('nested-W-mutates-next-G', [value(), value()],
    script=[{'actions': [{'write': ['7a', True]}]},
            {'actions': [{'row': [1, 424242, 0xA0A0B0B0]}, {'method': 606}]}])

# Chosen safe refusals have explicit predeclared prefix plans. The oracle does
# not parse malformed bytes and makes no native-fault-path claim.
for name, raw in [('empty-stream', b''), ('missing-literal', b'\x01'),
                  ('short-extended-length', b'\x80\x01'),
                  ('short-extended-body', b'\x80\x02\x00\x41'),
                  ('short-options', b'\x81\x01\x02\x03'),
                  ('short-first-quantity', b'\x82\x01'),
                  ('short-second-quantity', b'\x84\x01'),
                  ('short-index', b'\x88\x01'),
                  ('row-out-of-range', b'\x88\xff\xff\x00'),
                  ('dynamic0-out-of-range', b'\x92\xff\xff\x00'),
                  ('dynamic1-out-of-range', b'\xa4\xff\xff\x00')]:
    case = add('refusal-' + name, raw=raw)
    case['refuse_after_plan'] = True
case = add('refusal-missing-next-tag', [literal(b'A')], raw=b'\x01A')
case['refuse_after_plan'] = True
add('early-W-error-hides-malformed-tail', [literal(b'A')], raw=b'\x01A\xff', script=[{'return': 17}])
add('early-G-error-hides-malformed-tail', [value()], raw=b'\xc0\xff', script=[{'return': 231}])

def serialize_script(script):
    callbacks = []
    for entry in script:
        actions = []
        for action in entry.get('actions', []):
            if 'method' in action:
                actions.append('M' + format(action['method'], 'x'))
            elif 'row' in action:
                actions.append('R' + ','.join(format(item, 'x') for item in action['row']))
            elif 'context' in action:
                actions.append('C' + ','.join(format(item, 'x') for item in action['context']))
            else:
                data, propagate = action['write']
                actions.append('W' + data + ',' + str(int(propagate)))
        callbacks.append(str(entry.get('return', 0)) + '~' + '/'.join(actions))
    return ';'.join(callbacks) if callbacks else '-'

inputs = []
expected = []
for case in cases:
    rows = ','.join(format(first, 'x') + ':' + format(second, 'x') for first, second in case['rows']) or '-'
    inputs.append('\t'.join([case['id'], case['route'], case['raw'], format(case['destination'], 'x'),
                             format(case['table'], 'x'), format(case['method'], 'x'), rows,
                             serialize_script(case['script'])]))
    expected.append(answer(case))
authority = {'schema': 'formatter448-pre-source-plan-v1',
             'basis': 'published #1216 full native listing; full raw target admission pending at freeze',
             'cases': cases, 'expected': expected}
data = (json.dumps(authority, indent=2, sort_keys=True) + '\n').encode()
(ROOT / 'formatter448-authority.json').write_bytes(data)
(ROOT / 'formatter448-input.tsv').write_text('\n'.join(inputs) + '\n')
(ROOT / 'formatter448-expected.jsonl').write_text('\n'.join(json.dumps(item, sort_keys=True, separators=(',', ':')) for item in expected) + '\n')
receipt = {'cases': len(cases)}
for filename in ('formatter448-authority.json', 'formatter448-input.tsv', 'formatter448-expected.jsonl',
                 'generate_formatter.py', 'formatter448-proof.md'):
    receipt[filename + '_sha256'] = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
(ROOT / 'formatter448-freeze.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt, sort_keys=True))
