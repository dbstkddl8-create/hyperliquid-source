#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 unconditional-call packet.

Three adjacent FDE windows bound as one family item because they
share one skeleton and differ only in how the single call argument
is formed:

- 0x514b070 (27 bytes): push %rbx, lea 0x40(%rcx) into %rdi,
  save the out pointer in %rbx, call 0x51cc540, store the callee's
  result to [rsi], return 1 with %rbx preserved.
- 0x514b090 (26 bytes): push %rbx, move %rdx into %rdi, save the
  out pointer in %rbx, call 0x50aaf20, store the result to [rsi],
  return 1 with %rbx preserved.
- 0x514b0b0 (26 bytes): the same rdx-argument protocol with
  callee 0x50aaf30.

All window-specific facts are read from the evidence packet, not
hardcoded here; this checker verifies that those packet facts decode
consistently and, in binary mode, that they match the digest-bound
target. It never executes target code and makes no reconstruction
claim beyond these windows' observable rules.

Run from the repository root:

    python3 tools/foundation_unconditional_call_trio.py \
        --check research/work-items/foundation-unconditional-call-trio-94/evidence.json
    python3 tools/foundation_unconditional_call_trio.py \
        --check research/work-items/foundation-unconditional-call-trio-94/evidence.json \
        --binary work/hl-node-94.bin

On a checkout where the LFS artifact is materialized, run the binary
form with --binary artifacts/node/94/hl-node.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Per-window byte layout: (length, call offset, argument bytes,
# argument description). The argument bytes are checked exactly.
LAYOUTS = {
    'lea_arg_call': (27, 12, b'\x48\x8d\x79\x40', 'rcx + 0x40, via lea into rdi'),
    'rdx_arg_call_a': (26, 11, b'\x48\x89\xd7', 'rdx itself, moved to rdi'),
    'rdx_arg_call_b': (26, 11, b'\x48\x89\xd7', 'rdx itself, moved to rdi'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def simulate_unconditional_call(argument, callee):
    """Model a window against a stub callee: (callee(argument), 1)."""
    return callee(argument), 1


def _va_int(value):
    return int(value, 16) if isinstance(value, str) else value


def _call_target(raw, start, offset):
    require(raw[offset] == 0xE8, 'Call opcode changed')
    disp = struct.unpack_from('<i', raw, offset + 1)[0]
    return start + offset + 5 + disp


def _check_window(window):
    """Packet-only checks for one call-store window."""
    name = window['name']
    length, call_off, arg_bytes, _arg_desc = LAYOUTS[name]
    raw = bytes.fromhex(window['bytes_hex'])
    start = _va_int(window['start_va'])
    end = _va_int(window['end_va_exclusive'])
    require(len(raw) == end - start, 'Window length changed')
    require(len(raw) == window['bytes'], 'Evidence byte count changed')
    require(len(raw) == length, 'Window length changed for %s' % name)
    require(hashlib.sha256(raw).hexdigest() == window['sha256'],
            'Evidence window hash changed')
    require(raw[:4] == b'\xf3\x0f\x1e\xfa', 'Missing endbr64')
    require(raw[-1] == 0xC3, 'Missing ret terminator')
    require(window['next_fde_start'] >= window['end_va_exclusive'],
            'Next FDE must not precede the window end')
    require(raw[4] == 0x53, 'Frame push changed')
    arg_off = 5
    require(raw[arg_off:arg_off + len(arg_bytes)] == arg_bytes,
            'Call argument encoding changed')
    save_off = arg_off + len(arg_bytes)
    require(raw[save_off:save_off + 3] == b'\x48\x89\xf3',
            'Out-pointer save changed')
    require(_call_target(raw, start, call_off) ==
            _va_int(window['call_target']), 'Call target changed')
    store_off = call_off + 5
    require(raw[store_off:store_off + 3] == b'\x48\x89\x03',
            'Out store changed')
    require(raw[store_off + 3:store_off + 8] == b'\xb8\x01\x00\x00\x00',
            'Return value changed')
    require(raw[store_off + 8:store_off + 10] == b'\x5b\xc3',
            'Return sequence changed')
    return raw


def _scan_direct_callers(text_bytes, text_address, target):
    """Count direct e8 calls landing exactly on target within .text."""
    count = 0
    pos = text_bytes.find(b'\xe8')
    while pos != -1:
        if pos + 5 <= len(text_bytes):
            disp = struct.unpack_from('<i', text_bytes, pos + 1)[0]
            if text_address + pos + 5 + disp == target:
                count += 1
        pos = text_bytes.find(b'\xe8', pos + 1)
    return count


def analyze(data, ev):
    """Verify packet facts against binary bytes (or packet facts alone)."""
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 3, 'Packet must bind exactly the trio')
    require([w['name'] for w in windows] ==
            ['lea_arg_call', 'rdx_arg_call_a', 'rdx_arg_call_b'],
            'Window names changed')
    raw_by_name = {w['name']: _check_window(w) for w in windows}
    for window in windows:
        rule = ev['rules'][window['name']]
        _length, _off, _arg, desc = LAYOUTS[window['name']]
        require(rule['call_argument'] == desc, 'Rule call argument changed')
        require(rule['call_target'] == window['call_target'],
                'Rule call target changed')
        require(rule['preserved_registers'] == ['rbx'],
                'Rule registers changed')
        require(rule['return_value'] == 1, 'Rule return value changed')
    if data is None:
        return raw_by_name
    require(hashlib.sha256(data).hexdigest() == SHA256,
            'Target digest mismatch')
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA %s' % hex(va))
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    text = by_name['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    eh = by_name['.eh_frame']
    for window in windows:
        raw = raw_by_name[window['name']]
        start = _va_int(window['start_va'])
        end = _va_int(window['end_va_exclusive'])
        require(read(start, end - start) == raw, 'Window bytes changed')
        pad = read(end, window['padding_int3_bytes'])
        require(pad == b'\xcc' * window['padding_int3_bytes'],
                'Padding changed')
        require(_va_int(window['next_fde_start']) ==
                end + window['padding_int3_bytes'],
                'Padding must end exactly at the next FDE')
        rel = _va_int(window['fde_section_offset'])
        fde_off = eh['offset'] + rel
        rec = data[fde_off:fde_off + 20]
        require(len(rec) == 20, 'FDE record truncated')
        sdata, fde_range = struct.unpack_from('<iI', rec, 8)
        fde_start = eh['address'] + rel + 8 + sdata
        require(fde_start == start, 'FDE start changed')
        require(fde_range == end - start, 'FDE range changed')
        callers = _scan_direct_callers(text_bytes, text['address'], start)
        require(callers == ev['direct_callers'][window['name']],
                'Direct-caller count changed: %d' % callers)
    for target_hex, expected in ev['callee_direct_callers'].items():
        found = _scan_direct_callers(text_bytes, text['address'],
                                     _va_int(target_hex))
        require(found == expected,
                'Callee census changed for %s: %d' % (target_hex, found))
    return raw_by_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', required=True)
    parser.add_argument('--binary', default=None)
    args = parser.parse_args()
    with open(args.check) as fh:
        ev = json.load(fh)
    data = None
    if args.binary is not None:
        with open(args.binary, 'rb') as fh:
            data = fh.read()
    analyze(data, ev)
    print('foundation-unconditional-call-trio evidence OK')


if __name__ == '__main__':
    main()
