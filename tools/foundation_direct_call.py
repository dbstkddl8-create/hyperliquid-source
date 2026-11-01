#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 direct-call window packet.

One FDE window: push %rbx, load [container + 0x788], save the out
pointer in %rbx, load [[container + 0x788] + 0x8f8] as the callee
argument, call 0x5172a30, store the callee's result to [rsi], and
return 1 with %rbx preserved and the stack balanced (push/pop only).

All window-specific facts are read from the evidence packet, not
hardcoded here; this checker verifies that those packet facts decode
consistently and, in binary mode, that they match the digest-bound
target. It never executes target code and makes no reconstruction
claim beyond this window's observable rule.

Run from the repository root:

    python3 tools/foundation_direct_call.py \\
        --check research/work-items/foundation-direct-call-94/evidence.json
    python3 tools/foundation_direct_call.py \\
        --check research/work-items/foundation-direct-call-94/evidence.json \\
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


def require(condition, message):
    if not condition:
        raise ValueError(message)


def simulate_direct_call(field_8f8, callee):
    """Model the window against nested dict state.

    field_8f8 is the qword at [[container + 0x788] + 0x8f8]; callee
    is called with it. Returns (callee result, 1).
    """
    return callee(field_8f8), 1


def _va_int(value):
    return int(value, 16) if isinstance(value, str) else value


def _check_window_structure(window):
    """Packet-only checks: hashes, lengths, and instruction encodings."""
    raw = bytes.fromhex(window['bytes_hex'])
    start = _va_int(window['start_va'])
    end = _va_int(window['end_va_exclusive'])
    require(len(raw) == end - start, 'Window length changed')
    require(len(raw) == window['bytes'], 'Evidence byte count changed')
    require(hashlib.sha256(raw).hexdigest() == window['sha256'],
            'Evidence window hash changed')
    require(raw[:4] == b'\xf3\x0f\x1e\xfa', 'Missing endbr64')
    require(raw[-1] == 0xC3, 'Missing ret terminator')
    require(window['next_fde_start'] >= window['end_va_exclusive'],
            'Next FDE must not precede the window end')
    require(window['first_hop_offset'] == 0x788, 'First hop changed')
    require(window['field_offset'] == 0x8F8, 'Field offset changed')
    # push %rbx; mov 0x788(%rdi),%rax; mov %rsi,%rbx.
    require(raw[4] == 0x53, 'Frame push changed')
    require(raw[5:12] == b'\x48\x8b\x87\x88\x07\x00\x00',
            'First-hop load changed')
    require(raw[12:15] == b'\x48\x89\xf3', 'Out-pointer save changed')
    # mov 0x8f8(%rax),%rdi; call rel32.
    require(raw[15:22] == b'\x48\x8b\xb8\xf8\x08\x00\x00',
            'Field load changed')
    require(raw[22] == 0xE8, 'Call opcode changed')
    call_va = start + 22
    disp = struct.unpack_from('<i', raw, 23)[0]
    require(call_va + 5 + disp == _va_int(window['call_target']),
            'Call target changed')
    # mov %rax,(%rbx); mov $0x1,%eax; pop %rbx; ret.
    require(raw[27:30] == b'\x48\x89\x03', 'Out store changed')
    require(raw[30:35] == b'\xb8\x01\x00\x00\x00',
            'Return value changed')
    require(raw[35:37] == b'\x5b\xc3', 'Return sequence changed')
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
    """Verify packet facts against binary bytes (or packet facts alone).

    With data=None, only the packet-internal checks run (hashes,
    lengths, encodings, padding counts, and the pinned target digest
    claim). With binary bytes, the digest, window bytes, padding
    bytes, FDE records, and direct-caller counts are additionally
    cross-checked.
    """
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 1, 'Packet must bind exactly the window')
    require([w['name'] for w in windows] == ['direct_call'],
            'Window name changed')
    window = windows[0]
    raw = _check_window_structure(window)
    rules = ev['rules'][window['name']]
    require(rules['first_hop_offset'] == '0x788', 'Rule first hop changed')
    require(rules['field_offset'] == '0x8f8', 'Rule field changed')
    require(rules['call_target'] == window['call_target'],
            'Rule call target changed')
    require(rules['preserved_registers'] == ['rbx'],
            'Rule registers changed')
    require(rules['return_value'] == 1, 'Rule return value changed')
    if data is None:
        return [raw]
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
    # This CIE encodes initial_location as pcrel sdata4: the
    # stored value is relative to its own field address
    # (eh VA + rel + 8).
    sdata, fde_range = struct.unpack_from('<iI', rec, 8)
    fde_start = eh['address'] + rel + 8 + sdata
    require(fde_start == start, 'FDE start changed')
    require(fde_range == end - start, 'FDE range changed')
    callers = _scan_direct_callers(text_bytes, text['address'], start)
    require(callers == ev['direct_callers'][window['name']],
            'Direct-caller count changed: %d' % callers)
    return [raw]


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
    print('foundation-direct-call evidence OK')


if __name__ == '__main__':
    main()
