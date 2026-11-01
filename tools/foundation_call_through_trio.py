#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 call-through trio packet.

Three adjacent FDE windows share one protocol: push %rbx, load
[container + 0x788], save the out pointer in %rbx, add 0x8f0 to the
loaded pointer, call a small callee with that pointer, store an
extended form of the callee's result to [rsi], return 1:

* 0x514add0: call 0x51723e0, cltq (sign-extend the callee result).
* 0x514ae00: call 0x51723f0, cltq.
* 0x514ae30: call 0x5172c70, movzbl (zero-extend the low byte).

All window-specific facts (bytes, offsets, padding, FDE starts, call
targets, extensions) are read from the evidence packet, not hardcoded
here; this checker verifies that those packet facts decode
consistently and, in binary mode, that they match the digest-bound
target. It never executes target code and makes no reconstruction
claim beyond these windows' observable rules.

Run from the repository root:

    python3 tools/foundation_call_through_trio.py \\
        --check research/work-items/foundation-call-through-trio-94/evidence.json
    python3 tools/foundation_call_through_trio.py \\
        --check research/work-items/foundation-call-through-trio-94/evidence.json \\
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


def simulate_call_through(field_788, callee, extension):
    """Model one trio window against nested dict state.

    field_788 is the qword at [container + 0x788]; callee is called
    with field_788 + 0x8f0. cltq sign-extends the callee's 32-bit
    result; movzbl zero-extends its low byte. Returns (stored, 1).
    """
    raw = callee(field_788 + 0x8F0)
    if extension == 'cltq':
        value = raw & 0xFFFFFFFF
        if value >= 1 << 31:
            value -= 1 << 32
    elif extension == 'movzbl':
        value = raw & 0xFF
    else:
        raise ValueError('unknown extension %r' % extension)
    return value, 1


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
    require(window['next_fde_start'] > window['end_va_exclusive'],
            'Next FDE must follow the window')
    require(window['first_hop_offset'] == 0x788, 'First hop changed')
    require(window['add_offset'] == 0x8F0, 'Add offset changed')
    # push %rbx; mov 0x788(%rdi),%rdi; mov %rsi,%rbx.
    require(raw[4:5] == b'\x53', 'rbx push changed')
    require(raw[5:12] == b'\x48\x8b\xbf\x88\x07\x00\x00',
            'First-hop load changed')
    require(raw[12:15] == b'\x48\x89\xf3', 'Out-pointer save changed')
    # add $0x8f0,%rdi; call rel32 landing on the target.
    require(raw[15:22] == b'\x48\x81\xc7\xf0\x08\x00\x00',
            'Addend changed')
    require(raw[22:23] == b'\xe8', 'Call opcode changed')
    call_va = start + 22
    disp = struct.unpack_from('<i', raw, 23)[0]
    require(call_va + 5 + disp == _va_int(window['call_target']),
            'Call target changed')
    ext = window['extension']
    if ext == 'cltq':
        require(raw[27:29] == b'\x48\x98', 'cltq changed')
        require(raw[29:32] == b'\x48\x89\x03', 'Out store changed')
        tail = raw[32:]
    elif ext == 'movzbl':
        require(raw[27:30] == b'\x0f\xb6\xc0', 'movzbl changed')
        require(raw[30:33] == b'\x48\x89\x03', 'Out store changed')
        tail = raw[33:]
    else:
        raise ValueError('unknown extension %r' % ext)
    # mov $0x1,%eax; pop %rbx; ret.
    require(tail == b'\xb8\x01\x00\x00\x00\x5b\xc3',
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
    """Verify packet facts against binary bytes (or packet facts alone).

    With data=None, only the packet-internal checks run (hashes,
    lengths, encodings, padding counts, and the pinned target digest
    claim). With binary bytes, the digest, window bytes, padding
    bytes, FDE records, and direct-caller counts are additionally
    cross-checked.
    """
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 3, 'Packet must bind exactly the trio')
    require([w['name'] for w in windows] == [
        'call_through_cltq_23e0', 'call_through_cltq_23f0',
        'call_through_movzbl_2c70'], 'Window names changed')
    require(len({w['call_target'] for w in windows}) == 3,
            'Trio callees must be distinct')
    raws = [_check_window_structure(w) for w in windows]
    for window in windows:
        rules = ev['rules'][window['name']]
        require(rules['first_hop_offset'] == '0x788',
                'Rule first hop changed')
        require(rules['add_offset'] == '0x8f0', 'Rule addend changed')
        require(rules['call_target'] == window['call_target'],
                'Rule call target changed')
        require(rules['extension'] == window['extension'],
                'Rule extension changed')
        require(rules['preserved_registers'] == ['rbx'],
                'Rule registers changed')
        require(rules['return_value'] == 1, 'Rule return value changed')
    if data is None:
        return raws
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
    for window, raw in zip(windows, raws):
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
    return raws


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
    print('foundation-call-through-trio evidence OK')


if __name__ == '__main__':
    main()
