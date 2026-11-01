#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 chained-field-pair evidence packet.

The two claimed windows are adjacent FDE entries sharing one two-hop
chain and one store/return protocol:

* 0x514ac20, 31 bytes: out = sign_extend32([[[rdi + 0x788] + 0x30]
  + 0xb30]), returning 1. No call, no check.
* 0x514ac40, 31 bytes: out = qword at [[[rdi + 0x788] + 0x30]
  + 0x1008], returning 1. No call, no check.

All window-specific facts (bytes, offsets, padding, FDE starts) are read
from the evidence packet, not hardcoded here; this checker verifies that
those packet facts decode consistently and, in binary mode, that they
match the digest-bound target. It never executes target code and makes
no reconstruction claim beyond the two windows' observable rules.

Run from the repository root:

    python3 tools/foundation_chained_field_pair.py \\
        --check research/work-items/foundation-chained-field-pair-94/evidence.json
    python3 tools/foundation_chained_field_pair.py \\
        --check research/work-items/foundation-chained-field-pair-94/evidence.json \\
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


def simulate_chained_i32(field_i32):
    """Model the 0x514ac20 window: sign-extend the 32-bit field.

    Only the low 32 bits are loaded (movslq); the window itself always
    returns 1.
    """
    value = field_i32 & 0xFFFFFFFF
    if value >= 0x80000000:
        value -= 0x100000000
    return value & 0xFFFFFFFFFFFFFFFF, 1


def simulate_chained_qword(field_qword):
    """Model the 0x514ac40 window: out = field qword, ret 1."""
    return field_qword & 0xFFFFFFFFFFFFFFFF, 1


def _va_int(value):
    return int(value, 16) if isinstance(value, str) else value


def _check_window_structure(window):
    """Packet-only checks: hashes, lengths, and instruction encodings."""
    raw = bytes.fromhex(window['bytes_hex'])
    start = _va_int(window['start_va'])
    end = _va_int(window['end_va_exclusive'])
    require(len(raw) == end - start, 'Window length changed for %s' % window['name'])
    require(len(raw) == window['bytes'], 'Evidence byte count changed for %s' % window['name'])
    require(hashlib.sha256(raw).hexdigest() == window['sha256'],
            'Evidence window hash changed for %s' % window['name'])
    require(raw[:4] == b'\xf3\x0f\x1e\xfa', 'Missing endbr64 in %s' % window['name'])
    require(raw[-1] == 0xC3, 'Missing ret terminator in %s' % window['name'])
    require(window['next_fde_start'] > window['end_va_exclusive'],
            'Next FDE must follow the window for %s' % window['name'])
    # Shared chain: mov base_offset(%rdi),%rax; mov inner_offset(%rax),%rax.
    require(raw[4:7] == b'\x48\x8b\x87', 'Chain base load changed in %s' % window['name'])
    disp = struct.unpack_from('<i', raw, 7)[0]
    require(disp == window['base_offset'],
            'Chain base offset changed in %s: %s' % (window['name'], hex(disp)))
    require(raw[11:14] == b'\x48\x8b\x40', 'Chain inner load changed in %s' % window['name'])
    require(raw[14] == window['inner_offset'],
            'Chain inner offset changed in %s' % window['name'])
    if window['name'] == 'chained_i32':
        require(raw[15:18] == b'\x48\x63\x80', 'Sign-extending field load changed')
        disp = struct.unpack_from('<i', raw, 18)[0]
        require(disp == window['field_offset'],
                'Field offset changed: %s' % hex(disp))
    elif window['name'] == 'chained_qword':
        require(raw[15:18] == b'\x48\x8b\x80', 'Qword field load changed')
        disp = struct.unpack_from('<i', raw, 18)[0]
        require(disp == window['field_offset'],
                'Field offset changed: %s' % hex(disp))
    else:
        raise ValueError('Unknown window %s' % window['name'])
    require(raw[22:25] == b'\x48\x89\x06', 'Result store changed in %s' % window['name'])
    require(raw[25:30] == b'\xb8\x01\x00\x00\x00', 'Return changed in %s' % window['name'])
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

    With data=None, only the packet-internal checks run (hashes, lengths,
    encodings, padding counts, and the pinned target digest claim).
    With binary bytes, the digest, window bytes, padding bytes, FDE
    records, and direct-caller counts are additionally cross-checked.
    """
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 2, 'Packet must bind exactly the two windows')
    raws = {w['name']: _check_window_structure(w) for w in windows}
    if data is None:
        return raws
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest mismatch')
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
    for w in windows:
        start = _va_int(w['start_va'])
        end = _va_int(w['end_va_exclusive'])
        raw = raws[w['name']]
        require(read(start, end - start) == raw,
                'Window bytes changed at %s' % hex(start))
        pad = read(end, w['padding_int3_bytes'])
        require(pad == b'\xcc' * w['padding_int3_bytes'],
                'Padding changed at %s' % hex(end))
        require(_va_int(w['next_fde_start']) == end + w['padding_int3_bytes'],
                'Padding must end exactly at the next FDE for %s' % w['name'])
        eh = by_name['.eh_frame']
        rel = _va_int(w['fde_section_offset'])
        fde_off = eh['offset'] + rel
        rec = data[fde_off:fde_off + 20]
        require(len(rec) == 20, 'FDE record truncated for %s' % w['name'])
        # This CIE encodes initial_location as pcrel sdata4: the stored
        # value is relative to its own field address (eh VA + rel + 8).
        sdata, fde_range = struct.unpack_from('<iI', rec, 8)
        fde_start = eh['address'] + rel + 8 + sdata
        require(fde_start == start, 'FDE start changed for %s' % w['name'])
        require(fde_range == end - start, 'FDE range changed for %s' % w['name'])
        callers = _scan_direct_callers(text_bytes, text['address'], start)
        require(callers == ev['direct_callers'][w['name']],
                'Direct-caller count changed for %s: %d' % (w['name'], callers))
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
    # Without --binary, only packet-internal checks run: the default
    # artifact path may be an unmaterialized LFS pointer on this VM,
    # and silently checking against pointer bytes would be meaningless.
    analyze(data, ev)
    print('foundation-chained-field-pair evidence OK')


if __name__ == '__main__':
    main()
