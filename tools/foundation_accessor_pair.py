#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 accessor-pair evidence packet.

The two claimed windows flank the sentinel-checked field reader at
0x514abb0 (submitted separately as #1282, not claimed here):

* 0x514ab90, 20 bytes: plain copy of the qword at [container + 0x1228]
  to [out], returning 1. No call, no check.
* 0x514abf0, 33 bytes: virtual call through the vtable at [container]
  plus 0x478, with (rdi=container, rsi=out, rdx=container,
  rcx=entry rcx); the callee's low result byte is zero-extended and
  stored to [out], returning 1. rbx is preserved across the call.

All window-specific facts (bytes, offsets, padding, FDE starts) are read
from the evidence packet, not hardcoded here; this checker verifies that
those packet facts decode consistently and, in binary mode, that they
match the digest-bound target. It never executes target code and makes
no reconstruction claim beyond the two windows' observable rules.

Run from the repository root:

    python3 tools/foundation_accessor_pair.py \\
        --check research/work-items/foundation-accessor-pair-94/evidence.json
    python3 tools/foundation_accessor_pair.py \\
        --check research/work-items/foundation-accessor-pair-94/evidence.json \\
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


def simulate_plain_copy(field_qword):
    """Model the 0x514ab90 window: out = [container + 0x1228], ret 1."""
    return field_qword & 0xFFFFFFFFFFFFFFFF, 1


def simulate_virtual_call(call_result_byte):
    """Model the 0x514abf0 window: out = zero_extend(call_result & 0xff).

    Only the low byte of the callee's return value survives (movzbl);
    the window itself always returns 1 and preserves rbx.
    """
    return call_result_byte & 0xFF, 1


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
    if window['name'] == 'plain_copy':
        require(raw[4:7] == b'\x48\x8b\x82', 'Plain-copy load opcode changed')
        disp = struct.unpack_from('<i', raw, 7)[0]
        require(disp == window['field_offset'],
                'Plain-copy field offset changed: %s' % hex(disp))
        require(raw[11:14] == b'\x48\x89\x06', 'Plain-copy store changed')
        require(raw[14:19] == b'\xb8\x01\x00\x00\x00', 'Plain-copy return changed')
    elif window['name'] == 'virtual_call':
        require(raw[4:7] == b'\x48\x8b\x02', 'Virtual-call vtable load changed')
        require(raw[7] == 0x53, 'Virtual-call push rbx changed')
        require(raw[8:11] == b'\x48\x89\xd7', 'Virtual-call rdi setup changed')
        require(raw[11:14] == b'\x48\x89\xf3', 'Virtual-call rbx setup changed')
        require(raw[14:16] == b'\xff\x90', 'Virtual-call indirect call changed')
        disp = struct.unpack_from('<i', raw, 16)[0]
        require(disp == window['vtable_offset'],
                'Virtual-call vtable offset changed: %s' % hex(disp))
        require(raw[20:23] == b'\x0f\xb6\xc0', 'Virtual-call movzbl changed')
        require(raw[23:26] == b'\x48\x89\x03', 'Virtual-call result store changed')
        require(raw[26:31] == b'\xb8\x01\x00\x00\x00', 'Virtual-call return changed')
        require(raw[31] == 0x5B, 'Virtual-call pop rbx changed')
    else:
        raise ValueError('Unknown window %s' % window['name'])
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
    print('foundation-accessor-pair evidence OK')


if __name__ == '__main__':
    main()
