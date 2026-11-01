#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 conditional-call packet.

One FDE window, bound as a single item because its protocol is
distinct from its neighbours:

- 0x514b040 (33 bytes): push %rbx, zero %eax, save the out pointer
  in %rbx, test %rcx against itself, and jump exactly past the call
  when %rcx is zero, so the zero path stores 0 without calling.
  On the non-zero path, move %rcx itself into %rdi (no field load,
  no offset) and call 0x51ca580, store the callee's result to [rsi],
  and return 1 with %rbx preserved and the stack balanced.

All window-specific facts are read from the evidence packet, not
hardcoded here; this checker verifies that those packet facts decode
consistently and, in binary mode, that they match the digest-bound
target. It never executes target code and makes no reconstruction
claim beyond this window's observable rule.

Run from the repository root:

    python3 tools/foundation_conditional_call.py \
        --check research/work-items/foundation-conditional-call-94/evidence.json
    python3 tools/foundation_conditional_call.py \
        --check research/work-items/foundation-conditional-call-94/evidence.json \
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


def simulate_conditional_call(rcx, callee):
    """Model the window against a stub callee.

    Returns (out, 1). The callee is invoked only when rcx != 0;
    the zero path stores 0 without calling.
    """
    if rcx == 0:
        return 0, 1
    return callee(rcx), 1


def _va_int(value):
    return int(value, 16) if isinstance(value, str) else value


def _call_target(raw, start, offset):
    require(raw[offset] == 0xE8, 'Call opcode changed')
    disp = struct.unpack_from('<i', raw, offset + 1)[0]
    return start + offset + 5 + disp


def _check_window(window):
    """Packet-only checks for the 33-byte conditional-call window."""
    raw = bytes.fromhex(window['bytes_hex'])
    start = _va_int(window['start_va'])
    end = _va_int(window['end_va_exclusive'])
    require(len(raw) == end - start, 'Window length changed')
    require(len(raw) == window['bytes'], 'Evidence byte count changed')
    require(len(raw) == 33, 'Conditional-call window must be 33 bytes')
    require(hashlib.sha256(raw).hexdigest() == window['sha256'],
            'Evidence window hash changed')
    require(raw[:4] == b'\xf3\x0f\x1e\xfa', 'Missing endbr64')
    require(raw[-1] == 0xC3, 'Missing ret terminator')
    require(window['next_fde_start'] >= window['end_va_exclusive'],
            'Next FDE must not precede the window end')
    require(window['guard_register'] == 'rcx', 'Guard register changed')
    require(raw[4] == 0x53, 'Frame push changed')
    require(raw[5:7] == b'\x31\xc0', 'Zeroing changed')
    require(raw[7:10] == b'\x48\x89\xf3', 'Out-pointer save changed')
    require(raw[10:13] == b'\x48\x85\xc9', 'Guard test changed')
    # je at 0x514b04d (offset 13) must land exactly on the store
    # at 0x514b057 (offset 23): 13 + 2 + disp == 23.
    require(raw[13] == 0x74, 'Guard jump opcode changed')
    require(13 + 2 + struct.unpack_from('<b', raw, 14)[0] == 23,
            'Guard jump target changed')
    require(raw[15:18] == b'\x48\x89\xcf', 'Call argument move changed')
    require(_call_target(raw, start, 18) ==
            _va_int(window['call_target']), 'Call target changed')
    require(raw[23:26] == b'\x48\x89\x03', 'Out store changed')
    require(raw[26:31] == b'\xb8\x01\x00\x00\x00',
            'Return value changed')
    require(raw[31:33] == b'\x5b\xc3', 'Return sequence changed')
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
    bytes, FDE records, direct-caller counts, and callee censuses are
    additionally cross-checked.
    """
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 1, 'Packet must bind exactly the window')
    require([w['name'] for w in windows] == ['conditional_call'],
            'Window name changed')
    raw_by_name = {w['name']: _check_window(w) for w in windows}
    window = windows[0]
    rule = ev['rules']['conditional_call']
    require(rule['guard'] == 'rcx == 0 stores 0 without calling',
            'Rule guard changed')
    require(rule['call_argument'] == 'rcx itself, moved to rdi',
            'Rule call argument changed')
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
    raw = raw_by_name['conditional_call']
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
    require(callers == ev['direct_callers']['conditional_call'],
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
    print('foundation-conditional-call evidence OK')


if __name__ == '__main__':
    main()
