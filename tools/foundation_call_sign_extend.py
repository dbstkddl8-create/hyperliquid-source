#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 call-and-sign-extend packet.

The claimed window is one FDE entry, the immediate successor of the
#1290 delegating call window but on a different protocol:

* 0x514ad90: call 0x5334d60 with first argument container + 0x700,
  then out = sign_extend32(int32 at [container + 0x1440]),
  rbx and rbp preserved, ret 1.

The callee's return value is discarded: the stored value comes from
the field read after the call. All window-specific facts (bytes,
offsets, padding, FDE start, call target) are read from the evidence
packet, not hardcoded here; this checker verifies that those packet
facts decode consistently and, in binary mode, that they match the
digest-bound target. It never executes target code and makes no
reconstruction claim beyond this window's observable rule.

Run from the repository root:

    python3 tools/foundation_call_sign_extend.py \
        --check research/work-items/foundation-call-sign-extend-94/evidence.json
    python3 tools/foundation_call_sign_extend.py \
        --check research/work-items/foundation-call-sign-extend-94/evidence.json \
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


def simulate_call(container, callee):
    """Model the window against nested dict state.

    container is {0x700: arg, 0x1440: int32 value}; callee is called
    with the 0x700 field (its return value is discarded by the
    window) and the sign-extended 0x1440 field is returned with 1.
    """
    callee(container[0x700])
    value = container[0x1440]
    if value >= 1 << 31:
        value -= 1 << 32
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
    require(len(raw) == 51, 'Call-sign-extend window must be 51 bytes')
    require(hashlib.sha256(raw).hexdigest() == window['sha256'],
            'Evidence window hash changed')
    require(raw[:4] == b'\xf3\x0f\x1e\xfa', 'Missing endbr64')
    require(raw[-1] == 0xC3, 'Missing ret terminator')
    require(window['next_fde_start'] > window['end_va_exclusive'],
            'Next FDE must follow the window')
    # push %rbp; lea 0x700(%rdx),%rdi; mov %rsi,%rbp; push %rbx.
    require(raw[4:5] == b'\x55', 'rbp push changed')
    require(raw[5:12] == b'\x48\x8d\xba\x00\x07\x00\x00',
            'Call-argument lea changed')
    require(raw[12:15] == b'\x48\x89\xf5', 'Out-pointer save changed')
    require(raw[15:16] == b'\x53', 'rbx push changed')
    # mov %rdx,%rbx; sub $0x8,%rsp.
    require(raw[16:19] == b'\x48\x89\xd3', 'Container save changed')
    require(raw[19:23] == b'\x48\x83\xec\x08', 'Stack adjustment changed')
    # call rel32: opcode e8 plus a displacement landing on the target.
    require(raw[23:24] == b'\xe8', 'Call opcode changed')
    call_va = start + 23
    disp = struct.unpack_from('<i', raw, 24)[0]
    require(call_va + 5 + disp == _va_int(window['call_target']),
            'Call target changed')
    require(window['base_offset'] == 0x700, 'Base offset changed')
    require(window['field_offset'] == 0x1440, 'Field offset changed')
    require(_va_int(window['call_target']) == 0x5334D60,
            'Call target changed')
    # movslq 0x1440(%rbx),%rax; mov %rax,0x0(%rbp).
    require(raw[28:35] == b'\x48\x63\x83\x40\x14\x00\x00',
            'Sign-extended field load changed')
    require(raw[35:39] == b'\x48\x89\x45\x00', 'Out store changed')
    # add $0x8,%rsp; mov $0x1,%eax; pop %rbx; pop %rbp.
    require(raw[39:43] == b'\x48\x83\xc4\x08', 'Stack restore changed')
    require(raw[43:48] == b'\xb8\x01\x00\x00\x00', 'Return value changed')
    require(raw[48:49] == b'\x5b', 'rbx pop changed')
    require(raw[49:50] == b'\x5d', 'rbp pop changed')
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
    record, and direct-caller count are additionally cross-checked.
    """
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 1, 'Packet must bind exactly the one window')
    raws = [_check_window_structure(w) for w in windows]
    window = windows[0]
    require(window['name'] == 'call_sign_extend_700', 'Window name changed')
    rules = ev['rules'][window['name']]
    require(rules['base_offset'] == '0x700', 'Rule base offset changed')
    require(rules['field_offset'] == '0x1440', 'Rule field offset changed')
    require(rules['call_target'] == '0x5334d60', 'Rule call target changed')
    require(rules['preserved_registers'] == ['rbx', 'rbp'],
            'Rule registers changed')
    require(rules['return_value'] == 1, 'Rule return value changed')
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
    eh = by_name['.eh_frame']
    start = _va_int(window['start_va'])
    end = _va_int(window['end_va_exclusive'])
    raw = raws[0]
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
    # This CIE encodes initial_location as pcrel sdata4: the stored
    # value is relative to its own field address (eh VA + rel + 8).
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
    print('foundation-call-sign-extend evidence OK')


if __name__ == '__main__':
    main()
