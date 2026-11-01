#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 call-sum pair packet.

Two adjacent FDE windows share one protocol: push %rbp and %rbx,
save the out pointer in %rbx, load [container + 0x788], load
[[container + 0x788] + 0x8e8], add 0x8f0 to the first pointer, load
the qword at [[[container + 0x788] + 0x8e8] + 0xcd0] into %rbp,
call a small callee with the adjusted pointer, add %rbp to the
callee's result, store the sum to [rsi], and return 1:

* 0x514ae60: call 0x5172db0.
* 0x514aea0: call 0x5172df0.

The two windows are byte-identical: both call sites sit 0x40 apart
and both targets sit 0x40 apart, so the same rel32 displacement
lands on a different callee from each window. All window-specific
facts are read from the evidence packet, not hardcoded here; this
checker verifies that those packet facts decode consistently and,
in binary mode, that they match the digest-bound target. It never
executes target code and makes no reconstruction claim beyond
these windows' observable rules.

Run from the repository root:

    python3 tools/foundation_call_sum_pair.py \\
        --check research/work-items/foundation-call-sum-pair-94/evidence.json
    python3 tools/foundation_call_sum_pair.py \\
        --check research/work-items/foundation-call-sum-pair-94/evidence.json \\
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


def simulate_call_sum(field_788, callee, third_field):
    """Model one pair window against nested dict state.

    field_788 is the qword at [container + 0x788]; callee is called
    with field_788 + 0x8f0; third_field is the qword at
    [[[container + 0x788] + 0x8e8] + 0xcd0]. Returns (sum, 1).
    """
    return (callee(field_788 + 0x8F0) + third_field) & 0xFFFFFFFFFFFFFFFF, 1


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
    require(window['second_hop_offset'] == 0x8E8, 'Second hop changed')
    require(window['third_field_offset'] == 0xCD0, 'Third field changed')
    require(window['add_offset'] == 0x8F0, 'Add offset changed')
    # push %rbp; push %rbx; mov %rsi,%rbx; sub $0x8,%rsp.
    require(raw[4:6] == b'\x55\x53', 'Frame pushes changed')
    require(raw[6:9] == b'\x48\x89\xf3', 'Out-pointer save changed')
    require(raw[9:13] == b'\x48\x83\xec\x08', 'Stack adjustment changed')
    # mov 0x788(%rdi),%rdi; mov 0x8e8(%rdi),%rax.
    require(raw[13:20] == b'\x48\x8b\xbf\x88\x07\x00\x00',
            'First-hop load changed')
    require(raw[20:27] == b'\x48\x8b\x87\xe8\x08\x00\x00',
            'Second-hop load changed')
    # add $0x8f0,%rdi; mov 0xcd0(%rax),%rbp; call rel32.
    require(raw[27:34] == b'\x48\x81\xc7\xf0\x08\x00\x00',
            'Addend changed')
    require(raw[34:41] == b'\x48\x8b\xa8\xd0\x0c\x00\x00',
            'Third-field load changed')
    require(raw[41:42] == b'\xe8', 'Call opcode changed')
    call_va = start + 41
    disp = struct.unpack_from('<i', raw, 42)[0]
    require(call_va + 5 + disp == _va_int(window['call_target']),
            'Call target changed')
    # add %rbp,%rax; mov %rax,(%rbx); add $0x8,%rsp.
    require(raw[46:49] == b'\x48\x01\xe8', 'Sum add changed')
    require(raw[49:52] == b'\x48\x89\x03', 'Out store changed')
    require(raw[52:56] == b'\x48\x83\xc4\x08', 'Stack restore changed')
    # mov $0x1,%eax; pop %rbx; pop %rbp; ret.
    require(raw[56:] == b'\xb8\x01\x00\x00\x00\x5b\x5d\xc3',
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
    require(len(windows) == 2, 'Packet must bind exactly the pair')
    require([w['name'] for w in windows] == ['call_sum_db0', 'call_sum_df0'],
            'Window names changed')
    require(len({w['call_target'] for w in windows}) == 2,
            'Pair callees must be distinct')
    require(windows[0]['bytes_hex'] == windows[1]['bytes_hex'],
            'Pair windows must be byte-identical')
    raws = [_check_window_structure(w) for w in windows]
    for window in windows:
        rules = ev['rules'][window['name']]
        require(rules['first_hop_offset'] == '0x788',
                'Rule first hop changed')
        require(rules['second_hop_offset'] == '0x8e8',
                'Rule second hop changed')
        require(rules['third_field_offset'] == '0xcd0',
                'Rule third field changed')
        require(rules['add_offset'] == '0x8f0', 'Rule addend changed')
        require(rules['call_target'] == window['call_target'],
                'Rule call target changed')
        require(rules['preserved_registers'] == ['rbp', 'rbx'],
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
    print('foundation-call-sum-pair evidence OK')


if __name__ == '__main__':
    main()
