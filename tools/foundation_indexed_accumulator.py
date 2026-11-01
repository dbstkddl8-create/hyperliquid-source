#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 indexed-accumulator evidence packet.

The claimed window is the single FDE entry 0x514ac60..0x514ac8c:

* index = 13 when [r8] == 0, else sign_extend32(int32 at [[r8] + 0x20]).
* entry = [rdi] + index * 8.
* qword at [entry + 0xb0] += 1; qword at [entry + 0x40] += [rcx].
* returns the index (eax holds 0xd or the sign-extended field at ret).

No call, no out-pointer store, no check beyond the null test on [r8].
All window-specific facts (bytes, offsets, padding, FDE start) are read
from the evidence packet, not hardcoded here; this checker verifies that
those packet facts decode consistently and, in binary mode, that they
match the digest-bound target. It never executes target code and makes
no reconstruction claim beyond this window's observable rule.

Run from the repository root:

    python3 tools/foundation_indexed_accumulator.py \
        --check research/work-items/foundation-indexed-accumulator-94/evidence.json
    python3 tools/foundation_indexed_accumulator.py \
        --check research/work-items/foundation-indexed-accumulator-94/evidence.json \
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


def simulate_index(table_present, index_field_i32):
    """Model the index selection of the 0x514ac60 window.

    Returns the index the window leaves in eax: the default 13 when the
    table pointer is null, else the sign-extended 32-bit field at
    table + 0x20. Only the low 32 bits of the field are loaded (movslq).
    """
    if not table_present:
        return 13
    value = index_field_i32 & 0xFFFFFFFF
    if value >= 0x80000000:
        value -= 0x100000000
    return value


def simulate_entry(base, index):
    """Model the lea: entry = base + index * 8 (64-bit wrap)."""
    return (base + index * 8) & 0xFFFFFFFFFFFFFFFF


def simulate_apply(base, table_present, index_field_i32, addend,
                   count, total):
    """Model one window execution against a dict-free scalar state.

    Returns (index, entry, new_count, new_total) with 64-bit wrapping,
    matching the addq/add pair on the entry's +0xb0 and +0x40 fields.
    """
    index = simulate_index(table_present, index_field_i32)
    entry = simulate_entry(base, index)
    return (index, entry,
            (count + 1) & 0xFFFFFFFFFFFFFFFF,
            (total + addend) & 0xFFFFFFFFFFFFFFFF)


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
    # mov (%r8),%rdx; mov (%rcx),%rcx; mov $0xd,%eax.
    require(raw[4:7] == b'\x49\x8b\x10', 'Table load changed')
    require(raw[7:10] == b'\x48\x8b\x09', 'Addend load changed')
    require(raw[10:15] == b'\xb8\x0d\x00\x00\x00', 'Default index changed')
    # test %rdx,%rdx; je +4 (lands exactly on the base load, i.e. the
    # instruction after the movslq: je at start+0x12, 2 bytes, +4).
    require(raw[15:18] == b'\x48\x85\xd2', 'Null test changed')
    require(raw[18] == 0x74 and raw[19] == 0x04, 'Null branch changed')
    require(start + 0x12 + 2 + raw[19] == start + 0x18,
            'Null branch target changed')
    # movslq 0x20(%rdx),%rax: field offset must match the packet.
    require(raw[20:23] == b'\x48\x63\x42', 'Index field load changed')
    require(raw[23] == window['index_field_offset'],
            'Index field offset changed: %s' % hex(raw[23]))
    # mov (%rdi),%rdx; lea (%rdx,%rax,8),%rax.
    require(raw[24:27] == b'\x48\x8b\x17', 'Base load changed')
    require(raw[27:31] == b'\x48\x8d\x04\xc2', 'Entry lea changed')
    # addq $1,0xb0(%rax); add %rcx,0x40(%rax).
    require(raw[31:38] == b'\x48\x83\x80\xb0\x00\x00\x00',
            'Count field address changed')
    require(raw[38] == 0x01, 'Count increment changed')
    require(raw[39:43] == b'\x48\x01\x48\x40', 'Sum field address changed')
    # The movslq (start+0x14, 4 bytes) ends exactly at the je target.
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
    require(len(windows) == 1, 'Packet must bind exactly the one window')
    window = windows[0]
    raw = _check_window_structure(window)
    rules = ev['rules']['indexed_accumulator']
    require(rules['default_index'] == 13, 'Default index changed')
    require(rules['index_field_offset'] == '0x20', 'Rule field offset changed')
    require(rules['count_offset'] == '0xb0', 'Rule count offset changed')
    require(rules['sum_offset'] == '0x40', 'Rule sum offset changed')
    if data is None:
        return raw
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

    start = _va_int(window['start_va'])
    end = _va_int(window['end_va_exclusive'])
    require(read(start, end - start) == raw, 'Window bytes changed')
    pad = read(end, window['padding_int3_bytes'])
    require(pad == b'\xcc' * window['padding_int3_bytes'], 'Padding changed')
    require(_va_int(window['next_fde_start']) == end + window['padding_int3_bytes'],
            'Padding must end exactly at the next FDE')
    eh = by_name['.eh_frame']
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
    text = by_name['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    callers = _scan_direct_callers(text_bytes, text['address'], start)
    require(callers == ev['direct_callers']['indexed_accumulator'],
            'Direct-caller count changed: %d' % callers)
    return raw


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
    print('foundation-indexed-accumulator evidence OK')


if __name__ == '__main__':
    main()
