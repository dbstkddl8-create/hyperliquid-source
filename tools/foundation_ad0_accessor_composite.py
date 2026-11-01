#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 ad0 accessor + composite packet.

Two adjacent FDE windows bound as one family item, because the second
window is the composite consumer of the first window's callee:

- 0x514af10 (37 bytes): push %rbx, load [container + 0x788], save the
  out pointer in %rbx, load [[container + 0x788] + 0x8f8] as the callee
  argument, call 0x5172ad0, store the callee's result to [rsi], and
  return 1 with %rbx preserved and the stack balanced.
- 0x514af40 (152 bytes): with the same container root, S is
  [.. + 0xa70] + call 0x5172a30(field 0x8f8) +
  call 0x51ca740(rcx + 0x40), and T is twice
  (call 0x5172ad0(field 0x8f8) + [.. + 0xa78]); the stored result is
  S - T when T < S (unsigned, cmovb) and 0 otherwise, and the window
  returns 1 with r12/r13/rbp/rbx preserved.

All window-specific facts are read from the evidence packet, not
hardcoded here; this checker verifies that those packet facts decode
consistently and, in binary mode, that they match the digest-bound
target. It never executes target code and makes no reconstruction
claim beyond these windows' observable rules.

Run from the repository root:

    python3 tools/foundation_ad0_accessor_composite.py \
        --check research/work-items/foundation-ad0-accessor-composite-94/evidence.json
    python3 tools/foundation_ad0_accessor_composite.py \
        --check research/work-items/foundation-ad0-accessor-composite-94/evidence.json \
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
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def simulate_ad0_accessor(field_8f8, callee):
    """Model the accessor window against nested dict state.

    field_8f8 is the qword at [[container + 0x788] + 0x8f8]; callee
    is called with it. Returns (callee result, 1).
    """
    return callee(field_8f8), 1


def simulate_ad0_composite(field_a70, call_a30, call_mid, field_a78,
                          call_ad0):
    """Model the composite window from its callee results and fields.

    S = field_a70 + call_a30 + call_mid (mod 2**64);
    T = 2 * (call_ad0 + field_a78) (mod 2**64); the stored result is
    S - T when T < S in unsigned comparison, else 0. Returns
    (stored result, 1).
    """
    total = (field_a70 + call_a30 + call_mid) & MASK
    doubled = (2 * ((call_ad0 + field_a78) & MASK)) & MASK
    stored = (total - doubled) & MASK if doubled < total else 0
    return stored, 1


def _va_int(value):
    return int(value, 16) if isinstance(value, str) else value


def _call_target(raw, start, offset):
    require(raw[offset] == 0xE8, 'Call opcode changed')
    disp = struct.unpack_from('<i', raw, offset + 1)[0]
    return start + offset + 5 + disp


def _check_accessor(window):
    """Packet-only checks for the 0x514af10 window."""
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
    require(raw[4] == 0x53, 'Frame push changed')
    require(raw[5:12] == b'\x48\x8b\x87\x88\x07\x00\x00',
            'First-hop load changed')
    require(raw[12:15] == b'\x48\x89\xf3', 'Out-pointer save changed')
    require(raw[15:22] == b'\x48\x8b\xb8\xf8\x08\x00\x00',
            'Field load changed')
    require(_call_target(raw, start, 22) ==
            _va_int(window['call_target']), 'Call target changed')
    require(raw[27:30] == b'\x48\x89\x03', 'Out store changed')
    require(raw[30:35] == b'\xb8\x01\x00\x00\x00',
            'Return value changed')
    require(raw[35:37] == b'\x5b\xc3', 'Return sequence changed')
    return raw


def _check_composite(window):
    """Packet-only checks for the 0x514af40 window."""
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
    # Prologue: push r13/r12, save out/ container, push rbp/rbx, sub 8.
    require(raw[4:20] == b'\x41\x55\x41\x54\x49\x89\xf4\x55'
            b'\x48\x89\xfd\x53\x48\x83\xec\x08', 'Prologue changed')
    # First half: 0x788 root, 0x8e8 hop, 0x30 field, 0xa70 field,
    # 0x8f8 field, lea rcx+0x40.
    require(raw[20:27] == b'\x48\x8b\x87\x88\x07\x00\x00',
            'First-hop load changed')
    require(raw[27:34] == b'\x48\x8b\x90\xe8\x08\x00\x00',
            'Second-hop load changed')
    require(raw[34:38] == b'\x48\x8b\x48\x30', 'rcx field load changed')
    require(raw[38:45] == b'\x48\x8b\x9a\x70\x0a\x00\x00',
            'a70 field load changed')
    require(raw[45:52] == b'\x48\x8b\xb8\xf8\x08\x00\x00',
            'Field load changed')
    require(raw[52:56] == b'\x4c\x8d\x69\x40', 'lea changed')
    targets = window['call_targets']
    require(_call_target(raw, start, 56) == _va_int(targets[0]),
            'First call target changed')
    require(raw[61:64] == b'\x4c\x89\xef', 'Mid-call argument changed')
    require(raw[64:67] == b'\x48\x01\xc3', 'First accumulation changed')
    require(_call_target(raw, start, 67) == _va_int(targets[1]),
            'Second call target changed')
    require(raw[72:75] == b'\x48\x01\xc3', 'Second accumulation changed')
    # Second half: reload 0x788 root, 0x8e8 hop, 0xa78 field, 0x8f8 field.
    require(raw[75:82] == b'\x48\x8b\x85\x88\x07\x00\x00',
            'Reload first-hop load changed')
    require(raw[82:89] == b'\x48\x8b\x90\xe8\x08\x00\x00',
            'Reload second-hop load changed')
    require(raw[89:96] == b'\x48\x8b\xaa\x78\x0a\x00\x00',
            'a78 field load changed')
    require(raw[96:103] == b'\x48\x8b\xb8\xf8\x08\x00\x00',
            'Reload field load changed')
    require(_call_target(raw, start, 103) == _va_int(targets[2]),
            'Third call target changed')
    # Tail: rdx = S; rax += a78-field; rax += rax; rdx -= rax;
    # cmp rbx,rax; eax = 0; cmovb rdx,rax; store; add rsp,8; ret 1.
    require(raw[108:111] == b'\x48\x89\xda', 'S save changed')
    require(raw[111:114] == b'\x48\x01\xe8', 'a78 accumulation changed')
    require(raw[114:117] == b'\x48\x01\xc0', 'Doubling changed')
    require(raw[117:120] == b'\x48\x29\xc2', 'Difference changed')
    require(raw[120:123] == b'\x48\x39\xd8', 'Comparison changed')
    require(raw[123:128] == b'\xb8\x00\x00\x00\x00',
            'Zero result changed')
    require(raw[128:132] == b'\x48\x0f\x42\xc2', 'cmovb changed')
    require(raw[132:136] == b'\x49\x89\x04\x24', 'Out store changed')
    require(raw[136:140] == b'\x48\x83\xc4\x08', 'Stack restore changed')
    require(raw[140:145] == b'\xb8\x01\x00\x00\x00',
            'Return value changed')
    require(raw[145:152] == b'\x5b\x5d\x41\x5c\x41\x5d\xc3',
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
    bytes, FDE records, direct-caller counts, and callee censuses are
    additionally cross-checked.
    """
    require(ev['target_sha256'] == SHA256, 'Evidence digest mismatch')
    windows = ev['windows']
    require(len(windows) == 2, 'Packet must bind exactly the pair')
    require([w['name'] for w in windows] ==
            ['ad0_accessor', 'ad0_composite'], 'Window names changed')
    raw_by_name = {
        'ad0_accessor': _check_accessor(windows[0]),
        'ad0_composite': _check_composite(windows[1]),
    }
    rules = ev['rules']
    accessor_rules = rules['ad0_accessor']
    require(accessor_rules['first_hop_offset'] == '0x788',
            'Rule first hop changed')
    require(accessor_rules['field_offset'] == '0x8f8',
            'Rule field changed')
    require(accessor_rules['call_target'] ==
            windows[0]['call_target'], 'Rule call target changed')
    require(accessor_rules['preserved_registers'] == ['rbx'],
            'Rule registers changed')
    require(accessor_rules['return_value'] == 1, 'Rule return value changed')
    composite_rules = rules['ad0_composite']
    require(composite_rules['call_targets'] ==
            windows[1]['call_targets'], 'Rule call targets changed')
    require(composite_rules['preserved_registers'] ==
            ['r12', 'r13', 'rbp', 'rbx'], 'Rule registers changed')
    require(composite_rules['return_value'] == 1,
            'Rule return value changed')
    require(composite_rules['field_a70_offset'] == '0xa70',
            'Rule a70 field changed')
    require(composite_rules['field_a78_offset'] == '0xa78',
            'Rule a78 field changed')
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
    print('foundation-ad0-accessor-composite evidence OK')


if __name__ == '__main__':
    main()
