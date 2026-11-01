#!/usr/bin/env python3
"""Static byte witnesses for node 94 validator vote expiry and tree removal.

No captured code is executed. Local decision evaluation covers the two time
comparisons and done-byte branch. Leaf projection covers the two memmoves.
These are not an emulator of the host, calendar helpers, or complete B-tree.
"""
import argparse
import csv
import hashlib
import io
import itertools
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = (
    (0x336fef0, 'validator_vote_expiry_host'),
    (0x2fd8770, 'remove_at_cursor'),
    (0x2fc54c0, 'remove_leaf_and_repair'),
    (0x2fa3650, 'borrow_from_left'),
    (0x2faa040, 'borrow_from_right'),
    (0x337da10, 'drop_action_key'),
    (0x337bd60, 'drop_nested_action'),
    (0x337cf10, 'drop_tracker_value'),
    (0x33b8a70, 'consume_bucket_map_nodes'),
)
# Manually reviewed anchors. All emitted operands, targets and ranges are read
# from ELF bytes; no disassembler output or instruction substring census.
PINS = (
    ('enabled_byte', 0x336ff01, '0fb64720', 'read host guard byte'),
    ('enabled_compare', 0x336ff05, '3c01', 'only byte one runs'),
    ('guard_exit', 0x336ff07, '0f85fb090000', 'disabled returns'),
    ('map_root', 0x336ff2c, '498b3c24', 'root from map argument'),
    ('empty_root', 0x336ff3c, '7442', 'empty map setup'),
    ('map_height', 0x336ff3e, '498b4c2408', 'map height'),
    ('first_child', 0x336ff60, '488bbf600a0000', 'leftmost descent'),
    ('map_length_pointer', 0x336ffe1, '4983c410', 'map length at offset'),
    ('empty_exit', 0x3370017, '0f84d7040000', 'no nodes to scan'),
    ('node_length', 0x3370044, '0fb78f5a0a0000', 'u16 node length'),
    ('slot_exhausted', 0x337004e, '7310', 'ascend after last slot'),
    ('parent', 0x3370060, '4c8bbf500a0000', 'parent pointer'),
    ('root_exhausted', 0x337006a, '0f8484040000', 'end of scan'),
    ('parent_slot', 0x3370073, '0fb7af580a0000', 'u16 parent edge index'),
    ('value_stride', 0x3370087, '486bc570', 'tracker value stride'),
    ('value_base', 0x337008f, '4881c180050000', 'tracker value array'),
    ('first_date_load', 0x3370099, '8b13', 'now date'),
    ('first_date_compare', 0x337009b, '413b9407e0050000', 'expiry date at value plus 0x60'),
    ('first_date_set', 0x33700a3, '0f9fc2', 'signed greater'),
    ('first_date_diff', 0x33700a6, '7518', 'date differs'),
    ('first_seconds_load', 0x33700a8, '8b5304', 'now seconds'),
    ('first_seconds_compare', 0x33700ab, '3b5164', 'expiry seconds'),
    ('first_seconds_set', 0x33700ae, '0f97c2', 'unsigned greater'),
    ('first_seconds_diff', 0x33700b1, '750d', 'seconds differ'),
    ('first_nanos_load', 0x33700b3, '8b5308', 'now subsecond word'),
    ('first_nanos_compare', 0x33700b6, '3b5168', 'expiry subsecond word'),
    ('first_nanos_branch', 0x33700b9, '770d', 'strictly greater expires'),
    ('first_keep', 0x33700bb, 'e9f5000000', 'equal expiry keeps row'),
    ('first_flag_test', 0x33700c0, '84d2', 'test date or second result'),
    ('first_flag_branch', 0x33700c2, '0f84ed000000', 'not greater keeps row'),
    ('done_compare', 0x33700c8, '80796c00', 'done byte at value offset'),
    ('done_branch', 0x33700cc, '0f8581010000', 'expired nonzero done removes'),
    ('grace_seconds', 0x33700ed, 'ba80510100', 'extra interval passed to time helper'),
    ('grace_time_call', 0x33700fc, 'ff15a6e73f02', 'time of day addition slot'),
    ('grace_range_bias', 0x337010a, '48b9000000004057ffff', 'wrapping carry range bias'),
    ('grace_range_bound', 0x3370117, '48ba81aefeff7faefeff', 'unsigned carry range threshold'),
    ('grace_day_multiplier', 0x3370141, '48b9572951cea0c84518', 'signed high-product day divisor multiplier'),
    ('grace_day_multiply', 0x337014b, '48f7e9', 'signed full-width multiply'),
    ('grace_day_sign', 0x3370151, '48c1ee3f', 'high-product sign correction'),
    ('grace_day_shift', 0x3370155, '48c1ea0d', 'high-product quotient shift'),
    ('grace_day_add', 0x3370159, '01d6', 'low-word quotient plus sign correction'),
    ('grace_range_branch', 0x3370124, '0f8206080000', 'bad carry range panics'),
    ('grace_date_call', 0x337015b, 'ff154fe73f02', 'date carry slot'),
    ('grace_date_test', 0x3370161, '85c0', 'zero date result is failure'),
    ('grace_date_failure', 0x3370163, '0f84c7070000', 'overflow panic'),
    ('second_date_compare', 0x3370169, '3903', 'now versus shifted date'),
    ('second_date_set', 0x337016b, '0f9cc0', 'signed less'),
    ('second_date_diff', 0x3370175, '7529', 'date differs'),
    ('second_seconds_compare', 0x3370177, '44396b04', 'now versus shifted seconds'),
    ('second_seconds_set', 0x337017b, '0f92c0', 'unsigned less'),
    ('second_seconds_diff', 0x337017e, '7520', 'seconds differ'),
    ('second_nanos_compare', 0x3370184, '394308', 'now versus shifted subsecond word'),
    ('second_nanos_branch', 0x3370194, '721f', 'less keeps row; equality removes'),
    ('second_remove', 0x3370196, 'e9c6000000', 'remove at grace boundary'),
    ('second_flag_test', 0x33701a0, '84c0', 'test less result'),
    ('second_flag_branch', 0x33701af, '0f84ac000000', 'not less removes'),
    ('keep_leaf_or_descend', 0x33701b8, '0f8472feffff', 'leaf increments; internal descends right'),
    ('right_edge_base', 0x33701c2, '4805680a0000', 'next child array base'),
    ('remove_log_gate', 0x337025b, '0f8552020000', 'lazy initialization before done removal'),
    ('length_decrement', 0x3370266, '48ff08', 'decrement global row count before removal'),
    ('remove_call', 0x337028d, 'e8de84c6ff', 'tree removal returns continuation cursor'),
    ('removed_niche', 0x3370388, '48f7d9', 'negate first returned value word'),
    ('removed_niche_exit', 0x337038b, '0f8063010000', 'niche sentinel ends scan'),
    ('drop_key_call', 0x3370475, 'e896d50000', 'drop removed key before value'),
    ('drop_value_call', 0x3370482, 'e889ca0000', 'drop removed value'),
    ('continuation_branch', 0x33704ab, '0f8593fbffff', 'resume returned cursor without increment'),
    ('time_failure_text', 0x3370930, '488d3de896eafc', 'panic message reference'),
    ('time_failure_length', 0x337093e, 'be26000000', 'panic text length'),
    ('time_failure_sink', 0x3370943, 'ff151fdb3f02', 'panic call'),
    ('unwind_value_drop', 0x3370965, 'e8a6c50000', 'key drop unwind still drops value'),
    ('remove_internal_or_leaf', 0x2fd878d, '0f8470030000', 'zero height goes straight to leaf'),
    ('predecessor_child', 0x2fd8793, '488b8cc8600a0000', 'internal removal selects preceding child'),
    ('predecessor_last_index', 0x2fd886e, '0fb7815a0a000048ffc8', 'last leaf entry'),
    ('remove_predecessor', 0x2fd8898, 'e823ccfeff', 'leaf removal for internal case'),
    ('replacement_key_stride', 0x2fd88ff, '48c1e207', 'key copy stride power'),
    ('replacement_value_stride', 0x2fd8903, '496bcf70', 'value copy stride'),
    ('direct_leaf_call', 0x2fd8b1b, 'e8a0c9feff', 'leaf removal for leaf case'),
    ('leaf_index_scale', 0x2fc54f6, '48c1e007', 'key stride power'),
    ('leaf_key_tail', 0x2fc5572, '4881c680000000', 'source starts one key later'),
    ('leaf_tail_count', 0x2fc557c, '48f7d34c01f3', 'length minus index minus one'),
    ('leaf_move_slot', 0x2fc5589, '488b2d508b7a02', 'overlapping move helper'),
    ('leaf_key_move', 0x2fc5590, 'ffd5', 'move remaining keys left'),
    ('leaf_value_stride', 0x2fc5597, '496bc470', 'value stride'),
    ('leaf_value_base', 0x2fc559f, '4881c780050000', 'value array base'),
    ('leaf_value_source', 0x2fc5621, '4881c6f0050000', 'source starts one value later'),
    ('leaf_value_move', 0x2fc562c, 'ffd5', 'move remaining values left'),
    ('leaf_count_write', 0x2fc562e, '418d6eff664189ad5a0a0000', 'node count decremented'),
    ('leaf_underfull_compare', 0x2fc563e, '6683fd04', 'underfull threshold'),
    ('leaf_no_repair', 0x2fc5642, '0f874e060000', 'above threshold returns'),
    ('leaf_no_parent', 0x2fc565a, '0f841d060000', 'root needs no sibling'),
    ('left_edge_zero', 0x2fc566f, '0f8441050000', 'leftmost uses right sibling'),
    ('left_merge_limit', 0x2fc56c4, '4183fe0c', 'old length plus sibling count'),
    ('left_borrow_branch', 0x2fc56c8, '0f8384050000', 'sum at least limit borrows'),
    ('merge_cursor_failure', 0x2fc56e5, '0f874f050000', 'cursor outside merged interval'),
    ('merge_size_limit', 0x2fc5700, '4883f90c', 'result must fit node'),
    ('merge_size_failure', 0x2fc5704, '0f83bc0c0000', 'oversized merge assertion'),
    ('right_parent_empty', 0x2fc5bbe, '0f84e7070000', 'no right separator assertion'),
    ('right_merge_limit', 0x2fc5c16, '4183fe0c', 'right sibling combined limit'),
    ('right_borrow_branch', 0x2fc5c1a, '734f', 'borrow instead of merge'),
    ('borrow_left_call', 0x2fc5c5f, 'e8ecd9fdff', 'borrow one from left'),
    ('borrow_right_call', 0x2fc5c78, 'e8c343feff', 'borrow one from right'),
    ('parent_underfull_compare', 0x2fc5c90, '6683f804', 'repair may propagate upward'),
    ('parent_repair_branch', 0x2fc5c94, '764a', 'underfull parent'),
    ('returned_cursor', 0x2fc5cb4, '4c89abf00000004c89bbf8000000', 'returned node and height'),
    ('empty_root_compare', 0x2fc62dd, '4885c0', 'empty root after merge'),
    ('nonempty_root_exit', 0x2fc62e0, '0f85b0f9ffff', 'nonempty root retained'),
    ('root_handle_take', 0x2fc62f1, '48c70000000000', 'take optional root handle'),
    ('missing_root_failure', 0x2fc62fb, '0f84e0000000', 'missing root assertion'),
    ('zero_height_failure', 0x2fc6308, '0f84e2000000', 'cannot lower leaf root'),
    ('root_child', 0x2fc6311, '488b8f600a0000', 'promote first child'),
    ('root_height_write', 0x2fc631b, '48ffc848894308', 'height decreases'),
    ('root_parent_clear', 0x2fc6322, '48c781500a000000000000', 'promoted child has no parent'),
    ('root_free_size', 0x2fc632d, 'bec00a0000', 'free old internal node bytes'),
    ('left_target_size', 0x2fa3670, '4883f80c', 'borrow destination capacity'),
    ('left_target_failure', 0x2fa3674, '0f83f6050000', 'left borrow destination overflow'),
    ('left_source_failure', 0x2fa368f, '0f82f4050000', 'left borrow source underflow'),
    ('left_count_writes', 0x2fa369a, '664589be5a0a0000', 'write source count'),
    ('left_target_count_write', 0x2fa36a7, '6689835a0a0000', 'write destination count'),
    ('right_target_size', 0x2faa062, '4883f80c', 'right borrow destination capacity'),
    ('right_target_failure', 0x2faa066, '0f83a4060000', 'right borrow destination overflow'),
    ('right_source_failure', 0x2faa07a, '0f82a9060000', 'right borrow source underflow'),
    ('right_count_writes', 0x2faa080, '66418984245a0a000066898b5a0a0000', 'write both counts'),
    ('action_drop_bias', 0x337da13, '48b9f6ffffffffffff7f', 'niche tag bias'),
    ('action_drop_cases', 0x337da31, '4883f806', 'maximum jump table index'),
    ('action_drop_table', 0x337da37, '488d0dfec920fd', 'relative drop table'),
    ('action_drop_empty', 0x337da4e, '740c', 'empty owned string does not free'),
    ('action_drop_nested', 0x337da5d, 'e9fee2ffff', 'nested action cleanup'),
    ('value_drop_first', 0x337cf22, '740c', 'empty first buffer avoids free'),
    ('value_drop_bucket_map', 0x337cf37, '7435', 'empty map at value plus 0x28'),
    ('bucket_map_next', 0x337cf96, 'e8d5ba0300', 'consume map at value plus 0x28'),
    ('value_drop_snapshot', 0x337cfbf, '7435', 'empty map at value plus 0x40'),
    ('snapshot_map_next', 0x337d016, 'e8e5370300', 'shared node consumer, excluded dependency'),
)


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate and hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError('node 94 SHA-256 mismatch')
        self.data = data
        self.sections = sections(data)
        _, fs = eh_frame_records(data, self.sections)
        self.fdes = {f['start']: f for f in fs}
        if len(self.fdes) != len(fs):
            raise ValueError('Duplicate FDE start')

    def offset(self, va, size=1):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('Invalid virtual range')
        matches = [s['offset'] + va - s['address'] for s in self.sections
                   if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('Virtual range lacks a unique file-backed section')
        off = matches[0]
        if off < 0 or off + size > len(self.data):
            raise ValueError('Range outside file')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def integer(self, va, size, signed=False):
        return int.from_bytes(self.read(va, size), 'little', signed=signed)

    def branch(self, va):
        a = self.read(va, 1)[0]
        if a in (0xe8, 0xe9):
            size, delta, kind = 5, self.integer(va + 1, 4, True), 'call' if a == 0xe8 else 'jump'
        elif a == 0xeb or 0x70 <= a <= 0x7f:
            size, delta, kind = 2, self.integer(va + 1, 1, True), 'jump' if a == 0xeb else 'conditional'
        elif a == 0x0f and 0x80 <= self.read(va + 1, 1)[0] <= 0x8f:
            size, delta, kind = 6, self.integer(va + 2, 4, True), 'conditional'
        else:
            raise ValueError('Not a supported relative transfer')
        target = va + size + delta
        self.offset(target)
        return kind, target, va + size

    def rip(self, va, prefix):
        prefix = bytes.fromhex(prefix)
        if self.read(va, len(prefix)) != prefix:
            raise ValueError('Unexpected RIP-relative encoding')
        return va + len(prefix) + 4 + self.integer(va + len(prefix), 4, True)

    def validate(self):
        for name, va, expected, _ in PINS:
            if self.read(va, len(bytes.fromhex(expected))).hex() != expected:
                raise ValueError('Byte witness mismatch: ' + name)
        for va, _ in FUNCTIONS:
            if va not in self.fdes or self.fdes[va]['end'] <= va:
                raise ValueError('Missing nonempty FDE')
            f = self.fdes[va]
            self.offset(va, f['end'] - va)
            if not any(s['type'] != 8 and s['flags'] & 4 and s['address'] <= va
                       and f['end'] <= s['address'] + s['size'] for s in self.sections):
                raise ValueError('FDE not wholly executable')


class ByteOverlay(Image):
    """Read-only local mutation control, deliberately not an authenticated input."""
    def __init__(self, image, address, replacement):
        image.offset(address, len(replacement))
        self.__dict__.update(image.__dict__)
        self.original = image
        self.address = address
        self.replacement = bytes(replacement)

    def read(self, va, size):
        result = bytearray(self.original.read(va, size))
        low, high = max(va, self.address), min(va + size, self.address + len(self.replacement))
        if low < high:
            result[low-va:high-va] = self.replacement[low-self.address:high-self.address]
        return bytes(result)


MUTATIONS = (
    ('expiry_nanos_inclusive', 0x33700b9, '73'),
    ('grace_nanos_exclusive', 0x3370194, '76'),
    ('done_inverted', 0x33700cd, '84'),
    ('expiry_date_unsigned', 0x33700a4, '97'),
    ('expiry_seconds_signed', 0x33700af, '9f'),
    ('grace_date_unsigned', 0x337016c, '92'),
    ('grace_seconds_signed', 0x337017c, '9c'),
    ('grace_flag_inverted', 0x33701b0, '85'),
    ('guard_two_instead_of_one', 0x336ff06, '02'),
    ('date_ge_under_neq', 0x33700a4, '9d'),
)


def mutation_controls(image, cases):
    rows = []
    for name, address, replacement in MUTATIONS:
        mutated = ByteOverlay(image, address, bytes.fromhex(replacement))
        structural_reject = False
        try:
            mutated.validate()
        except ValueError:
            structural_reject = True
        changed = []
        for i, case in enumerate(cases):
            result, _ = decision(mutated, tuple(case['now']), tuple(case['expiry']), case['done'],
                                 None if case['shifted'] is None else tuple(case['shifted']), case['carry_ok'], case['guard'])
            if result != case['result']:
                changed.append(i)
        rows.append(dict(name=name, address=hex(address), before=image.read(address,len(bytes.fromhex(replacement))).hex(),
                         after=replacement, structural_reject=structural_reject,
                         changed_outcomes=len(changed), first_changed_case=changed[0] if changed else '',
                         limit='setge equals setg when consumed only under date-inequality' if name == 'date_ge_under_neq' else 'local projection only'))
    return rows


def flags_cmp(a, b, bits=32):
    mask = (1 << bits) - 1
    a, b = a & mask, b & mask
    r = (a - b) & mask
    sign = 1 << (bits - 1)
    return dict(z=r == 0, c=a < b, s=bool(r & sign), o=bool((a ^ b) & (a ^ r) & sign))


def condition(cc, f):
    # x86 condition codes used by the witnessed decision. No inferred labels.
    table = {2: f['c'], 3: not f['c'], 4: f['z'], 5: not f['z'],
             6: f['c'] or f['z'], 7: not f['c'] and not f['z'],
             12: f['s'] != f['o'], 13: f['s'] == f['o'],
             14: f['z'] or f['s'] != f['o'], 15: not f['z'] and f['s'] == f['o']}
    if cc not in table:
        raise ValueError('Unsupported condition code')
    return table[cc]


def decision(image, now, expiry, done, shifted=None, carry_ok=True, guard=1):
    """Interpret the local compare/branch graph; calendar result is an input.

    Other host operations, the calendar and the tree are not executed here.
    Each tuple contains raw (i32 date, u32 seconds, u32 subsecond) words.
    """
    for v in (now, expiry) + (() if shifted is None else (shifted,)):
        if len(v) != 3 or not -(1 << 31) <= v[0] < 1 << 31 or any(not 0 <= x < 1 << 32 for x in v[1:]):
            raise ValueError('Time words outside decoded widths')
    if not 0 <= done < 256 or not 0 <= guard < 256:
        raise ValueError('Byte outside range')
    trace = []
    if guard != image.integer(0x336ff06, 1):
        return 'disabled', [hex(0x336ff07), hex(image.branch(0x336ff07)[1])]
    pc, flag, f = 0x337009b, False, flags_cmp(0, 0)
    comparisons = {0x337009b: (0, expiry), 0x33700ab: (1, expiry), 0x33700b6: (2, expiry),
                   0x3370169: (0, shifted), 0x3370177: (1, shifted), 0x3370184: (2, shifted)}
    following = {0x337009b: 0x33700a3, 0x33700ab: 0x33700ae, 0x33700b6: 0x33700b9,
                 0x3370169: 0x337016b, 0x3370177: 0x337017b, 0x3370184: 0x3370194}
    fallthrough = {0x33700a6: 0x33700ab, 0x33700b1: 0x33700b6, 0x33700b9: 0x33700bb,
                   0x33700c2: 0x33700c8, 0x33700cc: 0x33700d2, 0x3370175: 0x3370177,
                   0x337017e: 0x3370184, 0x3370194: 0x3370196, 0x33701af: 0x33701b5}
    for _ in range(40):
        trace.append(hex(pc))
        if pc in (0x3370253, 0x3370261):
            return 'remove', trace
        if pc == 0x33701b5:
            return 'keep', trace
        if pc == 0x3370930:
            return 'time_overflow', trace
        if pc in comparisons:
            field, rhs = comparisons[pc]
            if rhs is None:
                raise ValueError('Calendar result required on grace path')
            f = flags_cmp(now[field], rhs[field])
            pc = following[pc]
        elif pc in (0x33700a3, 0x33700ae, 0x337016b, 0x337017b):
            opcode = image.read(pc, 3)
            if opcode[0] != 15 or not 0x90 <= opcode[1] <= 0x9f:
                raise ValueError('Expected setcc')
            flag = condition(opcode[1] & 15, f)
            pc = {0x33700a3: 0x33700a6, 0x33700ae: 0x33700b1,
                  0x337016b: 0x3370175, 0x337017b: 0x337017e}[pc]
        elif pc in (0x33700c0, 0x33701a0):
            f = flags_cmp(int(flag), 0, 8)
            pc = 0x33700c2 if pc == 0x33700c0 else 0x33701af
        elif pc == 0x33700c8:
            f = flags_cmp(done, image.integer(pc + 3, 1), 8)
            pc = 0x33700cc
        elif pc == 0x33700d2:
            if not carry_ok or shifted is None or shifted[0] == 0:
                pc = image.branch(0x3370124 if not carry_ok else 0x3370163)[1]
            else:
                pc = 0x3370169
        else:
            kind, target, after = image.branch(pc)
            if kind == 'jump':
                pc = target
            elif kind == 'conditional':
                opcode = image.read(pc, 2)
                cc = (opcode[1] if opcode[0] == 15 else opcode[0]) & 15
                pc = target if condition(cc, f) else fallthrough.get(pc, after)
            else:
                raise ValueError('Unexpected call in decision graph')
    raise ValueError('Decision graph did not terminate')


def carry_projection(image, seconds):
    """Project the host's carry range gate and magic divide, not calendar code."""
    if not -(1 << 63) <= seconds < 1 << 63:
        raise ValueError('Carry outside i64')
    mask = (1 << 64) - 1
    bias = image.integer(0x337010c, 8)
    bound = image.integer(0x3370119, 8)
    f = flags_cmp((seconds + bias) & mask, bound, 64)
    cc = image.read(0x3370124, 2)[1] & 15
    if condition(cc, f):
        return dict(result='time_overflow', days=None)
    multiplier = image.integer(0x3370143, 8, True)
    high = ((seconds * multiplier) >> 64) & mask
    quotient = ((high >> image.integer(0x3370158, 1)) +
                (high >> image.integer(0x3370154, 1))) & 0xffffffff
    if quotient & (1 << 31):
        quotient -= 1 << 32
    return dict(result='date_helper', days=quotient)


def carry_cases(image):
    mask = (1 << 64) - 1
    bias, bound = image.integer(0x337010c, 8), image.integer(0x3370119, 8)
    def signed(x):
        return x - (1 << 64) if x & (1 << 63) else x
    lo, hi = signed((bound-bias) & mask), signed((mask-bias) & mask)
    interval = image.integer(0x33700ee, 4)
    values = {-(1 << 63), (1 << 63)-1, -1, 0, 1}
    for edge in (lo, hi, -interval, interval, 2*interval, -2*interval):
        values.update((edge-1, edge, edge+1))
    return [dict(seconds=x, **carry_projection(image, x)) for x in sorted(values)]


def leaf_layout(image):
    return dict(key_size=1 << image.integer(0x2fc54f9, 1),
                value_size=image.integer(0x2fc559a, 1),
                values=image.integer(0x2fc55a2, 4),
                length=image.integer(0x2fc54ef, 4),
                minimum=image.integer(0x2fc5641, 1) + 1,
                capacity=image.integer(0x2fc5703, 1) - 1)


def leaf_projection(image, node, index):
    """Project only the two leaf memmoves and u16 length store from their operands."""
    layout = leaf_layout(image)
    ks, vs, vb, no = (layout[k] for k in ('key_size', 'value_size', 'values', 'length'))
    if len(node) < no + 2:
        raise ValueError('Truncated node')
    n = struct.unpack_from('<H', node, no)[0]
    if not 0 <= index < n <= layout['capacity']:
        raise ValueError('Invalid occupied slot')
    result = bytearray(node)
    key = bytes(node[index * ks:(index + 1) * ks])
    value = bytes(node[vb + index * vs:vb + (index + 1) * vs])
    for base, stride in ((0, ks), (vb, vs)):
        result[base + index * stride:base + (n - 1) * stride] = node[base + (index + 1) * stride:base + n * stride]
    struct.pack_into('<H', result, no, n - 1)
    return bytes(result), key, value


def repair_choice(image, old_length, sibling_length, parent_edge, has_parent):
    """Interpret only the initial leaf underfull and sibling choice branches."""
    capacity = leaf_layout(image)['capacity']
    if not 1 <= old_length <= capacity or not 0 <= sibling_length <= capacity or not 0 <= parent_edge < 1 << 16:
        raise ValueError('Invalid repair fixture bounds')
    def branch_taken(site, flags):
        raw = image.read(site, 2)
        cc = (raw[1] if raw[0] == 15 else raw[0]) & 15
        return condition(cc, flags)
    trace = [0x2fc563e, 0x2fc5642]
    n = old_length - 1
    threshold = image.integer(0x2fc5641, 1)
    if branch_taken(0x2fc5642, flags_cmp(n, threshold, 16)):
        return 'no_repair', trace
    trace += [0x2fc565a]
    if branch_taken(0x2fc565a, flags_cmp(int(has_parent), 0, 64)):
        return 'root', trace
    trace += [0x2fc566f]
    right = branch_taken(0x2fc566f, flags_cmp(parent_edge, 0, 64))
    compare, branch, limit = (0x2fc5c16, 0x2fc5c1a, 0x2fc5c19) if right else (0x2fc56c4, 0x2fc56c8, 0x2fc56c7)
    trace += [compare, branch]
    borrow = branch_taken(branch, flags_cmp(old_length + sibling_length, image.integer(limit, 1)))
    return ('borrow_' if borrow else 'merge_') + ('right' if right else 'left'), trace


def repair_cases(image):
    rows = []
    capacity = leaf_layout(image)['capacity']
    for old in range(1, capacity + 1):
        for sibling, edge, parent in [(0, 0, False)] + [(s, e, True) for s in range(capacity + 1) for e in (0, 1)]:
            result, trace = repair_choice(image, old, sibling, edge, parent)
            rows.append(dict(old_length=old, sibling_length=sibling, parent_edge=edge,
                             has_parent=parent, result=result, trace=','.join(hex(x) for x in trace)))
    return rows


def decode_one(data, offset, va):
    """Restricted x86-64 opcode-pattern length/transfer decoder for this packet.

    This does not assign source semantics. Unsupported opcodes fail closed.
    Instruction bytes are retained; internal transfer targets must be starts.
    """
    start, pos, rex, operand16, address32 = offset, offset, 0, False, False
    def need(n):
        if pos + n > len(data):
            raise ValueError('Truncated instruction')
    while True:
        need(1)
        op = data[pos]
        if op in (0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x3e, 0x26, 0x36, 0x64, 0x65) or 0x40 <= op <= 0x4f:
            operand16 |= op == 0x66
            address32 |= op == 0x67
            if 0x40 <= op <= 0x4f:
                rex = op
            pos += 1
            if pos - start >= 15:
                raise ValueError('Too many instruction prefixes')
        else:
            break
    pos += 1
    imm, modrm, kind, relative = 0, False, 'plain', False
    slot_disp = None
    opwidth = 2 if operand16 and not rex & 8 else 4
    if 0x70 <= op <= 0x7f:
        imm, kind, relative = 1, 'conditional', True
    elif op in (0xe8, 0xe9, 0xeb):
        imm, kind, relative = (1 if op == 0xeb else 4), ('call' if op == 0xe8 else 'jump'), True
    elif op == 0x0f:
        need(1)
        second = data[pos]
        pos += 1
        if 0x80 <= second <= 0x8f:
            imm, kind, relative = 4, 'conditional', True
        elif second == 0x0b:
            kind = 'trap'
        elif second in (0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x1f, 0x28, 0x29, 0x2a, 0x2c, 0x2d,
                        0x2e, 0x2f, 0x51, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
                        0x5e, 0x5f, 0x6e, 0x6f, 0x7e, 0x7f, 0xaf, 0xb0, 0xb1, 0xb6, 0xb7, 0xb8,
                        0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xd6, 0xef) or 0x40 <= second <= 0x4f or 0x90 <= second <= 0x9f:
            modrm = True
        elif second in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            modrm, imm = True, 1
        else:
            raise ValueError('Unsupported 0f opcode at ' + hex(va))
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0x9c, 0x9d, 0xc9):
        pass
    elif op in (0xc3, 0xc2):
        kind, imm = 'return', 2 if op == 0xc2 else 0
    elif op == 0xcc:
        kind = 'trap'
    elif 0xb0 <= op <= 0xb7:
        imm = 1
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else opwidth
    elif op in (0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x6a, 0xa8):
        imm = 1
    elif op in (0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x68, 0xa9):
        imm = opwidth
    elif (op < 0x40 and op & 7 <= 3) or op in (0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
             0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7,
             0xd0, 0xd1, 0xd2, 0xd3, 0xf6, 0xf7, 0xfe, 0xff):
        modrm = True
        imm = 1 if op in (0x6b, 0x80, 0x83, 0xc0, 0xc1, 0xc6) else opwidth if op in (0x69, 0x81, 0xc7) else 0
    else:
        raise ValueError('Unsupported opcode at ' + hex(va))
    if modrm:
        need(1)
        m = data[pos]
        pos += 1
        mode, group, rm = m >> 6, (m >> 3) & 7, m & 7
        if op in (0xf6, 0xf7) and group in (0, 1):
            imm = 1 if op == 0xf6 else opwidth
        if op == 0xff and group in (2, 4):
            kind = 'indirect_call' if group == 2 else 'indirect_jump'
        if mode != 3:
            disp = 1 if mode == 1 else 4 if mode == 2 else 0
            if rm == 4:
                need(1)
                sib = data[pos]
                pos += 1
                if mode == 0 and sib & 7 == 5:
                    disp = 4
            elif mode == 0 and rm == 5:
                disp = 4
                if op == 0xff and group in (2, 4) and not address32:
                    slot_disp = pos
            need(disp)
            pos += disp
    need(imm)
    delta_pos = pos
    pos += imm
    if pos - start > 15:
        raise ValueError('Instruction exceeds architectural length')
    target = va + pos - start + int.from_bytes(data[delta_pos:pos], 'little', signed=True) if relative else None
    slot = va + pos - start + int.from_bytes(data[slot_disp:slot_disp + 4], 'little', signed=True) if slot_disp is not None else None
    return dict(address=va, size=pos-start, bytes=data[start:pos].hex(), kind=kind, target=target, slot=slot)


def decode_function(image, start):
    end = image.fdes[start]['end']
    raw, result, pos = image.read(start, end-start), [], 0
    while pos < len(raw):
        row = decode_one(raw, pos, start + pos)
        result.append(row)
        pos += row['size']
    starts = {r['address'] for r in result}
    for row in result:
        target = row['target']
        if target is not None and start <= target < end and target not in starts:
            raise ValueError('Internal transfer targets an instruction interior')
    return result


def relocations(image):
    found = [s for s in image.sections if s['name'] == '.rela.dyn']
    if len(found) != 1 or found[0]['type'] != 4 or found[0]['size'] % 24:
        raise ValueError('Unsupported RELA section')
    s = found[0]
    result = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        va, info, addend = struct.unpack_from('<QQq', image.data, off)
        if info == 8:
            if va in result:
                raise ValueError('Duplicate RELATIVE relocation')
            result[va] = addend
    return result


def import_symbols(image):
    """Resolve GLOB_DAT names, retaining imported-address uncertainty."""
    selected = {}
    for name in ('.rela.dyn', '.dynsym', '.dynstr'):
        rows = [s for s in image.sections if s['name'] == name]
        if len(rows) != 1 or rows[0]['type'] == 8:
            raise ValueError('Missing file-backed dynamic table')
        selected[name] = rows[0]
    rela, sym, strings = (selected[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if rela['size'] % 24 or sym['size'] % 24:
        raise ValueError('Truncated dynamic record table')
    table = image.read(strings['address'], strings['size'])
    result = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, _ = struct.unpack_from('<QQq', image.data, pos)
        if info & 0xffffffff != 6:
            continue
        index = info >> 32
        if (index + 1) * 24 > sym['size']:
            raise ValueError('Dynamic symbol index outside table')
        name = image.integer(sym['address'] + index * 24, 4)
        if name >= len(table):
            raise ValueError('Symbol name outside string table')
        end = table.find(b'\0', name)
        if end < 0:
            raise ValueError('Unterminated dynamic symbol name')
        if slot in result:
            raise ValueError('Duplicate imported slot')
        result[slot] = table[name:end].decode('ascii')
    return result


FAILURE_TEXTS = (
    ('calendar_overflow', 0x3370930, 0x337093f),
    ('merge_cursor', 0x2fc5c46, 0x2fc5c42),
    ('merge_child_count', 0x2fc6390, 0x2fc639f),
    ('empty_parent', 0x2fc63ab, 0x2fc63ba),
    ('merge_capacity', 0x2fc63d2, 0x2fc63ce),
    ('root_is_leaf', 0x2fc63fc, 0x2fc63f8),
    ('left_capacity', 0x2fa3c70, 0x2fa3c7f),
    ('left_count', 0x2fa3c89, 0x2fa3c98),
    ('left_child_count', 0x2fa3ca2, 0x2fa3cb1),
    ('right_capacity', 0x2faa710, 0x2faa71f),
    ('right_count', 0x2faa729, 0x2faa738),
)


def failure_records(image):
    rows = []
    for name, load, length in FAILURE_TEXTS:
        va = image.rip(load, '488d3d')
        if image.read(length-1,1) != b'\xbe':
            raise ValueError('Failure text length encoding changed')
        argument = image.integer(length, 4)
        packed = name == 'empty_parent'
        if packed and not argument & 1:
            raise ValueError('Expected odd packed static literal descriptor')
        size = argument >> 1 if packed else argument
        rows.append(dict(name=name, site=hex(load), text_va=hex(va), raw_argument=argument,
                         encoding='packed_static_literal' if packed else 'raw_length', length=size,
                         text=image.read(va, size).decode('ascii')))
    return rows


def tsv(rows, fields):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fields, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


# Register-indirect transfers: their manually reviewed defining RIP loads.
# They are call-target bindings, not proof of all runtime data flow.
REGISTER_LOADS = {
    0x2fc5590: (0x2fc5589, '488b2d'), 0x2fc562c: (0x2fc5589, '488b2d'),
    0x2fc57bc: (0x2fc57b5, '488b05'), 0x2fc5f00: (0x2fc5ef9, '488b05'),
    0x2fc5f89: (0x2fc5f82, '4c8b3d'), 0x2fc60a5: (0x2fc5f82, '4c8b3d'),
    **{va: (0x2faa4bb, '4c8b2d') for va in (0x2faa4c5, 0x2faa4e0, 0x2faa4fb, 0x2faa515)},
    **{va: (0x337be6e, '4c8b2d') for va in (0x337be9a, 0x337bead)},
    **{va: (0x337bfa0, '4c8b3d') for va in (0x337bfe5, 0x337bff9)},
    **{va: (0x33b8bf7, '488b1d') for va in (0x33b8c15, 0x33b8c7a)},
}
TABLES = ((0x337da45, 0x337da37, 0x337da34), (0x337bda0, 0x337bd92, 0x337bd8f))
INCOMING = ((0x222a21f, 0x222a25a), (0x470f3b0, 0x470f3eb), (0x4716e0d, 0x4716e48))


def flow_records(image, rel):
    instructions, flow, tables, incoming = [], [], [], []
    table_targets = {}
    imports = import_symbols(image)
    for jump, load, limit in TABLES:
        table = image.rip(load, '488d0d')
        n = image.integer(limit, 1) + 1
        targets = []
        for i in range(n):
            address = table + i * 4
            delta = image.integer(address, 4, True)
            target = table + delta
            targets.append(target)
            tables.append(dict(jump=hex(jump), index=i, entry=hex(address), relative=delta, target=hex(target)))
        table_targets[jump] = targets
    all_starts = set()
    for start, name in FUNCTIONS:
        rows = decode_function(image, start)
        all_starts.update(r['address'] for r in rows)
        for r in rows:
            va, kind = r['address'], r['kind']
            instructions.append(dict(function=name, address=hex(va), size=r['size'], bytes=r['bytes'], kind=kind))
            if kind == 'plain':
                continue
            slot, source, target = r['slot'], None, r['target']
            if kind == 'indirect_call' and slot is None:
                if va not in REGISTER_LOADS:
                    raise ValueError('Unbound register call')
                source, prefix = REGISTER_LOADS[va]
                slot = image.rip(source, prefix)
            if slot is not None:
                target = rel.get(slot)
            targets = table_targets.get(va, [target])
            if kind == 'indirect_jump' and slot is None and va not in table_targets:
                raise ValueError('Unbound register jump')
            for t in sorted(set(targets), key=lambda x: -1 if x is None else x):
                flow.append(dict(function=name, site=hex(va), kind=kind,
                                 target=hex(t) if t is not None else '',
                                 continuation=hex(va+r['size']) if kind in ('call', 'conditional', 'indirect_call') else '',
                                 slot=hex(slot) if slot is not None else '', imported_symbol=imports.get(slot, ''),
                                 load=hex(source) if source is not None else '',
                                 scope='selected_window' if t is not None and any(start <= t < image.fdes[start]['end'] for start, _ in FUNCTIONS) else 'outside_selected' if t is not None else 'terminal_or_external'))
    for row in tables:
        if int(row['target'], 16) not in all_starts:
            raise ValueError('Jump table target is not a decoded instruction start')
    for begin, call in INCOMING:
        # This is an incoming xref window only, not ownership of its large host.
        raw = image.read(begin, call + 5 - begin)
        if raw[:3] != bytes.fromhex('488d05') or raw[33:38] != bytes.fromhex('0f97442440'):
            raise ValueError('Incoming guard construction changed')
        if raw[38:42] != bytes.fromhex('498db424'):
            raise ValueError('Incoming map argument changed')
        label = image.rip(begin, '488d05')
        label_size = image.integer(begin + 17, 4)
        # Length is the imm32 of mov qword [rsp+0x28],imm32 at offset 12.
        if label_size != 39:
            raise ValueError('Unexpected metric label size')
        if image.branch(call)[:2] != ('call', 0x336fef0):
            raise ValueError('Incoming call changed')
        incoming.append(dict(site=hex(call), window=hex(begin), bytes=raw.hex(),
                             label_va=hex(label), label=image.read(label,label_size).decode('ascii'),
                             state_offset=hex(image.integer(begin + 42,4)), target=hex(image.branch(call)[1])))
    return instructions, flow, tables, incoming


def collect(image):
    image.validate()
    windows, functions, pins, transfers = [], [], [], []
    for va, name in FUNCTIONS:
        f = image.fdes[va]
        body = image.read(va, f['end'] - va)
        functions.append(dict(name=name, start=hex(va), end=hex(f['end']), size=len(body),
                              file_offset=hex(image.offset(va)), fde=hex(f['fde']), cie=hex(f['cie']),
                              lsda=None if f['lsda'] is None else hex(f['lsda']), sha256=hashlib.sha256(body).hexdigest()))
        windows.append(dict(start=hex(va), bytes=body.hex()))
    rel = relocations(image)
    instructions, flow, tables, incoming = flow_records(image, rel)
    for name, va, pattern, note in PINS:
        b = image.read(va, len(bytes.fromhex(pattern)))
        pins.append(dict(name=name, va=hex(va), file_offset=hex(image.offset(va)), bytes=b.hex(), observation=note))
        first = b[0]
        if first in (0xe8, 0xe9, 0xeb) or 0x70 <= first <= 0x7f or b[:1] == b'\x0f' and len(b) >= 2 and 0x80 <= b[1] <= 0x8f:
            kind, target, after = image.branch(va)
            transfers.append(dict(name=name, site=hex(va), kind=kind, target=hex(target), fallthrough=hex(after), slot=''))
        elif b[:2] in (b'\xff\x15', b'\xff\x25'):
            slot = image.rip(va, b[:2].hex())
            transfers.append(dict(name=name, site=hex(va), kind='slot_call' if b[1] == 21 else 'slot_jump',
                                  target=hex(rel[slot]) if slot in rel else 'unresolved', fallthrough=hex(va + 6), slot=hex(slot)))
    table = image.rip(0x337da37, '488d0d')
    count = image.integer(0x337da34, 1) + 1
    drops = []
    for i in range(count):
        delta = image.integer(table + 4 * i, 4, True)
        drops.append(dict(index=i, entry=hex(table + 4 * i), relative=delta, target=hex(table + delta)))
    cases = []
    def add(name, now, expiry, done, shifted, carry=True, guard=1):
        result, trace = decision(image, now, expiry, done, shifted, carry, guard)
        cases.append(dict(name=name, now=list(now), expiry=list(expiry), done=done,
                          shifted=None if shifted is None else list(shifted), carry_ok=carry,
                          guard=guard, result=result, trace=trace))
    # Raw-word tests isolate signed date versus unsigned second/subsecond order.
    words = (-2147483648, -1, 0, 1, 2147483647)
    expiry, shifted = (1, 100, 500), (17, 100, 500)
    for done in (0, 1, 255):
        for date in words:
            for sec in (0, 100, 101, 2147483648, 4294967295):
                for nano in (0, 499, 500, 501, 2147483648, 4294967295):
                    add('word_order', (date, sec, nano), expiry, done, shifted)
    for done in (0, 1, 255):
        for now in ((1, 100, 499), expiry, (1, 100, 501), (17, 100, 499), shifted, (17, 100, 501)):
            add('expiry_and_grace_edges', now, expiry, done, shifted)
    for done, carry, shifted_word in itertools.product((0, 1), (False, True), (0, 17)):
        add('calendar_failure_order', (18, 0, 0), expiry, done, (shifted_word, 100, 500), carry)
    add('grace_signed_date', (-1, 0, 0), (-2, 0, 0), 0, (1, 0, 0))
    add('grace_signed_seconds', (17, 2147483648, 0), expiry, 0, shifted)
    for guard in (0, 2, 255):
        add('disabled', (18, 0, 0), expiry, 1, shifted, guard=guard)
    mutations = mutation_controls(image, cases)
    layout = leaf_layout(image)
    leaves = []
    for n in range(1, layout['capacity'] + 1):
        for index in range(n):
            node = bytearray([0xa5] * (layout['length'] + 2))
            for j in range(n):
                node[j * layout['key_size']:(j + 1) * layout['key_size']] = bytes([j + 1]) * layout['key_size']
                start = layout['values'] + j * layout['value_size']
                node[start:start + layout['value_size']] = bytes([0x40 + j]) * layout['value_size']
            struct.pack_into('<H', node, layout['length'], n)
            after, key, value = leaf_projection(image, node, index)
            leaves.append(dict(length=n, index=index, remaining=struct.unpack_from('<H', after, layout['length'])[0],
                               removed_key_byte=key[0], removed_value_byte=value[0],
                               before_sha256=hashlib.sha256(node).hexdigest(), after_sha256=hashlib.sha256(after).hexdigest()))
    text_va = image.rip(0x3370930, '488d3d')
    text_len = image.integer(0x337093f, 4)
    summary = dict(target_sha256=DIGEST, coordinate_system='linked ELF virtual addresses',
                   functions=functions, function_count=len(functions), selected_bytes=sum(f['size'] for f in functions),
                   control_kinds={k: sum(r['kind'] == k for r in flow) for k in sorted({r['kind'] for r in flow})},
                   failure_text_records=len(FAILURE_TEXTS), jump_table_entries=len(tables), witness_count=len(pins), transfer_count=len(transfers),
                   decoded_instructions=len(instructions), decoded_control_records=len(flow), incoming_xrefs=len(incoming),
                   decision_cases=len(cases), carry_cases=len(carry_cases(image)), repair_choice_cases=len(repair_cases(image)), leaf_projection_cases=len(leaves), leaf_layout=layout,
                   mutations=len(mutations), mutations_changing_outcomes=sum(r['changed_outcomes'] > 0 for r in mutations),
                   grace_seconds=image.integer(0x33700ee, 4),
                   panic=dict(va=hex(text_va), length=text_len, text=image.read(text_va, text_len).decode('ascii')),
                   scope='static path witnesses and local branch/leaf projections; no target execution',
                   unresolved=['calendar helper implementation and invalid chrono values',
                               'dynamic behavior of merge, rotation, allocator and unwind paths',
                               'complete metrics call closure',
                               'stake accounting and epoch transitions outside this prune path'],
                   gates=dict(mapped=False, built=False, behavior=False, identity=False))
    return {'evidence.json': json_bytes(summary), 'windows.json': json_bytes(windows),
            'instructions.tsv': tsv(instructions, ('function', 'address', 'size', 'bytes', 'kind')),
            'control-flow.tsv': tsv(flow, ('function', 'site', 'kind', 'target', 'continuation', 'slot', 'imported_symbol', 'load', 'scope')),
            'incoming-xrefs.tsv': tsv(incoming, ('site', 'window', 'bytes', 'label_va', 'label', 'state_offset', 'target')),
            'jump-tables.tsv': tsv(tables, ('jump', 'index', 'entry', 'relative', 'target')),
            'failures.tsv': tsv(failure_records(image), ('name', 'site', 'text_va', 'raw_argument', 'encoding', 'length', 'text')),
            'witnesses.tsv': tsv(pins, ('name', 'va', 'file_offset', 'bytes', 'observation')),
            'transfers.tsv': tsv(transfers, ('name', 'site', 'kind', 'target', 'fallthrough', 'slot')),
            'drop-table.tsv': tsv(drops, ('index', 'entry', 'relative', 'target')),
            'decisions.json': json_bytes(cases),
            'carry-cases.tsv': tsv(carry_cases(image), ('seconds', 'result', 'days')),
            'repair-choices.tsv': tsv(repair_cases(image), ('old_length', 'sibling_length', 'parent_edge', 'has_parent', 'result', 'trace')),
            'mutation-controls.tsv': tsv(mutations, ('name', 'address', 'before', 'after', 'structural_reject', 'changed_outcomes', 'first_changed_case', 'limit')),
            'leaf-projections.tsv': tsv(leaves, ('length', 'index', 'remaining', 'removed_key_byte', 'removed_value_byte', 'before_sha256', 'after_sha256'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    # Authenticate and collect before creating or writing any output.
    files = collect(Image(BINARY.read_bytes()))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(files.items()):
        (args.out / name).write_bytes(data)
    print('Wrote ' + str(len(files)) + ' deterministic static evidence files')


if __name__ == '__main__':
    main()
