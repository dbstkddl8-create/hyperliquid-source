"""Target-grounded local controls; no target execution and no external programs."""
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import staking_validator_vote_prune94 as p


class PruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = p.Image(p.BINARY.read_bytes())
        cls.files = p.collect(cls.image)
        cls.evidence = json.loads(cls.files['evidence.json'])
        cls.cases = json.loads(cls.files['decisions.json'])

    def test_target_identity(self):
        self.assertEqual(hashlib.sha256(self.image.data).hexdigest(), p.DIGEST)

    def test_wrong_hash_rejected_before_elf(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            p.Image(b'wrong target')

    def test_all_byte_witnesses(self):
        self.image.validate()

    def test_every_witness_local_corruption_rejected(self):
        for name, va, expected, _ in p.PINS:
            with self.subTest(name=name):
                byte = bytes([int(expected[:2], 16) ^ 1])
                with self.assertRaises(ValueError):
                    p.ByteOverlay(self.image, va, byte).validate()

    def test_virtual_ranges_fail_closed(self):
        for va, n in ((-1, 1), (0, 0), (1 << 64, 1), (0x1343c80, 1 << 64)):
            with self.subTest(va=va, n=n), self.assertRaises(ValueError):
                self.image.read(va, n)

    def test_nobits_has_no_file_mapping(self):
        bss = next(s for s in self.image.sections if s['type'] == 8 and s['name'] == '.bss' and s['size'])
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_section_crossing_rejected(self):
        text = next(s for s in self.image.sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            self.image.read(text['address'] + text['size'] - 1, 2)

    def test_fde_and_decoding_cover_exact_windows(self):
        for va, _ in p.FUNCTIONS:
            rows = p.decode_function(self.image, va)
            self.assertEqual(rows[0]['address'], va)
            self.assertEqual(rows[-1]['address'] + rows[-1]['size'], self.image.fdes[va]['end'])
            self.assertEqual(b''.join(bytes.fromhex(r['bytes']) for r in rows),
                             self.image.read(va, self.image.fdes[va]['end'] - va))

    def test_pins_are_decoded_instruction_starts(self):
        starts = {r['address'] for va, _ in p.FUNCTIONS for r in p.decode_function(self.image, va)}
        self.assertTrue(all(va in starts for _, va, _, _ in p.PINS))

    def test_decoder_known_instruction_forms(self):
        vectors = [('e8fbffffff', 5, 'call', 100), ('7505', 2, 'conditional', 107),
                   ('488b842488000000', 8, 'plain', None), ('41ffd5', 3, 'indirect_call', None),
                   ('ff1501000000', 6, 'indirect_call', None), ('48b90102030405060708', 10, 'plain', None),
                   ('6683f804', 4, 'plain', None), ('f0410fb04d00', 6, 'plain', None),
                   ('66666666662e0f1f840000000000', 14, 'plain', None), ('0f0b', 2, 'trap', None)]
        for raw, size, kind, target in vectors:
            with self.subTest(raw=raw):
                r = p.decode_one(bytes.fromhex(raw), 0, 100)
                self.assertEqual((r['size'], r['kind'], r['target']), (size, kind, target))
        self.assertEqual(p.decode_one(bytes.fromhex('ff1501000000'), 0, 100)['slot'], 107)

    def test_decoder_rejects_truncation_and_unknown_forms(self):
        for raw in ('e8', '488b84', '488b842400', '0f', '0f38', 'c5f8', '66' * 15, 'f7c001', 'ff15'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                p.decode_one(bytes.fromhex(raw), 0, 0)

    def test_branch_into_operand_rejected(self):
        # Redirect the guard into the immediate of the epilogue stack adjustment.
        va = 0x336ff07
        target = 0x337090b
        mutant = p.ByteOverlay(self.image, va + 2, struct.pack('<i', target - (va + 6)))
        with self.assertRaisesRegex(ValueError, 'instruction interior'):
            p.decode_function(mutant, 0x336fef0)

    def test_jump_tables_have_real_decoded_targets(self):
        rel = p.relocations(self.image)
        _, _, tables, _ = p.flow_records(self.image, rel)
        starts = {r['address'] for va, _ in p.FUNCTIONS for r in p.decode_function(self.image, va)}
        self.assertTrue(all(int(r['target'], 16) in starts for r in tables))

    def test_corrupt_jump_table_target_rejected(self):
        table = self.image.rip(0x337da37, '488d0d')
        raw = self.image.integer(table, 4, True)
        mutant = p.ByteOverlay(self.image, table, struct.pack('<i', raw + 1))
        with self.assertRaisesRegex(ValueError, 'instruction start'):
            p.flow_records(mutant, p.relocations(mutant))

    def test_incoming_call_and_metric_label(self):
        _, _, _, incoming = p.flow_records(self.image, p.relocations(self.image))
        self.assertEqual({r['label'] for r in incoming}, {'validator_l1_vote_tracker_prune_expired'})
        self.assertEqual({r['state_offset'] for r in incoming}, {'0x3688', '0x4108'})
        self.assertEqual({r['target'] for r in incoming}, {'0x336fef0'})

    def test_local_decisions_against_independent_tuple_rule(self):
        for c in self.cases:
            now, expiry = tuple(c['now']), tuple(c['expiry'])
            if c['guard'] != 1:
                expected = 'disabled'
            elif now <= expiry:
                expected = 'keep'
            elif c['done']:
                expected = 'remove'
            elif not c['carry_ok'] or c['shifted'] is None or c['shifted'][0] == 0:
                expected = 'time_overflow'
            else:
                expected = 'remove' if now >= tuple(c['shifted']) else 'keep'
            with self.subTest(c=c):
                self.assertEqual(c['result'], expected)

    def test_first_boundary_is_strict(self):
        t = (100, 500, 999999999)
        for done in (0, 1, 255):
            self.assertEqual(p.decision(self.image, t, t, done, (116, 500, 999999999))[0], 'keep')

    def test_grace_boundary_is_inclusive(self):
        self.assertEqual(p.decision(self.image, (116, 5, 3), (100, 5, 3), 0, (116, 5, 3))[0], 'remove')

    def test_completed_row_does_not_call_calendar(self):
        self.assertEqual(p.decision(self.image, (101, 0, 0), (100, 0, 0), 1, None, False)[0], 'remove')

    def test_calendar_failure_precedes_removal(self):
        self.assertEqual(p.decision(self.image, (101, 0, 0), (100, 0, 0), 0, None, False)[0], 'time_overflow')

    def test_decision_width_rejections(self):
        good = (1, 0, 0)
        for bad in ((1 << 31, 0, 0), (0, -1, 0), (0, 0, 1 << 32), (1, 0)):
            with self.assertRaises(ValueError):
                p.decision(self.image, bad, good, 0, good)
        for done in (-1, 256):
            with self.assertRaises(ValueError):
                p.decision(self.image, good, good, done, good)

    def test_unknown_condition_rejected(self):
        with self.assertRaises(ValueError):
            p.condition(0, p.flags_cmp(1, 2))

    def test_signed_overflow_flags(self):
        f = p.flags_cmp(-2147483648, 2147483647)
        self.assertTrue(p.condition(12, f))
        self.assertFalse(p.condition(15, f))
        self.assertTrue(p.condition(7, f))

    def test_carry_range_and_magic_division(self):
        for row in p.carry_cases(self.image):
            x = row['seconds']
            q = abs(x) // 86400 * (-1 if x < 0 else 1)
            with self.subTest(seconds=x):
                if -(1 << 31) <= q < 1 << 31:
                    self.assertEqual(row['result'], 'date_helper')
                    self.assertEqual(row['days'], q)
                else:
                    self.assertEqual(row['result'], 'time_overflow')
                    self.assertIsNone(row['days'])

    def test_carry_width_rejection(self):
        for x in (-(1 << 63)-1, 1 << 63):
            with self.assertRaises(ValueError):
                p.carry_projection(self.image, x)

    def test_carry_gate_and_quotient_mutations(self):
        gate = p.ByteOverlay(self.image, 0x3370125, b'\x83')
        self.assertNotEqual(p.carry_projection(gate, 0), p.carry_projection(self.image, 0))
        shift = p.ByteOverlay(self.image, 0x3370158, b'\x0c')
        self.assertNotEqual(p.carry_projection(shift, 86400), p.carry_projection(self.image, 86400))
        for mutant in (gate, shift):
            with self.assertRaises(ValueError):
                mutant.validate()

    def test_leaf_projection_for_every_occupied_slot(self):
        l = p.leaf_layout(self.image)
        for n in range(1, l['capacity'] + 1):
            for index in range(n):
                node = bytearray([0xa5] * (l['length'] + 2))
                keys = [bytes([j]) * l['key_size'] for j in range(n)]
                vals = [bytes([j + 50]) * l['value_size'] for j in range(n)]
                node[:n*l['key_size']] = b''.join(keys)
                node[l['values']:l['values']+n*l['value_size']] = b''.join(vals)
                struct.pack_into('<H', node, l['length'], n)
                actual, key, value = p.leaf_projection(self.image, node, index)
                expected = bytearray(node)
                expected[:(n-1)*l['key_size']] = b''.join(keys[:index] + keys[index+1:])
                expected[l['values']:l['values']+(n-1)*l['value_size']] = b''.join(vals[:index] + vals[index+1:])
                struct.pack_into('<H', expected, l['length'], n-1)
                with self.subTest(n=n, index=index):
                    self.assertEqual(actual, bytes(expected))
                    self.assertEqual((key, value), (keys[index], vals[index]))
                    self.assertEqual(actual[(n-1)*l['key_size']:n*l['key_size']], keys[-1])

    def test_repair_choices_against_occupancy_rule(self):
        for row in p.repair_cases(self.image):
            n, sibling = row['old_length'], row['sibling_length']
            if n - 1 >= 5:
                expected = 'no_repair'
            elif not row['has_parent']:
                expected = 'root'
            else:
                expected = ('merge_' if n - 1 + sibling + 1 <= 11 else 'borrow_')
                expected += 'left' if row['parent_edge'] else 'right'
            with self.subTest(row=row):
                self.assertEqual(row['result'], expected)

    def test_repair_bounds_and_count_mutation(self):
        for args in ((0, 5, 0, True), (12, 5, 0, True), (5, 12, 0, True), (5, 5, 65536, True)):
            with self.assertRaises(ValueError):
                p.repair_choice(self.image, *args)
        mutant = p.ByteOverlay(self.image, 0x2fc5643, b'\x83')
        self.assertEqual(p.repair_choice(self.image, 5, 5, 1, True)[0], 'merge_left')
        self.assertEqual(p.repair_choice(mutant, 5, 5, 1, True)[0], 'no_repair')
        with self.assertRaises(ValueError):
            mutant.validate()

    def test_repair_sibling_boundary_mutations(self):
        for site, edge in ((0x2fc56c9, 1), (0x2fc5c1a, 0)):
            original = self.image.read(site, 1)[0]
            mutant = p.ByteOverlay(self.image, site, bytes([original ^ 1]))
            self.assertNotEqual(p.repair_choice(self.image, 5, 7, edge, True)[0],
                                p.repair_choice(mutant, 5, 7, edge, True)[0])
            with self.assertRaises(ValueError):
                mutant.validate()

    def test_bad_leaf_ranges(self):
        with self.assertRaises(ValueError):
            p.leaf_projection(self.image, b'\0' * 4, 0)
        l = p.leaf_layout(self.image)
        for n, index in ((0, 0), (12, 0), (2, 2), (2, -1)):
            node = bytearray(l['length'] + 2)
            struct.pack_into('<H', node, l['length'], n)
            with self.subTest(n=n,index=index), self.assertRaises(ValueError):
                p.leaf_projection(self.image, node, index)

    def test_mutations_report_real_survivor(self):
        rows = list(csv.DictReader(io.StringIO(self.files['mutation-controls.tsv'].decode()), delimiter='\t'))
        self.assertTrue(all(r['structural_reject'] == 'True' for r in rows))
        self.assertEqual([r['name'] for r in rows if int(r['changed_outcomes']) == 0], ['date_ge_under_neq'])
        self.assertEqual(sum(int(r['changed_outcomes']) > 0 for r in rows), 9)

    def test_rela_truncation_rejected(self):
        original = self.image.sections
        copied = [dict(s) for s in original]
        next(s for s in copied if s['name'] == '.rela.dyn')['size'] -= 1
        mutant = p.ByteOverlay(self.image, 0x336ff06, b'\x01')
        mutant.sections = copied
        with self.assertRaises(ValueError):
            p.relocations(mutant)

    def test_imported_memory_operations(self):
        names = p.import_symbols(self.image)
        self.assertEqual({slot: names[slot] for slot in (0x576dfe0, 0x576e0e0, 0x576e488)},
                         {0x576dfe0: 'memcpy', 0x576e0e0: 'memmove', 0x576e488: 'memcmp'})

    def test_failure_descriptor_encoding(self):
        rows = {r['name']: r for r in p.failure_records(self.image)}
        row = rows['empty_parent']
        self.assertEqual(row['raw_argument'], 2 * row['length'] + 1)
        self.assertEqual(row['text'], 'internal error: entered unreachable code: empty internal node')
        with self.assertRaises(ValueError):
            p.failure_records(p.ByteOverlay(self.image, 0x2fc63ba, b'\x7a'))

    def test_control_scope_includes_interior_blocks(self):
        rows = list(csv.DictReader(io.StringIO(self.files['control-flow.tsv'].decode()), delimiter='\t'))
        starts = {a for a, _ in p.FUNCTIONS}
        interior = [r for r in rows if r['target'] and int(r['target'],16) not in starts
                    and r['scope'] == 'selected_window']
        self.assertTrue(interior)
        for row in rows:
            if row['target']:
                target = int(row['target'],16)
                selected = any(a <= target < self.image.fdes[a]['end'] for a in starts)
                self.assertEqual(row['scope'] == 'selected_window', selected)

    def test_generated_data_matches_collector(self):
        folder = p.ROOT / 'research/work-items/staking-validator-vote-prune-94'
        for name, expected in self.files.items():
            with self.subTest(name=name):
                self.assertEqual((folder/name).read_bytes(), expected)

    def test_gates_remain_false(self):
        self.assertFalse(any(self.evidence['gates'].values()))


if __name__ == '__main__':
    unittest.main()
