"""Actual pinned-input and fixed-row corruption controls; no target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import u128_remainder_contract as subject


class RemainderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.body = (subject.PACKET / 'native/target-197.bin').read_bytes()
        cls.observed = json.loads((subject.PACKET / 'native/record.json').read_text())

    def test_complete_actual_body(self):
        result = subject.inspect_target(self.target)
        self.assertEqual(result['body_sha256'], subject.BODY_SHA256)
        self.assertEqual(result['proof']['rows'], 68)
        self.assertEqual(result['proof']['returns'], [0x565f875, 0x565f8b4])
        self.assertEqual(result['selected_frame']['end'], subject.BEGIN + 197)

    def test_actual_instruction_change_bypasses_file_guard_then_rejects(self):
        # Actual CMOVB r8,rcx -> CMOVAE: changes whether low divisor is zeroed.
        changed = bytearray(self.body)
        changed[0x77] ^= 1
        with self.assertRaisesRegex(ValueError, 'instruction encoding differs'):
            subject.prove_body(bytes(changed))

    def test_truncated_complete_body_rejects(self):
        with self.assertRaisesRegex(ValueError, '197-byte body required'):
            subject.prove_body(self.body[:-1])

    def test_actual_fde_size_change_bypasses_digest_guard_then_rejects(self):
        changed = bytearray(self.target)
        off = self.observed['target']['selected_frame']['FDE_range_file_offset']
        struct.pack_into('<I', changed, off, 198)
        with self.assertRaisesRegex(ValueError, 'FDE extent disagreement'):
            subject.inspect_target(bytes(changed))

    def test_actual_slot_kind_change_bypasses_digest_guard_then_rejects(self):
        changed = bytearray(self.target)
        off = self.observed['target']['slot']['record_file_offset']
        struct.pack_into('<Q', changed, off + 8, 1)
        with self.assertRaisesRegex(ValueError, 'RELATIVE relocation'):
            subject.inspect_target(bytes(changed))

    def test_full_input_admission_rejects_changed_target(self):
        changed = bytearray(self.target)
        changed[self.observed['target']['mapping']['file_offset']] ^= 1
        with self.assertRaisesRegex(ValueError, 'Target identity differs'):
            subject.analyze(bytes(changed), b'not-an-archive')

    def test_full_archive_admission_rejects_unpinned_input(self):
        with self.assertRaisesRegex(ValueError, 'archive identity differs'):
            subject.analyze(self.target, b'not-an-archive')

    def test_retained_both_actual_candidates_equal(self):
        records = self.observed['official']['definitions']
        self.assertEqual(len(records), 2)
        self.assertEqual({row['member'] for row in records}, set(subject.DEFINITIONS))
        for row in records:
            self.assertEqual(bytes.fromhex(row['body_hex']), self.body)
            self.assertEqual(row['code_relocations'], [])
        self.assertTrue(all(row['raw_equal'] for row in self.observed['comparison']))
        self.assertEqual(self.observed['selected_interval_denominator'], 1)


if __name__ == '__main__':
    unittest.main()
