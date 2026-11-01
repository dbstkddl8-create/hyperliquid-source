import hashlib
import unittest

from tools import pdi_display_decimals94 as subject


class PdiDisplayDecimalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.evidence, cls.table, cls.branches = subject.validate(cls.data)
        cls.sections = subject.elf_index.sections(cls.data)

    def test_target_and_extent(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        self.assertEqual(len(self.evidence['functions']), 3)
        self.assertEqual([f['end_va'] for f in self.evidence['functions']],
                         ['0x36ff4e2', '0x3be46f3', '0x4a06dba'])

    def test_table_all_entries_and_first_drift(self):
        self.assertEqual(len(self.table), 256)
        self.assertEqual(sum(r[-1] for r in self.table), 195)
        self.assertEqual(self.table[24][-1], 0)
        self.assertEqual(self.table[25][2:], ('45208b2a2c280290', '45208b2a2c280291', 1))
        self.assertEqual(int(self.table[-1][2], 16), subject.multiply_ten(int(self.table[-2][2], 16)))

    def test_branch_destinations_and_inversion(self):
        rows = {a: target for a, _, _, target in self.branches}
        self.assertEqual(len(rows), 17)
        self.assertEqual(rows['0x36ff473'], '0x36ff49a')
        self.assertEqual(rows['0x3be4645'], '0x3be46ba')
        self.assertEqual(rows['0x4a06d0b'], '0x4a06dad')
        altered = bytearray(self.data)
        pos = subject.offset(self.sections, 0x36ff473, 1)
        altered[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'branch opcode'):
            subject.decode_branch(altered, self.sections, 0x36ff473, 0x75)

    def test_exact_rounding_ties(self):
        self.assertEqual(subject.round_binary64_integer((1 << 53) + 1), 0x4340000000000000)
        self.assertEqual(subject.round_binary64_integer((1 << 53) + 3), 0x4340000000000002)
        with self.assertRaises(ValueError):
            subject.round_binary64_integer(0)

    def test_reciprocal_boundaries(self):
        m = int(self.evidence['reciprocal'], 16)
        for x in (0, 1, 9999, 10000, 10001, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
            self.assertEqual((x * m) >> 75, x // 10000)
        self.assertEqual(self.evidence['reciprocal_error'], 432)

    def test_corrupted_digest_rejected(self):
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.validate(damaged)

    def test_corrupted_branch_rejected_without_digest_guard(self):
        damaged = bytearray(self.data)
        pos = subject.offset(self.sections, 0x36ff473, 1)
        damaged[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'function bytes'):
            subject.validate(damaged, check_digest=False)

    def test_corrupted_table_rejected_without_digest_guard(self):
        damaged = bytearray(self.data)
        pos = subject.offset(self.sections, subject.TABLE + 25 * 8, 8)
        damaged[pos] ^= 1
        with self.assertRaisesRegex(ValueError, 'recurrence'):
            subject.validate(damaged, check_digest=False)

    def test_unbacked_address_rejected(self):
        with self.assertRaises(ValueError):
            subject.offset(self.sections, (1 << 64) - 1, 8)
        with self.assertRaises(ValueError):
            subject.offset(self.sections, subject.TABLE, 0)


if __name__ == '__main__':
    unittest.main()
