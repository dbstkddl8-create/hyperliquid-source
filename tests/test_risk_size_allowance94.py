"""Controls for the static size allowance packet; no node execution."""
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import risk_size_allowance94 as risk
from elf_index import sections


class SizeAllowanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = risk.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.evidence, cls.rows = risk.generate(cls.data)

    def test_digest_of_input(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), risk.SHA)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            risk.check_digest(self.data, '0' * 64)

    def test_changed_input_rejected(self):
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            risk.check_digest(damaged)

    def test_wrong_arithmetic_bytes_rejected(self):
        damaged = bytearray(self.data)
        _, off = risk.read_va(damaged, self.secs, 0x2a1eaa0, 1)
        damaged[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'arithmetic changed'):
            risk.validate_anchors(damaged, self.secs)

    def test_wrong_lookup_bytes_rejected(self):
        damaged = bytearray(self.data)
        _, off = risk.read_va(damaged, self.secs, 0x370ea43, 1)
        damaged[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'lookup result paths changed'):
            risk.validate_anchors(damaged, self.secs)

    def test_unmapped_and_nobits_ranges_rejected(self):
        with self.assertRaises(ValueError):
            risk.read_va(self.data, self.secs, 0, 1)
        bss = next(s for s in self.secs if s['name'] == '.bss')
        with self.assertRaises(ValueError):
            risk.read_va(self.data, self.secs, bss['address'], 1)

    def test_non_branch_rejected(self):
        with self.assertRaises(ValueError):
            risk.short_branch(self.data, self.secs, 0x2a1ea81)

    def test_extents_and_resolved_lookup(self):
        self.assertEqual([(f['start'], f['end']) for f in self.evidence['functions']],
                         [('0x2a1e9e0', '0x2a1eb16'), ('0x370e870', '0x370ea4a')])
        self.assertEqual(self.evidence['calls'][1]['target'], '0x370e870')
        self.assertEqual(len(self.evidence['branches']), 14)

    def test_signed_side_and_maxima(self):
        self.assertEqual(risk.allowance(10, 1, 3, 7, 4), ('return', 6, 7))
        self.assertEqual(risk.allowance(-20, 0, 3, 7, 4), ('return', 16, 16))
        self.assertEqual(risk.allowance(10, 0, 3, 7, 4), ('return', 3, 7))
        self.assertEqual(risk.allowance(10, 1, 3, 7, 12), ('return', 3, 7))

    def test_failure_is_conditional_and_ordered(self):
        self.assertEqual(risk.allowance(-(1 << 63), 0, 3, 7, 0)[0], 'panic')
        self.assertEqual(risk.allowance(-(1 << 63), 1, 3, 7, -1), ('return', 3, 7))
        self.assertEqual(risk.allowance(1, 1, 3, 7, -1)[0], 'panic')
        self.assertEqual(risk.allowance(0, 1, -1, 7, 0)[0], 'panic')
        self.assertEqual(risk.allowance(0, 1, 1, -1, 0)[0], 'panic')

    def test_invalid_model_inputs_rejected(self):
        with self.assertRaises(ValueError):
            risk.allowance(0, 2, 0, 0, 0)
        with self.assertRaises(ValueError):
            risk.allowance(1 << 63, 0, 0, 0, 0)

    def test_output_is_stable_and_has_controls(self):
        self.assertEqual(len(self.rows), 17)
        self.assertEqual(risk.render_tsv(self.rows), risk.render_tsv(self.rows))
        self.assertEqual(sum(row['result'] == 'panic' for row in self.rows), 4)


if __name__ == '__main__':
    unittest.main()
