"""Negative controls for the bounded, static lattice-state reader evidence."""
import hashlib
import unittest

from tools import lthash_read94 as subject


class LatticeReadEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.BINARY.read_bytes()
        cls.record = subject.extract(cls.data)
        cls.sections = subject.sections(cls.data)

    def test_target_and_extents(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        self.assertEqual(len(self.record['functions']), 10)
        for item in self.record['functions']:
            self.assertLess(int(item['start'], 16), int(item['end'], 16))

    def test_wrong_digest(self):
        with self.assertRaises(ValueError):
            subject.verify_digest(b'not the captured node')

    def test_field_classification(self):
        for keyset in self.record['field_names'].values():
            for i, name in enumerate(keyset):
                self.assertEqual(subject.classify(name, keyset), i)
                self.assertEqual(subject.classify(name + 'x', keyset), 3)
                self.assertEqual(subject.classify(name.upper(), keyset), 3)
            self.assertEqual(subject.classify('', keyset), 3)

    def test_pinned_windows_reject_corruption(self):
        for name, va, expected in subject.PINS:
            raw = bytearray(subject.at(self.data, self.sections, va, len(bytes.fromhex(expected))))
            subject.check_pin(raw, expected)
            raw[len(raw) // 2] ^= 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                subject.check_pin(raw, expected)

    def test_dispatch_tables_and_corruption(self):
        s = [{'type': 1, 'address': 0x100, 'offset': 0, 'size': 8}]
        data = (4).to_bytes(4, 'little', signed=True) + (8).to_bytes(4, 'little', signed=True)
        self.assertEqual(subject.table(data, s, 0x100, (0x104, 0x108))['targets'], ['0x104', '0x108'])
        with self.assertRaises(ValueError):
            subject.table(data, s, 0x100, (0x104, 0x109))
        self.assertEqual(len(self.record['dispatch']), 2)
        self.assertEqual([len(x['targets']) for x in self.record['dispatch']], [4, 4])

    def test_call_and_corrupt_opcode_and_target(self):
        s = [{'type': 1, 'address': 0x100, 'offset': 0, 'size': 5}]
        good = b'\xe8\x05\x00\x00\x00'
        self.assertEqual(subject.call(good, s, 0x100, 0x10a)['target'], '0x10a')
        with self.assertRaises(ValueError):
            subject.call(b'\xe9' + good[1:], s, 0x100, 0x10a)
        with self.assertRaises(ValueError):
            subject.call(good, s, 0x100, 0x10b)
        self.assertEqual(len(self.record['calls']), 19)

    def test_rip_reference_rejects_mutation(self):
        sec = [{'type': 1, 'address': 0x100, 'offset': 0, 'size': 7}]
        raw = b'\x48\x8d\x05\x05\x00\x00\x00'
        self.assertEqual(subject.rip_lea(raw, sec, 0x100, 0x10c)['target'], '0x10c')
        with self.assertRaises(ValueError):
            subject.rip_lea(b'\x48\x8b' + raw[2:], sec, 0x100, 0x10c)
        with self.assertRaises(ValueError):
            subject.rip_lea(raw, sec, 0x100, 0x10d)
        self.assertEqual(len(self.record['rip_references']), 20)

    def test_conditional_rejects_wrong_opcode_or_target(self):
        section = [{'type': 1, 'address': 0x100, 'offset': 0, 'size': 6}]
        raw = b'\x0f\x84\x05\x00\x00\x00'
        self.assertEqual(subject.conditional(raw, section, 0x100, b'\x0f\x84', 0x10b)['target'], '0x10b')
        with self.assertRaises(ValueError):
            subject.conditional(raw, section, 0x100, b'\x0f\x85', 0x10b)
        with self.assertRaises(ValueError):
            subject.conditional(raw, section, 0x100, b'\x0f\x84', 0x10a)
        self.assertEqual(len(self.record['duplicate_branches']), 6)

    def test_reject_unmapped_nobits_and_cross_boundary(self):
        s = [{'type': 8, 'address': 0x100, 'offset': 0, 'size': 16},
             {'type': 1, 'address': 0x200, 'offset': 0, 'size': 4}]
        for va, size in ((0x100, 1), (0x203, 2), (0x1ff, 1), (0x200, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                subject.at(b'abcd', s, va, size)
        self.assertEqual(subject.at(b'abcd', s, 0x200, 4), b'abcd')

    def test_selected_branch_destinations(self):
        outer, inner = self.record['dispatch']
        self.assertEqual(outer['targets'], ['0x2dbb6c6', '0x2dbb812', '0x2dbb754', '0x2dbb7c7'])
        self.assertEqual(inner['targets'], ['0x2bb1e7e', '0x2bb1fbc', '0x2bb1ec9', '0x2bb1f85'])

    def test_record_lengths(self):
        self.assertEqual(self.record['payload_bytes'], 2048)
        self.assertEqual(self.record['inner_copy_bytes'], 2064)
        self.assertEqual(self.record['outer_copy_bytes'], 6192)

    def test_trailing_whitespace_mask(self):
        self.assertEqual(self.record['json_trailing_whitespace_bytes'], [9, 10, 13, 32])
        self.assertNotIn(11, self.record['json_trailing_whitespace_bytes'])
        self.assertNotIn(0, self.record['json_trailing_whitespace_bytes'])


if __name__ == '__main__':
    unittest.main()
