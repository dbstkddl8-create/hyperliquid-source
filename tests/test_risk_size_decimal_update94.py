import unittest
from tools import risk_size_decimal_update94 as subject


class CorruptedView:
    def __init__(self, image, address):
        self.image, self.address = image, address

    def read(self, address, size):
        data = bytearray(self.image.read(address, size))
        if address <= self.address < address + size:
            data[self.address - address] ^= 1
        return bytes(data)

    def relative(self, slot):
        return self.image.relative(slot)


class DecimalUpdateEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        subject.authenticate(cls.data)
        cls.image = subject.Image(cls.data)
        cls.result, cls.cases, cls.seeds = subject.collect(cls.data)

    def test_target_digest_is_required(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.authenticate(b'not the node')

    def test_outside_and_nobits_are_not_file_backed(self):
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 1)
        section = next(s for s in self.image.sections if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            self.image.read(section['address'], 1)

    def test_corrupt_instruction_is_rejected(self):
        corrupted = CorruptedView(self.image, 0x36ff459)
        with self.assertRaisesRegex(ValueError, 'control mismatch'):
            subject.control_bytes(corrupted)
        with self.assertRaisesRegex(ValueError, 'branch opcode mismatch'):
            subject.branch(corrupted, 'gate', 0x36ff459, '75')

    def test_nested_key_width_and_corruption(self):
        self.assertEqual(int.from_bytes(self.image.read(0x33a8451, 4), 'little'), 20)
        with self.assertRaisesRegex(ValueError, 'nested_key_compare'):
            subject.control_bytes(CorruptedView(self.image, 0x33a8451))
        with self.assertRaisesRegex(ValueError, 'nested_replace'):
            subject.control_bytes(CorruptedView(self.image, 0x33a84b2))

    def test_corrupt_call_displacement_is_rejected(self):
        with self.assertRaises(ValueError):
            subject.direct_edge(CorruptedView(self.image, 0x37056d5), 0x37056d4, 0x3315e90)
        with self.assertRaises(ValueError):
            subject.edge(CorruptedView(self.image, 0x36ff3de), 0x36ff3dc, 0x3705690)

    def test_functions_and_edges(self):
        self.assertEqual(len(self.result['functions']), 7)
        self.assertEqual(len(self.result['branches']), 15)
        self.assertEqual(len(self.result['direct_calls']), 7)
        self.assertEqual(len(self.result['indirect_calls']), 4)
        self.assertEqual(self.result['vote_dispatch']['destination'], '0x2357565')

    def test_unsigned_division_magic(self):
        d = self.result['division']['divisor']
        m = int(self.result['division']['magic'], 16)
        shift = self.result['division']['shift']
        for n in (0, 1, d - 1, d, d + 1, (1 << 63), (1 << 64) - 1):
            with self.subTest(n=n):
                self.assertEqual((n * m >> 64) >> shift, n // d)

    def test_gate_precedence_and_row_boundary(self):
        f = subject.outcome
        self.assertEqual(f(10000, False, 0, 0, 1, 7, 10000), 'no-entry')
        self.assertEqual(f(10000, True, 1, 0, 1, 7, 10000), 'nonempty')
        self.assertEqual(f(10000, True, 0, 0, 1, 7, 10000), 'report-0x60')
        self.assertEqual(f(10000, True, 0, 1, 0, 7, 10000), 'report-0x60')
        self.assertEqual(f(10000, True, 0, 1, 1, 7, 10000), 'write')
        self.assertEqual(len(self.cases), 8)

    def test_seed_generation_and_overflow(self):
        f = subject.seed_keys
        self.assertEqual(f(1, 0, 2, 10000), [10000, 10001])
        self.assertEqual(f((1 << 64) - 1, 0, 0, 10000), [])
        with self.assertRaisesRegex(OverflowError, 'multiply'):
            f(((1 << 64) - 1) // 10000 + 1, 0, 1, 10000)
        with self.assertRaisesRegex(OverflowError, 'addition'):
            f(((1 << 64) - 1) // 10000, 1616, 1617, 10000)
        self.assertEqual(len(self.seeds), 6)

    def test_reject_invalid_model_widths(self):
        with self.assertRaises(ValueError):
            subject.outcome(1 << 64, True, 0, 0, 1, 0, 10000)
        with self.assertRaises(ValueError):
            subject.outcome(0, True, 0, 0, 1, 256, 10000)


if __name__ == '__main__':
    unittest.main()
