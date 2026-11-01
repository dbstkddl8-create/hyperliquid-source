import hashlib
import unittest
from pathlib import Path
from tools import bole_scaled_exposure94 as m


class ExposureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = m.TARGET.read_bytes()
        cls.image = m.Image(cls.raw)

    def test_digest_and_fdes(self):
        self.assertEqual(len(self.image.frames), 2)
        for start, (end, _) in m.WINDOWS.items():
            self.assertEqual(self.image.frames[start]['end'], end)
        with self.assertRaises(ValueError):
            m.Image(self.raw, '0' * 64)

    def test_corrupt_body_even_with_recomputed_digest(self):
        image = bytearray(self.raw)
        p = self.image.offset(0x394b6aa, 8)
        image[p] ^= 1
        damaged = bytes(image)
        with self.assertRaises(ValueError):
            m.Image(damaged, hashlib.sha256(damaged).hexdigest())

    def test_range_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read((1 << 64) - 1, 8)
        bss = next(s for s in self.image.sections if s['type'] == 8 and s['name'] == '.bss')
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)

    def test_branch_decoder_and_wrong_opcode(self):
        self.assertEqual(self.image.branch(0x394b751)['condition'], 'e')
        with self.assertRaises(ValueError):
            self.image.branch(0x394b660)

    def test_indirect_call_relocation(self):
        self.assertEqual(self.image.relocation(self.image.rel_target(0x394b7ba)), 0x32815f0)
        self.assertEqual(self.image.relocation(self.image.rel_target(0x28db45f)), 0x565f5a0)
        with self.assertRaises(ValueError):
            self.image.rel_target(0x394b660)
        with self.assertRaises(ValueError):
            self.image.relocation(0)

    def test_floor_ceil_exact_and_fraction(self):
        self.assertEqual(m.scale(2, m.D, 0), (2, 0))
        self.assertEqual(m.scale(1, m.D + 1, 0), (1, 1))
        self.assertEqual(m.scale(1, m.D + 1, 1), (2, 1))
        self.assertEqual(m.single(0, m.MAX, 1)[:3], ('ok', 0, 0))

    def test_width_boundary(self):
        self.assertEqual(m.single(m.MAX, m.D, 1)[:3], ('ok', 0, m.MAX))
        self.assertEqual(m.single(m.MAX, m.D+1, 0)[:2], ('error', 3))
        b = (m.MAX * m.D) // (m.D+1) + 1
        self.assertEqual(m.scale(m.D+1, b, 0)[0], m.MAX)
        self.assertIsNone(m.scale(m.D+1, b, 1)[0])

    def test_two_stages_and_hook(self):
        self.assertEqual(m.double(2, 3*m.D//4, 3*m.D//4, 0)[:4], ('helper-ok', 0, 1, 0))
        self.assertEqual(m.double(1, m.D+1, m.D+1, 1)[:4], ('helper-ok', 0, 2, 3))
        self.assertEqual(m.double(1, m.D, m.D, 0, False)[:4], ('helper-error', 7, 1, 1))
        self.assertEqual(m.double(m.MAX, m.MAX, 1, 0)[:2], ('first-error', 3))
        self.assertEqual(m.double(m.MAX, m.D, m.MAX, 0)[:2], ('second-error', 3))

    def test_real_slice_and_corrupt_instruction(self):
        result, visited = m.run_first_slice(self.image, 1, m.D+1, 1)
        self.assertEqual(result, ('ok', 0, 2))
        self.assertIn(0x28db488, visited)
        self.assertEqual(m.run_first_slice(self.image, 0, 5, 0,
                                          lambda dividend, divisor: 1)[0], ('error', 2, None))
        original = self.image
        class Damaged:
            def read(self, va, size):
                data = original.read(va, size)
                return bytes([data[0] ^ 1]) + data[1:] if va == 0x28db46e else data
            def rel_target(self, va):
                return original.rel_target(va)
        with self.assertRaises(ValueError):
            m.run_first_slice(Damaged(), 1, 1, 1)

    def test_second_slice_and_corruption(self):
        result, visits = m.run_second_slice(self.image, 2, 3*m.D//4, 3*m.D//4, 0)
        self.assertEqual(result, ('helper', 0, 1, 0))
        self.assertIn(0x394b73e, visits)
        self.assertEqual(m.run_second_slice(self.image, m.MAX, m.D, m.MAX, 1)[0][:2], ('error', 3))
        original = self.image
        class Damaged:
            def read(self, va, size):
                data = original.read(va, size)
                return bytes([data[0] ^ 1]) + data[1:] if va == 0x394b751 else data
            def rel_target(self, va):
                return original.rel_target(va)
            def branch(self, va):
                return original.branch(va)
        with self.assertRaises(ValueError):
            m.run_second_slice(Damaged(), 1, 1, 1, 1)

    def test_limb_remainder_matches_closed_form(self):
        vals = (0, 1, m.D-1, m.D, m.D+1, m.MAX//2, m.MAX)
        for a in vals:
            for b in vals:
                for up in (0,1):
                    self.assertEqual(m.machine_scale(a,b,up), m.scale(a,b,up))
        for args in ((-1,0,0),(0,m.MAX+1,0),(1,1,2)):
            with self.assertRaises(ValueError):
                m.machine_scale(*args)

if __name__ == '__main__':
    unittest.main()
