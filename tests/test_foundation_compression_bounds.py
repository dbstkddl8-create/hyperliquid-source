"""Target-grounded controls for the static compression-bound packet (no node execution)."""
import json
from pathlib import Path
import random
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_compression_bounds as bounds
from elf_index import sections

PACKET = (Path(__file__).resolve().parents[1] /
          'research/work-items/foundation-compression-bounds-94')


class CompressionBoundRuleTests(unittest.TestCase):
    """Restatement checks that need no target input."""

    def test_snappy_rule_matches_instruction_order(self):
        rng = random.Random(94)
        samples = [0, 1, 5, 6, 7, 11, 12, 65535, 65536, (1 << 63) - 1,
                   1 << 63, bounds.U64 - 33, bounds.U64 - 32, bounds.U64]
        samples += [rng.getrandbits(64) for _ in range(20000)]
        samples += [6 * k + d for k in range(2000) for d in (-1, 0, 1) if 6 * k + d >= 0]
        for n in samples:
            self.assertEqual(bounds.snappy_bound(n), bounds.snappy_bound_insns(n), n)

    def test_snappy_edges(self):
        self.assertEqual(bounds.snappy_bound(0), 32)
        self.assertEqual(bounds.snappy_bound(6), 39)
        self.assertEqual(bounds.snappy_bound(65536), 76490)
        # The window has no overflow guard: the sum wraps modulo 2**64.
        self.assertEqual(bounds.snappy_bound(bounds.U64),
                         (32 + bounds.U64 + bounds.U64 // 6) & bounds.U64)
        with self.assertRaises(ValueError):
            bounds.snappy_bound(-1)

    def test_lz4_rule_matches_instruction_order(self):
        rng = random.Random(255)
        samples = [0, 1, 254, 255, 256, 0x7dffffff, 0x7e000000, 0x7e000001,
                   0x7fffffff, 0x80000000, 0xfffffff0, bounds.U32]
        samples += [rng.randrange(0, 0x7e000001) for _ in range(20000)]
        samples += [rng.randrange(0x7e000001, 1 << 32) for _ in range(2000)]
        samples += [255 * k + d for k in range(4000) for d in (-1, 0, 1) if 255 * k + d >= 0]
        for n in samples:
            self.assertEqual(bounds.lz4_bound(n), bounds.lz4_bound_insns(n), n)

    def test_lz4_edges(self):
        self.assertEqual(bounds.lz4_bound(0), 16)
        self.assertEqual(bounds.lz4_bound(254), 270)
        self.assertEqual(bounds.lz4_bound(255), 272)
        self.assertEqual(bounds.lz4_bound(0x7e000000), 0x7e7e7e8e)
        # Unsigned limit: one past the limit and every negative int32 give 0.
        for n in (0x7e000001, 0x7fffffff, 0x80000000, bounds.U32):
            self.assertEqual(bounds.lz4_bound(n), 0)
        with self.assertRaises(ValueError):
            bounds.lz4_bound(1 << 32)

    def test_magic_exactness(self):
        m = bounds.magic_exactness()
        self.assertEqual(m['div6_error'], 2)
        self.assertTrue(m['div6_exact_all_u64'])
        self.assertEqual(m['div255_error'], 127)
        self.assertTrue(m['div255_covers_admitted_range'])


class CompressionBoundEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not bounds.TARGET.is_file() or bounds.TARGET.stat().st_size != bounds.SIZE:
            raise unittest.SkipTest('Requires materialized node #94 Git LFS input')
        cls.result = bounds.inspect(bounds.TARGET)
        cls.data = bounds.TARGET.read_bytes()
        cls.sections = sections(cls.data)

    def offset(self, va):
        s = next(s for s in self.sections
                 if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutated(self, va, raw):
        data = bytearray(self.data)
        off = self.offset(va)
        data[off:off + len(raw)] = raw
        return bytes(data)

    def assertRejects(self, data):
        with self.assertRaises(ValueError):
            bounds.analyze(data)

    def test_identity_and_windows(self):
        self.assertEqual(self.result['snappy']['window'], (0x546af50, 0x546af6b))
        self.assertEqual(self.result['lz4']['window'], (0x546e280, 0x546e2ad))
        self.assertEqual(self.result['snappy']['body_sha256'],
                         '8c23296a82e969ac0537190fdcbae87527ac42aeca3e225608500d55620463f2')
        self.assertEqual(self.result['lz4']['body_sha256'],
                         '2faf91e85036c759201857f0ee15f1c7418a0c1d9f46dcd83eed1c1edd60e23f')
        self.assertEqual(self.result['snappy']['direct_callers'],
                         [0x5081ae3, 0x5343c43, 0x546b097, 0x546c24f])
        self.assertEqual(self.result['lz4']['direct_callers'],
                         [0x5081bcf, 0x5081ce0, 0x5343e07, 0x5343ec0, 0x5489260])

    def test_snappy_magic_lock(self):
        self.assertRejects(self.mutated(0x546af50 + 6, b'\xac'))

    def test_snappy_shift_lock(self):
        self.assertRejects(self.mutated(0x546af50 + 20, b'\x03'))

    def test_snappy_constant_lock(self):
        self.assertRejects(self.mutated(0x546af50 + 25, b'\x21'))

    def test_lz4_limit_lock(self):
        self.assertRejects(self.mutated(0x546e280 + 11, b'\x7f'))

    def test_lz4_branch_lock(self):
        # ja -> jg would make the limit signed and admit negative inputs.
        self.assertRejects(self.mutated(0x546e280 + 12, b'\x7f'))

    def test_lz4_magic_lock(self):
        self.assertRejects(self.mutated(0x546e280 + 22, b'\x82'))

    def test_lz4_constant_lock(self):
        self.assertRejects(self.mutated(0x546e280 + 43, b'\x11'))

    def test_padding_locks(self):
        self.assertRejects(self.mutated(0x546af6b, b'\x90'))
        self.assertRejects(self.mutated(0x546e2ad, b'\x90'))

    def test_fde_locks(self):
        eh = next(s for s in self.sections if s['name'] == '.eh_frame')
        for off in (0x2be1a0, 0x2be1b4, 0x2be544, 0x2be558):
            with self.subTest(fde=hex(off)):
                bad = bytearray(self.data)
                bad[eh['offset'] + off + 12] ^= 0x01
                self.assertRejects(bytes(bad))

    def test_caller_locks(self):
        self.assertRejects(self.mutated(0x5343c43 + 1, b'\x00'))
        self.assertRejects(self.mutated(0x5489260 + 1, b'\x00'))

    def test_shared_callers_reach_both_windows(self):
        for lo, hi in bounds.SHARED_CALLER_FDES:
            self.assertTrue(any(lo <= c < hi for c in self.result['snappy']['direct_callers']))
            self.assertEqual(
                sum(lo <= c < hi for c in self.result['lz4']['direct_callers']), 2)

    def test_evidence_json_matches(self):
        retained = json.loads((PACKET / 'evidence.json').read_text())
        self.assertEqual(retained['target_sha256'], bounds.SHA256)
        for name in ('snappy', 'lz4'):
            self.assertEqual(retained['windows'][name]['sha256'],
                             self.result[name]['body_sha256'])
            self.assertEqual(retained['windows'][name]['e8_candidates'],
                             [hex(c) for c in self.result[name]['direct_callers']])


if __name__ == '__main__':
    unittest.main()
