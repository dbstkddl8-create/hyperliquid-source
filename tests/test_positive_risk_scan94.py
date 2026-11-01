import hashlib
import struct
import unittest

from tools import positive_risk_scan94 as scan


class PositiveRiskScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = scan.TARGET.read_bytes()

    def test_authenticated_result_and_closure(self):
        result, branches, byte_lines = scan.analyze(self.data)
        self.assertEqual(result['target_sha256'], scan.DIGEST)
        self.assertEqual(len(result['functions']), 3)
        self.assertEqual(len(branches), 27)
        self.assertEqual(len(result['edges']), 18)
        self.assertEqual(result['constants']['result_row_stride'], 48)
        self.assertEqual(result['source_location']['line'], 194)
        self.assertEqual(sum(row['length'] for row in result['functions']), 1497)
        self.assertGreater(len(byte_lines), 0)

    def test_digest_rejects_corrupt_input_before_parsing(self):
        data = bytearray(self.data)
        data[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            scan.analyze(data)

    def test_code_corruption_rejected_even_without_digest_gate(self):
        data = bytearray(self.data)
        off, _ = scan.file_view(data, 0x21bc7dd, 1, True)
        data[off] ^= 1
        with self.assertRaisesRegex(ValueError, 'function bytes mismatch'):
            scan.analyze(data, verify_digest=False)

    def test_every_recorded_branch_detects_condition_flip(self):
        data = bytearray(self.data)
        for site, expected, target, _ in scan.BRANCHES:
            with self.subTest(site=hex(site)):
                off, first = scan.file_view(data, site, 1, True)
                opcode_offset = off + (first[0] == 0x0f)
                self.assertEqual(scan.branch(data, site)[:2], (expected, target))
                data[opcode_offset] ^= 1
                try:
                    flipped = scan.branch(data, site)[:2]
                except ValueError:
                    flipped = None
                self.assertNotEqual(flipped, (expected, target))
                data[opcode_offset] ^= 1

    def test_direct_and_indirect_call_controls(self):
        data = bytearray(self.data)
        target, _ = scan.direct_call(data, 0x251ca72)
        self.assertEqual(target, 0x24fdfe0)
        slot, _ = scan.got_call(data, 0x21bc867)
        self.assertEqual(scan.relocation(data, slot), 0x3708bf0)
        off, _ = scan.file_view(data, 0x251ca72, 5, True)
        data[off] = 0x90
        with self.assertRaisesRegex(ValueError, 'not an E8'):
            scan.direct_call(data, 0x251ca72)
        off, _ = scan.file_view(data, 0x21bc867, 6, True)
        data[off] = 0x90
        with self.assertRaisesRegex(ValueError, 'not a RIP'):
            scan.got_call(data, 0x21bc867)

    def test_relocation_type_corruption_rejected(self):
        data = bytearray(self.data)
        sec = next(s for s in scan.sections(data) if s['name'] == '.rela.dyn')
        offsets = [i for i in range(sec['offset'], sec['offset'] + sec['size'], 24)
                   if struct.unpack_from('<Q', data, i)[0] == 0x57738b8]
        self.assertEqual(len(offsets), 1)
        data[offsets[0] + 8] = 0
        with self.assertRaisesRegex(ValueError, 'relative relocation'):
            scan.relocation(data, 0x57738b8)

    def test_unbacked_and_out_of_range_addresses_rejected(self):
        with self.assertRaises(ValueError):
            scan.file_view(self.data, 0, 0, True)
        with self.assertRaises(ValueError):
            scan.file_view(self.data, 1 << 63, 1)
        bss = next(s for s in scan.sections(self.data) if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            scan.file_view(self.data, bss['address'], 1)

    def test_immediate_and_target_controls(self):
        data = bytearray(self.data)
        off, _ = scan.file_view(data, 0x21bc82e, 5, True)
        self.assertEqual(scan.immediate(data, 0x21bc82e, b'\xba', '<I'), 10000)
        data[off] = 0x90
        with self.assertRaisesRegex(ValueError, 'immediate instruction changed'):
            scan.immediate(data, 0x21bc82e, b'\xba', '<I')
        self.assertNotEqual(hashlib.sha256(data).hexdigest(), scan.DIGEST)


if __name__ == '__main__':
    unittest.main()
