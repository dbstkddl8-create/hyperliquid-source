"""Target-byte controls for the bounded bucket-guard family packet."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
import bucket_guard_static as packet
from bucket_guard_static import CONTROLS, CONSTANTS, EXPECT_CENSUS, FILE_VA, GOT, LIMITS, LOCATIONS, MAGIC_DIV25, OTHER_LOCATIONS, RANGES, census, controls, fde_bounds, generate, locations, read_va, relocations

PACKET = ROOT / 'research/work-items/RE-001-bucket-guard-94'


class BucketGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        target = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == 'artifacts/node/94/hl-node')
        check(target, identity)
        cls.data = target.read_bytes()

    def test_actual_target_obligations(self):
        controls(self.data)
        self.assertEqual(len(relocations(self.data)), len(GOT) + len(LOCATIONS) + len(OTHER_LOCATIONS))

    def test_location_structs(self):
        found = locations(self.data)
        self.assertEqual(sum(1 for v in found.values() if not v.get('other_file')), 5)
        self.assertEqual(found['0x5666b68'], {'line': 66, 'col': 84})
        for va in ('0x569e0a0', '0x56e9e20', '0x5718b20', '0x572e848'):
            self.assertEqual(found[va], {'line': 118, 'col': 21})
        self.assertEqual(found['0x566ae58']['line'], 124)
        self.assertEqual(found['0x566aac8']['line'], 62)

    def test_update_body_and_helper_controls(self):
        for va in CONTROLS:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    controls(bytes(changed))

    def test_constants_and_file_string(self):
        controls(self.data)
        for va in list(CONSTANTS) + [FILE_VA]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    controls(bytes(changed))

    def test_census_records_and_dispatch(self):
        records = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(records['census_total'], sum(EXPECT_CENSUS.values()))
        for va, expected_count in records['census'].items():
            self.assertEqual(len(expected_count), EXPECT_CENSUS[int(va, 16)])
        for va, sites in records['census'].items():
            target = '0x157aa10' if va == '0x5666b68' else '0x14027b0'
            for site in sites:
                self.assertEqual(site['got_target'], target)
                self.assertIsNotNone(site['fde'])

    def test_census_spot_redisassembly(self):
        records = json.loads((PACKET / 'records.json').read_text())
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for va, sites in sorted(records['census'].items()):
            site = sites[len(sites) // 2]
            address = int(site['va'], 16)
            window = read_va(self.data, address, 8)[1]
            insn = next(md.disasm(window, address))
            self.assertEqual(insn.mnemonic, 'lea')
            self.assertEqual(int(va, 16), packet._rip_target(insn))

    def test_percentile_magic_is_floor_division(self):
        for length in list(range(1, 513)) + [1000, 4095, 4096, 100000]:
            for percent in (50, 95):
                value = length * percent
                quotient = ((value >> 2) * MAGIC_DIV25) >> 64 >> 2
                self.assertEqual(quotient, value // 100, f'len={length} pct={percent}')

    def test_generate_matches_committed_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = generate(ROOT / 'artifacts/node/94/hl-node', Path(tmp) / 'packet')
            committed = json.loads((PACKET / 'records.json').read_text())
            self.assertEqual(output, committed)
            for name in RANGES:
                self.assertTrue((Path(tmp) / 'packet' / f'{name}.disasm.txt').exists())

    def test_fde_extents_and_disassembly_extracts(self):
        bounds, _ = fde_bounds(self.data)
        self.assertEqual(bounds['update-body'], (0x14027b0, 0x1403c29))
        self.assertEqual(bounds['line66-helper'], (0x13c8e10, 0x13c8f53))
        body = (PACKET / 'update-body.disasm.txt').read_text().splitlines()
        self.assertGreater(len(body), 900)
        self.assertTrue(any('0x1402b4c: movabs rcx, 0x28f5c28f5c28f5c3' in line for line in body))
        self.assertTrue(any(line.startswith('0x1403a75: lea rdi') for line in body))
        self.assertTrue(any(line.startswith('0x1403adc: lea rdi') for line in body))


if __name__ == '__main__':
    unittest.main()
