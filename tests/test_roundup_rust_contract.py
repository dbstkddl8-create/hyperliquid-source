import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-roundup-rust'
sys.path.insert(0, str(ROOT / 'tools'))
import foundation_round_up_division as foundation

spec = importlib.util.spec_from_file_location('roundup_test_contract', PACKET / 'contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class RoundupContractTests(unittest.TestCase):
    def test_frozen_equations_and_rust_fixtures_are_identical(self):
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        vectors = contract.vector_bytes()
        self.assertEqual(hashlib.sha256(vectors).hexdigest(), freeze['vectors_sha256'])
        self.assertEqual(contract.digest(PACKET / 'contract.py'), freeze['contract_source_sha256'])
        self.assertEqual(vectors, (ROOT / 'src/node94-roundup/target-vectors.tsv').read_bytes())
        self.assertEqual(vectors, (PACKET / 'preparation/target-vectors.tsv').read_bytes())
        self.assertEqual(len(contract.corpus()), freeze['cases'])

    def test_overflow_and_fault_controls_have_target_semantics(self):
        self.assertEqual(contract.registers(1, (1 << 64) - 1), 0)
        self.assertIsNone(contract.registers((1 << 32) - 1, 5))
        self.assertEqual(contract.registers(9, 25), 3)
        self.assertEqual(contract.registers(0, (1 << 64) - 1), (1 << 64) - 1)

    def test_target_admission_and_corrupted_divisor_instruction(self):
        binary = ROOT / 'artifacts/node/94/hl-node'
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        self.assertEqual(contract.admit(binary), freeze['admitted_static_facts'])
        data = bytearray(binary.read_bytes())
        sections = foundation.elf_sections(data)
        evidence = json.loads((contract.FOUNDATION / 'evidence.json').read_text())
        address, offset, size = sections['.text']
        data[offset + 0x4f9eea8 - address + 2] ^= 1
        # Deliberately bypass full-file hash admission to exercise body checks.
        with self.assertRaises(ValueError):
            foundation.check_window(evidence, bytes(data), sections)


if __name__ == '__main__':
    unittest.main()
