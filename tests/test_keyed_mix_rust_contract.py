import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-keyed-mix-rust'
sys.path.insert(0, str(ROOT / 'tools'))
from foundation_keyed_multiply_xor_mixer import analyze, parse, START
from elf_index import sections

spec = importlib.util.spec_from_file_location('keyed_contract_test', PACKET / 'contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class KeyedMixContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = ROOT / 'artifacts/node/94/hl-node'
        cls.data = cls.binary.read_bytes()

    def test_frozen_expectations_reproduce_before_rust_contract(self):
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        vectors = contract.vector_bytes()
        self.assertEqual(hashlib.sha256(vectors).hexdigest(), freeze['vectors_sha256'])
        self.assertEqual(hashlib.sha256((PACKET / 'contract.py').read_bytes()).hexdigest(),
                         freeze['contract_source_sha256'])
        self.assertEqual(vectors, (PACKET / 'preparation/target-vectors.tsv').read_bytes())
        self.assertEqual(contract.mathematical_contract([0] * 6 + [1, 0]), [20])

    def test_existing_static_reader_agrees_on_all_frozen_inputs(self):
        for index, words in enumerate(contract.corpus()):
            value = parse(words[5], contract.block_bytes(words), words[6], words[7])
            self.assertEqual([value], contract.mathematical_contract(words), f'case {index}')

    def test_authenticated_target_and_instruction_corruption_control(self):
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        self.assertEqual(contract.admit(self.binary), freeze['admitted_static_facts'])
        text = next(section for section in sections(self.data) if section['name'] == '.text')
        offset = text['offset'] + START - text['address']
        corrupt = bytearray(self.data)
        corrupt[offset + 0x0d] = 0x10  # change overlapping qword offset +12 to +16
        with self.assertRaises(ValueError):
            analyze(bytes(corrupt))


if __name__ == '__main__':
    unittest.main()
