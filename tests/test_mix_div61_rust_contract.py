import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-mix-div61-rust'
sys.path.insert(0, str(ROOT / 'tools'))
from foundation_multiply_mix_div61 import analyze, apply_window, TABLE_BASE
from elf_index import sections

spec = importlib.util.spec_from_file_location('mix_div61_contract_test', PACKET / 'contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class MixDiv61ContractTests(unittest.TestCase):
    def test_frozen_cases_and_every_table_bucket(self):
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        vectors = contract.vector_bytes()
        self.assertEqual(hashlib.sha256(vectors).hexdigest(), freeze['vectors_sha256'])
        self.assertEqual(hashlib.sha256((PACKET / 'contract.py').read_bytes()).hexdigest(),
                         freeze['contract_source_sha256'])
        self.assertEqual(vectors, (PACKET / 'preparation/target-vectors.tsv').read_bytes())
        buckets = {contract.mathematical_contract(words)[0] >> 58 for words in contract.corpus()}
        self.assertEqual(buckets, set(range(64)))

    def test_signed_field_and_existing_static_reader(self):
        for index, words in enumerate(contract.corpus()):
            raw = words[1]
            signed = raw - (1 << 32) if raw >= (1 << 31) else raw
            updated, _, stored, returned = apply_window(words[0], signed)
            self.assertEqual([updated, stored, returned], contract.mathematical_contract(words),
                             f'case {index}')
        self.assertEqual(contract.mathematical_contract([0, 0xffffffff])[1], 4013330093)

    def test_authenticated_capture_and_table_corruption(self):
        binary = ROOT / 'artifacts/node/94/hl-node'
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        self.assertEqual(contract.admit(binary), freeze['admitted_static_facts'])
        data = binary.read_bytes()
        section = next(s for s in sections(data)
                       if s['address'] <= TABLE_BASE < s['address'] + s['size'])
        offset = section['offset'] + TABLE_BASE - section['address']
        corrupt = bytearray(data)
        corrupt[offset] ^= 1
        with self.assertRaises(ValueError):
            analyze(bytes(corrupt))


if __name__ == '__main__':
    unittest.main()
