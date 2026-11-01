import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-wide-subtract-rust'
spec = importlib.util.spec_from_file_location('wide_subtract_contract', PACKET / 'contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
sys.path.insert(0, str(ROOT / 'tools'))
import wide_subtract_rust


class WideSubtractContractTests(unittest.TestCase):
    def test_borrow_propagation_and_both_top_sources(self):
        maximum = contract.MASK
        self.assertEqual(contract.native_contract([0] * 8), [0] * 5)
        self.assertEqual(contract.native_contract([0] * 4 + [1, 0, 0, 0]), [maximum] * 4 + [1])
        self.assertEqual(contract.native_contract([0, 0, 0, 1, 1, 0, 0, 0]),
                         [maximum, maximum, maximum, 0, 0])
        self.assertEqual(contract.native_contract([0, 0, 0, 0, 0, 0, 0, 1]),
                         [0, 0, 0, maximum, 1])

    def test_frozen_whole_integer_oracle(self):
        rows = [str(i) + '\t' + '\t'.join(f'{x:016x}' for x in words + contract.mathematical_contract(words))
                for i, words in enumerate(contract.corpus())]
        expected = ('\n'.join(rows) + '\n').encode()
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        self.assertEqual(len(rows), 1352)
        self.assertEqual(hashlib.sha256(expected).hexdigest(), freeze['vectors_sha256'])
        self.assertEqual(expected, (PACKET / 'preparation/target-vectors.tsv').read_bytes())
        self.assertEqual(expected, (ROOT / 'src/node94-wide-subtract/target-vectors.tsv').read_bytes())
        self.assertIs(freeze['new_rust_exists_at_freeze'], False)

    def test_existing_result_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            sentinel = output / 'result'
            sentinel.write_bytes(b'prior evidence')
            with self.assertRaisesRegex(ValueError, 'fresh output directory'):
                wide_subtract_rust.qualify(Path('unread-target'), Path('unrun-rustc'), output)
            self.assertEqual(sentinel.read_bytes(), b'prior evidence')

    @unittest.skipUnless(importlib.util.find_spec('z3'), 'optional pinned Z3 proof dependency absent')
    def test_full_domain_and_wrong_semantic_controls(self):
        checks = contract.proof()['checks']
        self.assertEqual(checks['full_512_bit_numeric_domain']['result'], 'unsat')
        self.assertEqual(checks['top_borrow_and_control']['result'], 'sat')
        self.assertEqual(checks['drop_incoming_top_borrow_control']['result'], 'sat')


if __name__ == '__main__':
    unittest.main()
