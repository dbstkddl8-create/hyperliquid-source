import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node94-limb-fold-rust'
spec = importlib.util.spec_from_file_location('limb_fold_contract', PACKET / 'contract.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
sys.path.insert(0, str(ROOT / 'tools'))
import limb_fold_rust


class LimbFoldContractTests(unittest.TestCase):
    def test_observed_carry_and_high_limb_edges(self):
        self.assertEqual(contract.native_contract([0] * 5), [0] * 5)
        self.assertEqual(contract.native_contract([0, 0, 0, 0, 1 << 48]),
                         [0x1000003d1, 0, 0, 0, 0])
        self.assertEqual(contract.native_contract([contract.MASK52] * 4 + [1 << 48]),
                         [0x1000003d0, 0, 0, 0, 1])

    def test_frozen_fixture_is_reproduced_without_rust(self):
        rows = [str(index) + '\t' + '\t'.join(f'{value:016x}' for value in
                words + contract.native_contract(words))
                for index, words in enumerate(contract.corpus())]
        expected = ('\n'.join(rows) + '\n').encode()
        retained = (PACKET / 'preparation/target-vectors.tsv').read_bytes()
        freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
        self.assertEqual(len(rows), 1331)
        self.assertEqual(expected, retained)
        self.assertEqual(hashlib.sha256(retained).hexdigest(), freeze['vectors_sha256'])
        self.assertEqual(retained, (ROOT / 'src/node94-limb-fold/target-vectors.tsv').read_bytes())
        self.assertIs(freeze['new_rust_exists_at_freeze'], False)

    def test_qualification_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            sentinel = output / 'prior-result'
            sentinel.write_bytes(b'keep prior evidence')
            with self.assertRaisesRegex(ValueError, 'fresh output directory'):
                limb_fold_rust.qualify(Path('not-opened-target'), Path('not-run-compiler'), output)
            self.assertEqual(sentinel.read_bytes(), b'keep prior evidence')

    @unittest.skipUnless(importlib.util.find_spec('z3'), 'optional pinned Z3 proof dependency absent')
    def test_static_proof_and_semantic_controls(self):
        checks = contract.proof()['checks']
        self.assertEqual(checks['full_320_bit_numeric_domain']['result'], 'unsat')
        self.assertEqual(checks['wrong_coefficient_control']['result'], 'sat')
        self.assertEqual(checks['keep_discarded_bit64_control']['result'], 'sat')


if __name__ == '__main__':
    unittest.main()
