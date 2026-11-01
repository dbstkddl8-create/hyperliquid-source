"""Authentic scalar expectations and fail-closed build admission; no target execution."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import wire_qty_rust as subject


class WireQtyRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = subject.oracle()

    def test_frozen_expectations_regenerate_from_authenticated_operands(self):
        expected = self.expected
        self.assertEqual(subject.FIXTURE.read_bytes(), expected['fixture'])
        freeze = json.loads((subject.PACKET/'PRE-RUST-FREEZE.json').read_text())
        self.assertEqual(freeze['fixture_sha256'], expected['fixture_sha256'])
        self.assertFalse(freeze['source_exists'])
        self.assertEqual((freeze['cases'], expected['count']), (2540, 2540))

    def test_all_exit_scales_zero_cap_and_limb_carries_have_witnesses(self):
        rows = [tuple(map(int, line.split())) for line in self.expected['fixture'].splitlines()]
        self.assertEqual({r[2] for r in rows}, set(range(9)))
        selected = {r[0]: r for r in rows}
        self.assertEqual(selected[0], (0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(selected[10**9][1:3], (10, 0))
        for n in [(1 << 32)-1, 1 << 32, (1 << 32)+1, (1 << 63)-1]:
            r = selected[n]
            self.assertEqual((r[6] << 32) | r[5], r[1])
            self.assertEqual(r[1]*10**(8-r[2]), n)

    def test_actual_operand_mutations_change_the_scalar_result(self):
        results = subject.target_controls()
        self.assertEqual(len(results), 2)
        for result in results:
            self.assertNotEqual(result['expected'], result['mutated_relation'])
            self.assertFalse(result['captured_program_executed'])

    def test_wrong_identity_precedes_compiler_or_output_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad = root/'wrong-node'
            bad.write_bytes(b'not the captured node')
            output = root/'unused'
            with mock.patch.object(subject.subprocess, 'check_output', side_effect=AssertionError('compiler invoked')):
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    subject.build(bad, root/'unused-rustc', output)
            self.assertFalse(output.exists())

    def test_existing_evidence_and_modified_fixture_precede_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            keep = root/'marker'
            keep.write_bytes(b'previous evidence')
            with mock.patch.object(subject, 'oracle', side_effect=AssertionError('must not inspect target')):
                with self.assertRaisesRegex(ValueError, 'must be new'):
                    subject.build(root/'unused', root/'unused-rustc', root)
            self.assertEqual(keep.read_bytes(), b'previous evidence')
            fixture = root/'bad-fixture'
            fixture.write_bytes(b'0\t0\t8\t524288\t0\t0\t0\n')
            with mock.patch.object(subject, 'oracle', return_value=self.expected), \
                 mock.patch.object(subject, 'FIXTURE', fixture), \
                 mock.patch.object(subject.subprocess, 'check_output', side_effect=AssertionError('compiler invoked')):
                with self.assertRaisesRegex(ValueError, 'frozen fixture differs'):
                    subject.build(root/'unused', root/'unused-rustc', root/'new')
            self.assertFalse((root/'new').exists())
