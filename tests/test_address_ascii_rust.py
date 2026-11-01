"""Static target-grounded ASCII corpus identity and actual operand controls."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import address_ascii_rust as subject


class AddressAsciiRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected=subject.oracle()

    def test_compact_pre_rust_freeze_binds_full_regenerated_corpus(self):
        freeze=json.loads((subject.PACKET/'PRE-RUST-FREEZE.json').read_text())
        self.assertFalse(freeze['rust_source_exists'])
        self.assertEqual(freeze['input_sha256'],subject.sha(self.expected['inputs']))
        self.assertEqual(freeze['expected_sha256'],subject.sha(self.expected['expected']))
        self.assertEqual((subject.COMPONENT/'target-smoke.tsv').read_bytes(),self.expected['smoke'])
        self.assertEqual((self.expected['count'],self.expected['ascii_cases'],self.expected['distinct_inputs']),
                         (10872,10869,10789))
        self.assertEqual(json.loads((subject.PACKET/'native-records.json').read_text()),self.expected['record'])

    def test_counted_scope_separates_native_ascii_from_own_nonascii_policy(self):
        inputs=subject.stimuli()
        self.assertEqual(sum(not raw.isascii() for raw in inputs),3)
        # The first 10240 are the accepted single-position population, not
        # 10240 distinct target executions or a complete string-space proof.
        self.assertEqual(len(inputs[:10240]),40*128*2)
        self.assertEqual({len(raw) for raw in inputs[:10240]}, {40,42})

    def test_actual_native_operands_change_acceptance_and_payload(self):
        controls=subject.target_controls()
        self.assertEqual(len(controls),3)
        for result in controls:
            self.assertNotEqual(result['before'],result['after'])
            self.assertTrue(result['rejected'])
            self.assertFalse(result['captured_instruction_evaluation'])

    def test_wrong_identity_and_existing_output_precede_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);wrong=root/'wrong';wrong.write_bytes(b'not-node94')
            with mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler ran')):
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    subject.build(wrong,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
            with mock.patch.object(subject,'oracle',side_effect=AssertionError('opened target')):
                with self.assertRaisesRegex(ValueError,'must be new'):
                    subject.build(wrong,root/'compiler',root)

    def test_changed_frozen_expectations_precede_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            freeze=json.loads((subject.PACKET/'PRE-RUST-FREEZE.json').read_text())
            freeze['expected_sha256']='0'*64
            (root/'PRE-RUST-FREEZE.json').write_text(json.dumps(freeze))
            with mock.patch.object(subject,'PACKET',root), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler ran')):
                with self.assertRaisesRegex(ValueError,'corpus identity differs'):
                    subject.build(subject.TARGET,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
