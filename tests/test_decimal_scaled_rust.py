"""Admit replayed native fixtures and preserve evaluator/production boundaries."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import decimal_scaled_rust as subject


class DecimalScaledRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = subject.oracle()

    def test_replay_freeze_and_all_fixtures_are_authenticated(self):
        self.assertEqual(self.expected['count'],25325)
        replay = json.loads((subject.PACKET/'PRE-RUST-REPLAY.json').read_text())
        self.assertFalse(replay['new_Rust_module_exists'])
        self.assertTrue(replay['offline_python_instruction_evaluation_authorized'])
        self.assertTrue(all(row['matches_accepted_packet'] for row in replay['files']))
        self.assertEqual(len(self.expected['inputs'].splitlines()),25325)
        self.assertEqual(len(self.expected['expected'].splitlines()),25325)

    def test_expected_policy_edges_are_from_replayed_native_rows(self):
        pairs = zip(self.expected['inputs'].decode().splitlines(),self.expected['expected'].decode().splitlines())
        found = {}
        for inputs,expected in pairs:
            fields = tuple(map(int,inputs.split()[1:]))
            found[fields] = expected.split('\t')[1:]
        self.assertEqual(found[(0,25,1,2,0)],['ok','2','0'])
        self.assertEqual(found[(0,35,1,2,0)],['ok','4','0'])
        self.assertEqual(found[(0,1,0,0,20)],['error','-','0'])
        self.assertEqual(found[(0,10005000000,10,1,0)],['ok','1','1'])
        self.assertEqual(found[(0,subject.native.CAP,0,0,0)],['ok',str(subject.native.CAP),'0'])
        self.assertEqual(found[(0,subject.native.CAP+1,0,0,0)],['error','-','0'])

    def test_actual_native_controls_use_authorized_python_not_native_execution(self):
        controls = subject.target_controls()
        self.assertEqual(len(controls),3)
        for row in controls:
            self.assertNotEqual(row['before'],row['after'])
            self.assertTrue(row['authorized_offline_Python_instruction_evaluation'])
            self.assertFalse(row['native_capture_launched'])

    def test_wrong_identity_and_existing_output_precede_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrong = root/'wrong'
            wrong.write_bytes(b'not the captured node')
            with mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler ran')):
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    subject.build(wrong,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
            with mock.patch.object(subject,'oracle',side_effect=AssertionError('opened target')):
                with self.assertRaisesRegex(ValueError,'must be new'):
                    subject.build(wrong,root/'compiler',root)

    def test_modified_fixture_rejected_before_compiler_or_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'evidence.json').write_bytes(b'corrupt expected metadata')
            with mock.patch.object(subject,'OLD',root), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler ran')):
                with self.assertRaisesRegex(ValueError,'accepted evidence.json changed'):
                    subject.build(subject.native.TARGET,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
