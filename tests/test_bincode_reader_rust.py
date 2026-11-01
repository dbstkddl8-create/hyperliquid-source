"""Target-derived Reader/cursor fixtures and admission, without captured execution."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import bincode_reader_rust as subject


class BincodeReaderRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = subject.oracle()

    def test_frozen_input_and_expected_files_regenerate(self):
        self.assertEqual(subject.FIXTURE.read_bytes(), self.expected['fixture'])
        self.assertEqual((subject.PACKET/'target-inputs.tsv').read_bytes(), self.expected['inputs'])
        self.assertEqual(json.loads((subject.PACKET/'native-records.json').read_text()),
                         json.loads(json.dumps(self.expected['record'])))
        freeze = json.loads((subject.PACKET/'PRE-RUST-FREEZE.json').read_text())
        self.assertFalse(freeze['reader_rust_api_exists'])
        self.assertEqual(freeze['fixture_sha256'], subject.sha(self.expected['fixture']))
        self.assertEqual(self.expected['count'], 3276)

    def test_every_initial_tag_both_widths_and_orders_and_payload_lengths(self):
        cases = subject.stimuli()
        for width in (32,64):
            for big in (0,1):
                subset = [raw for w,b,raw in cases if (w,b)==(width,big)]
                self.assertEqual({raw[0] for raw in subset if raw}, set(range(256)))
                self.assertIn(b'', subset)
                for tag in range(251,256):
                    self.assertTrue(set(range(1,11)) <= {len(raw) for raw in subset if raw and raw[0]==tag})

    def test_short_input_and_error_cursor_relations_are_not_transactional(self):
        p = subject.parameters(subject.bv.TARGET.read_bytes())
        self.assertEqual(subject.relation(32,0,b'\xfb\x34',p), 'end\t1\t1\t34')
        self.assertEqual(subject.relation(64,0,b'\xfd\x34',p), 'end\t7\t1\t34')
        self.assertEqual(subject.relation(32,0,b'\xfd\x34',p), 'type\t2:3\t1\t34')
        self.assertEqual(subject.relation(64,0,b'\xfe',p), 'type\t3:4\t1\t-')
        self.assertEqual(subject.relation(64,0,b'',p), 'end\t1\t0\t-')
        self.assertEqual(subject.relation(32,0,b'\xfb\x34\x12',p), 'ok\t4660\t3\t-')
        self.assertEqual(subject.relation(32,1,b'\xfb\x34\x12',p), 'ok\t13330\t3\t-')

    def test_actual_operand_and_opcode_controls_change_observable_values(self):
        controls = subject.target_controls()
        self.assertEqual(len(controls),3)
        for result in controls:
            self.assertNotEqual(result['before'],result['after'])
            self.assertTrue(result['rejected'])

    def test_bad_identity_existing_output_and_changed_fixture_precede_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wrong = root/'wrong'
            wrong.write_bytes(b'not-node94')
            with mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler invoked')):
                with self.assertRaisesRegex(ValueError,'identity mismatch'):
                    subject.build(wrong,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
            with mock.patch.object(subject,'oracle',side_effect=AssertionError('target opened')):
                with self.assertRaisesRegex(ValueError,'must be new'):
                    subject.build(wrong,root/'compiler',root)
            changed = root/'changed-fixture'
            changed.write_bytes(b'bad expected answers')
            with mock.patch.object(subject,'oracle',return_value=self.expected), \
                 mock.patch.object(subject,'FIXTURE',changed), \
                 mock.patch.object(subject.subprocess,'check_output',side_effect=AssertionError('compiler invoked')):
                with self.assertRaisesRegex(ValueError,'frozen fixture differs'):
                    subject.build(wrong,root/'compiler',root/'new')
            self.assertFalse((root/'new').exists())
