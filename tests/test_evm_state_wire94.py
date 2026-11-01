import hashlib
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from unittest import mock

import evm_state_wire94 as m
from tools.elf_index import sections


class EvmStateWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.secs = sections(cls.data)
        cls.result = m.analyze(cls.data)

    def mutate(self, va):
        row = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        data = bytearray(self.data)
        data[row['offset'] + va - row['address']] ^= 1
        return data

    def test_identity_and_extents(self):
        self.assertEqual(len(self.result['functions']), 17)
        self.assertEqual(len(self.result['windows']), 31)
        self.assertEqual(len(self.result['calls']), 25)
        self.assertEqual(len(self.result['branches']), 38)
        self.assertEqual(self.result['target_sha256'], m.DIGEST)

    def test_identity_rejected(self):
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            m.checked_digest(b'not the target')

    def test_rehashed_mutated_body_rejected(self):
        bad = self.mutate(0x2206b2c)
        with mock.patch.object(m, 'DIGEST', hashlib.sha256(bad).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'code body changed'):
                m.analyze(bad)

    def test_rehashed_mutated_literal_rejected(self):
        bad = self.mutate(0x3dfee1)
        with mock.patch.object(m, 'DIGEST', hashlib.sha256(bad).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'literal and comparison disagree'):
                m.analyze(bad)

    def test_call_edges(self):
        edges = {x['site']: x['target'] for x in self.result['calls']}
        self.assertEqual(edges['0x2206b2c'], '0x1e5a190')
        self.assertEqual(edges['0x185544d'], '0x16891f0')
        self.assertEqual(edges['0x18cee7c'], '0x22e4cb0')
        with self.assertRaises(ValueError):
            m.call_target(self.mutate(0x2206b2c), self.secs, 0x2206b2c)

    def test_branch_targets_and_corruption(self):
        self.assertEqual(m.branch_target(self.data, self.secs, 0x1855441), 0x1855509)
        self.assertEqual(m.branch_target(self.data, self.secs, 0x185545e), 0x185557d)
        self.assertEqual(m.branch_target(self.data, self.secs, 0x1856147), 0x1856428)
        self.assertEqual(m.branch_target(self.data, self.secs, 0x18560b6), 0x1856469)
        with self.assertRaises(ValueError):
            m.branch_target(self.mutate(0x185545e), self.secs, 0x185545e)

    def test_key_comparisons(self):
        self.assertEqual(m.read_name_compare(self.data,self.secs,0x1855cd6,6),b'evm_db')
        self.assertEqual(m.read_name_compare(self.data,self.secs,0x1855d47,12),b'block_hashes')
        self.assertNotEqual(m.read_name_compare(self.mutate(0x1855cd9),self.secs,0x1855cd6,6),b'evm_db')
        with self.assertRaises(ValueError):
            m.read_name_compare(self.mutate(0x1855cd6),self.secs,0x1855cd6,6)

    def test_variant_comparison_and_mutation(self):
        self.assertEqual(m.variant_name(self.data,self.secs), b'NoEvmDb')
        with self.assertRaises(ValueError):
            m.variant_name(self.mutate(0x22e4d9a),self.secs)
        with self.assertRaises(ValueError):
            m.variant_name(self.mutate(0x22e4d90),self.secs)

    def test_variant_all_single_byte_changes(self):
        value = b'NoEvmDb'
        self.assertTrue(m.classify_variant(self.data, self.secs, value))
        for i in range(len(value)):
            for byte in range(256):
                if byte != value[i]:
                    changed = value[:i] + bytes([byte]) + value[i+1:]
                    self.assertFalse(m.classify_variant(self.data, self.secs, changed))
        for changed in (b'',value[:-1],value+b'\0',b'noEvmDb'):
            self.assertFalse(m.classify_variant(self.data,self.secs,changed))

    def test_all_field_single_byte_changes(self):
        field_names = [m.read_name_compare(self.data,self.secs,0x1855cd6,6),
                       m.read_name_compare(self.data,self.secs,0x1855d47,12)]
        for name in field_names:
            for i in range(len(name)):
                changed = name[:i] + bytes([name[i] ^ 1]) + name[i+1:]
                self.assertNotIn(changed, field_names)
        self.assertNotIn(b'evm_db\0',field_names)
        self.assertNotIn(b'block_hash',field_names)

    def test_mode_examples(self):
        self.assertEqual(self.result['examples']['named_empty_hashes'],
                         '82a665766d5f646281a74e6f45766d446280ac626c6f636b5f68617368657390')
        self.assertEqual(self.result['examples']['positional_empty_hashes'],
                         '9281a74e6f45766d44629090')
        self.assertNotEqual(self.result['examples']['named_empty_hashes'],
                            self.result['examples']['positional_empty_hashes'])

    def test_file_backing_and_bounds(self):
        with self.assertRaises(ValueError):
            m.va_bytes(self.data,self.secs,0xffffffffffffffff,1)
        with self.assertRaises(ValueError):
            m.va_bytes(self.data,self.secs,0,-1)
        bss = next(s for s in self.secs if s['type'] == 8 and s['name'] == '.bss')
        with self.assertRaises(ValueError):
            m.va_bytes(self.data,self.secs,bss['address'],1)

if __name__ == '__main__':
    unittest.main()
