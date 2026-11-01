"""Real node #94 evidence and below-hash corruption controls; static only."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('node94_weak_pidfd', Path(__file__).resolve().parents[1]/'tools/node94_weak_pidfd.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def target_observations(record):
    """Compare target facts while retaining provider receipts in raw evidence."""
    result = copy.deepcopy(record)
    result.pop('versions')
    # This hashes the provider's whole frame dump. Selected actual FDE headers,
    # extents, instruction bytes, bindings and edges are still compared below.
    result['frames'].pop('sha256')
    return result


class WeakPidfdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = m.produce()
        cls.data = m.TARGET.read_bytes()
        cls.secs = m.sections(cls.data)
        cls.ins = {i['va']: i for e in cls.report['extents'] for i in e['instructions']}

    def test_real_target_and_committed_evidence(self):
        self.assertEqual(m.sha(self.data), m.DIGEST)
        retained = json.loads((m.OUT/'evidence.json').read_text())
        self.assertEqual(target_observations(self.report), target_observations(retained))
        self.assertEqual([e['instruction_count'] for e in self.report['extents']], [57, 1998])
        self.assertEqual(len(self.report['edges']), 17)

    def test_provider_projection_keeps_target_identity_and_extent_bytes(self):
        changed = copy.deepcopy(self.report)
        changed['extents'][0]['extent_sha256'] = '0' * 64
        self.assertNotEqual(target_observations(self.report), target_observations(changed))
        changed = copy.deepcopy(self.report)
        changed['target']['sha256'] = '0' * 64
        self.assertNotEqual(target_observations(self.report), target_observations(changed))

    def test_relocations_and_reference_denominator(self):
        m.check_bindings(self.report['relocations'])
        self.assertEqual({r['symbol']['index'] for r in self.report['relocations']}, {173, 182})
        for d in self.report['scan']['denominator']:
            for length, count in d['eligible_positions_by_length'].items():
                self.assertEqual(count, max(0, d['byte_offsets']-int(length)+1))
        self.assertEqual({c['va'] for c in self.report['scan']['candidates']}, m.SITES)

    def test_local_import_paths(self):
        for va, name in [(0x4ee3915, 'ioctl'), (0x4ee3928, '__errno_location'),
                         (0x4ee3955, 'pidfd_getpid'), (0x4ee834d, 'pidfd_spawnp'),
                         (0x4ee83e2, 'posix_spawnp')]:
            self.assertEqual(self.ins[va]['referenced_import'].split('@')[0], name)
        self.assertEqual(self.ins[0x4ee877b]['bytes'], '0f0b')
        self.assertEqual(m.EDGES[0x4ee8328], 0x4ee8753)
        self.assertNotEqual(m.EDGES[0x4ee8328], 0x4ee83af)

    def test_relocation_slot_mutation_below_hash(self):
        r = self.report['relocations'][0]
        data = bytearray(self.data)
        struct.pack_into('<Q', data, r['record_offset'], r['slot_va']+8)
        with self.assertRaisesRegex(ValueError, 'slots differ'):
            m.check_bindings(m.bindings(data, self.secs))

    def test_displacement_mutation_below_hash(self):
        c = self.report['scan']['candidates'][0]
        data = bytearray(self.data)
        data[c['file_offset']+3] ^= 1
        found, _ = m.scan(data, self.secs, self.report['relocations'])
        with self.assertRaisesRegex(ValueError, 'census differs'):
            m.check_observations(data, self.secs, found, self.ins)

    def test_branch_displacement_and_condition_mutations_below_hash(self):
        for delta in (0, 1):
            with self.subTest(byte=delta):
                data = bytearray(self.data)
                data[m.file_offset(self.secs, 0x4ee394d)+delta] ^= 1
                with self.assertRaisesRegex(ValueError, 'edge differs'):
                    m.check_observations(data, self.secs, self.report['scan']['candidates'], self.ins)
        altered = copy.deepcopy(self.ins)
        altered[0x4ee394d]['bytes'] = '7422'
        with self.assertRaisesRegex(ValueError, 'edge differs'):
            m.check_observations(self.data, self.secs, self.report['scan']['candidates'], altered)

    def test_disassembly_corruption_below_hash(self):
        first = self.ins[m.EXTENTS[0][0]]
        text = f" {first['va']:x}:\t54\tpush rsp\n"
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            m.decode(text, self.data, self.secs, *m.EXTENTS[0])

    def test_last_eligible_positions_and_truncation(self):
        # Supplementary encoder boundary controls, not substitutes for target evidence.
        va, slot = 0x1000, 0x2000
        for prefix, length in [(b'\xff\x15', 6), (b'\x48\x8b\x05', 7), (b'\x48\x83\x3d', 8)]:
            raw = prefix+struct.pack('<i', slot-va-length)+(b'\0' if length == 8 else b'')
            secs = [dict(type=1, flags=4, name='.text', va=va, offset=0, size=len(raw))]
            found = [dict(slot_va=slot, symbol=dict(name='pidfd_getpid'))]
            hits, _ = m.scan(raw, secs, found)
            self.assertEqual(len(hits), 1)
            secs[0]['size'] -= 1
            hits, _ = m.scan(raw[:-1], secs, found)
            self.assertEqual(hits, [])


if __name__ == '__main__':
    unittest.main()
