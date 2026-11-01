"""Target and adversarial controls for the exact-file packet; stdlib only (MIT)."""
import copy
import importlib.util
import json
import mmap
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import gossip_rpc_client_inventory as g

PACKET = g.ROOT/'research/work-items/gossip-rpc-client-inventory-94'
spec = importlib.util.spec_from_file_location('client_verify', PACKET/'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class SmallImage:
    def __init__(self, data, base=0x1000):
        self.data, self.base = data, base

    def read(self, va, size):
        offset = va-self.base
        g.n.require(size > 0 and 0 <= offset and offset+size <= len(self.data), 'read outside synthetic image')
        return self.data[offset:offset+size]

    def evidence(self, va, size):
        return {'va': hex(va), 'file_offset': hex(va-self.base), 'section': 'synthetic', 'bytes': self.read(va,size).hex()}


class DecoderTests(unittest.TestCase):
    def test_lea_signed_displacement_and_all_registers(self):
        for reg in range(16):
            for disp in (-2147483648, -7, 0, 2147483647):
                raw = bytes((0x4c if reg >= 8 else 0x48, 0x8d, 5+8*(reg%8)))+struct.pack('<i',disp)
                self.assertEqual(g.n.decode_lea(raw, 0x100000000),(0x100000007+disp,reg))

    def test_shifted_or_malformed_lea_rejected(self):
        for raw in (bytes.fromhex('8d0500000000'),bytes.fromhex('488d0400000000'),
                    bytes.fromhex('488d05000000'),bytes.fromhex('408d0500000000'),bytes.fromhex('488d050000000000')):
            with self.subTest(raw=raw.hex()), self.assertRaises(g.n.EvidenceError):
                g.n.decode_lea(raw,0x1000)

    def test_instruction_boundary_rejects_embedded_lea(self):
        im = SmallImage(bytes.fromhex('48b8488d050000000090c3'))
        insns = g.n.decode_fde(im, {'start':0x1000,'end':0x100b})
        with self.assertRaises(g.n.EvidenceError):
            g.n.verified_lea(im,insns,0x1002,0x1009)

    def test_rel32_and_opcode_controls(self):
        for opcode in (0xe8,0xe9):
            for disp in (-2147483648,-5,0,2147483647):
                self.assertEqual(g.n.decode_rel32_transfer(bytes([opcode])+struct.pack('<i',disp),0x100000000),0x100000005+disp)
        for raw in (b'\xe8\0',b'\xeb\0\0\0\0',b'\xff\0\0\0\0'):
            with self.assertRaises(g.n.EvidenceError): g.n.decode_rel32_transfer(raw,0)

    def test_immediate_and_length_store_controls(self):
        self.assertEqual(g.n.decode_mov_immediate(bytes.fromhex('41b812000000'))['value'],18)
        self.assertEqual(g.n.decode_mov_immediate(bytes.fromhex('48c744245812000000'))['value'],18)
        for raw in ('c744245812000000','48c74c245812000000','48c7050000000012000000','48c744645812000000'):
            with self.subTest(raw=raw), self.assertRaises(g.n.EvidenceError): g.n.decode_mov_immediate(bytes.fromhex(raw))

    def test_branch_inside_operand_rejected(self):
        im = SmallImage(bytes.fromhex('eb0148b80000000000000000c3'))
        with self.assertRaises(g.n.EvidenceError): g.n.decode_fde(im,{'start':0x1000,'end':0x100d})

    def test_truncated_instruction_rejected(self):
        for text in ('488d0d69d215fe','48c78424d00000001c000000','e8e932fcff'):
            raw=bytes.fromhex(text)
            for end in range(len(raw)):
                with self.subTest(text=text,end=end), self.assertRaises(g.n.EvidenceError): g.n.decode_instruction(raw[:end])


class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (g.ROOT/g.TARGET).open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            cls.result = g.build(data)

    def test_exact_regeneration_and_report_counts(self):
        v.verify_outputs(PACKET,g,self.result)
        v.verify_manifest(PACKET)

    def test_document_metric_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            for name in ('README.md','RESULT.md'): (p/name).write_bytes((PACKET/name).read_bytes())
            text=(p/'RESULT.md').read_text().replace('| locations | 15 |','| locations | 16 |')
            self.assertIn('| locations | 16 |',text)
            (p/'RESULT.md').write_text(text)
            with self.assertRaisesRegex(ValueError,'report facts differ'): v.verify_docs(p,self.result['inventory.json'])

    def test_whitelist_and_manifest_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            for name in v.MANIFEST | {'MANIFEST.sha256'}: (p/name).write_bytes((PACKET/name).read_bytes())
            (p/'extra').write_text('extra')
            with self.assertRaisesRegex(ValueError,'whitelist'): v.verify_manifest(p)
            (p/'extra').unlink()
            (p/'inventory.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'manifest mismatch'): v.verify_manifest(p)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'): g.build(b'wrong binary')

    def test_missing_section_rejected(self):
        with (g.ROOT/g.TARGET).open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            original=g.n.sections
            with mock.patch.object(g.n,'sections',side_effect=lambda x:[s for s in original(x) if s['name'] != '.rela.dyn']):
                with self.assertRaisesRegex(ValueError,'missing section'): g.n.Image(data)

    def test_mutated_location_rejected(self):
        loc=self.result['inventory.json']['locations'][0]
        with (g.ROOT/g.TARGET).open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY) as data:
            off=int(loc['file_offset'],16)+16
            data[off:off+4]=struct.pack('<I',loc['line']+1)
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'): g.build(data)
            with mock.patch.object(g.n,'authenticate'):
                with self.assertRaisesRegex(ValueError,'Location census differs'): v.verify_facts(g.build(data)['inventory.json'])

    def test_shifted_location_lea_rejected_after_auth_bypass(self):
        lea=self.result['inventory.json']['location_leas'][0]['instruction']
        with (g.ROOT/g.TARGET).open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY) as data:
            off=int(lea['file_offset'],16)
            data[off+3] ^= 1
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'): g.build(data)
            with mock.patch.object(g.n,'authenticate'):
                with self.assertRaises(ValueError): v.verify_facts(g.build(data)['inventory.json'])

    def test_pointer_length_and_call_corruptions_rejected(self):
        ev=self.result['inventory.json']
        anchor=next(a for d in ev['diagnostics'] for a in d['anchors'] if a['kind']=='adjacent_pointer_length_fields')
        length=anchor['setup'][2]
        edge=ev['call_edges'][0]['instruction']
        for record,delta in ((length,-1),(edge,1)):
            with self.subTest(va=record['va']), (g.ROOT/g.TARGET).open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY) as data:
                off=int(record['file_offset'],16)
                index=off+len(bytes.fromhex(record['bytes']))+delta if delta < 0 else off+delta
                data[index] ^= 1
                with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'): g.build(data)
                with mock.patch.object(g.n,'authenticate'):
                    try: changed=g.build(data)
                    except ValueError: continue
                    with self.assertRaises(ValueError): v.verify_outputs(PACKET,g,changed)

    def test_pinned_counts_and_relocation_bytes(self):
        ev=self.result['inventory.json']
        v.verify_facts(ev)
        self.assertTrue(all(x['relocation']['type']=='R_X86_64_RELATIVE' and len(x['relocation']['bytes'])==48 for x in ev['locations']))
        changed=copy.deepcopy(ev)
        changed['metrics']['location_leas'] += 1
        with self.assertRaisesRegex(ValueError,'pinned metrics'): v.verify_facts(changed)

if __name__ == '__main__':
    unittest.main()
