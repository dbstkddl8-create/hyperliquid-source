"""Static CFG/operand controls and integer identities; no instruction execution."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import cache_publication_static as subject
from elf_index import sections


class CachePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec=subject.specification()
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size!=cls.spec['target_size']:
            raise unittest.SkipTest('materialized pinned node115 required')
        cls.data=subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest()!=cls.spec['target_sha256']:raise ValueError('wrong capture')
        cls.secs=sections(cls.data);cls.rows,_=subject.native_rows(cls.data)
        cls.report=subject.analyze(cls.data,cls.rows);cls.params=subject.parameters(cls.data)

    def offset(self,va):
        s=next(s for s in self.secs if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,va,value=None):
        b=bytearray(self.data);o=self.offset(va);b[o]=b[o]^1 if value is None else value
        return b

    def test_full_native_packet_and_static_cfg_certificate(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        o=self.report['owner'];self.assertEqual((o['end']-o['start'],o['instructions']),(1674,454))
        c=self.report['cfg'];self.assertEqual(c['structurally_reachable_rows'],454)
        self.assertTrue(c['publication_dominates_returns']);self.assertEqual(len(c['at_publication']),3)
        self.assertEqual(len(c['at_returns']),1)
        with tempfile.TemporaryDirectory() as tmp:
            subject.generate(subject.TARGET,Path(tmp))
            for p in Path(tmp).iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_130_integer_basis_and_edge_pairs_roundtrip(self):
        pairs=[(0,0),(subject.U64,subject.U64)]
        pairs += [(1<<i,0) for i in range(64)]+[(0,1<<i) for i in range(64)]
        self.assertEqual(len(set(pairs)),130)
        for a,b in pairs:
            result=subject.store_equations(a,b,self.params);words=result['final_words']
            self.assertEqual(subject.unpack(words),(a,b))
            self.assertEqual(result['raw_return'],a)
            self.assertTrue(all(v&subject.H for v in words.values()))
            for bit in [10,15,19,25]:self.assertEqual((words[0]>>bit)&1,(a>>bit)&1)
        zero=subject.store_equations(0,0,self.params)
        self.assertEqual(zero['raw_return'],0)
        self.assertEqual(zero['final_words'],{0:subject.H,8:subject.H,16:subject.H})
        for words in [{0:0,8:subject.H,16:subject.H},{0:subject.H,8:subject.H,16:subject.H|4}]:
            with self.assertRaises(ValueError):subject.unpack(words)

    def test_actual_shift_and_offset_operands_change_store_equations(self):
        cases=[(0x5cae3b2,2,1<<62,0),(0x5cae3c0,61,0,1<<61),(0x5cae3b9,0,7,3)]
        for site,value,a,b in cases:
            changed=self.mutate(site,value);params=subject.parameters(changed)
            self.assertNotEqual(subject.store_equations(a,b,params),subject.store_equations(a,b,self.params))
            with self.assertRaisesRegex(ValueError,'equation changed'):subject.analyze(changed,self.rows)

    def test_actual_marker_constants_change_the_reaching_definition_certificate(self):
        baseline=self.report['cfg']['at_publication']
        for site in self.spec['sentinel_sites']:
            changed=self.mutate(site+9,0x40)
            rows,_=subject.native_rows(changed);cert=subject.cfg_certificate(rows)
            self.assertNotEqual(cert['at_publication'],baseline)
            self.assertIn(hex(1<<62),cert['constant_definitions'].values())
            words=subject.store_equations(0,0,self.params,marker=1<<62)['final_words']
            self.assertFalse(words[0]&subject.H)
            with self.assertRaisesRegex(ValueError,'marker reaching-definition'):subject.analyze(changed,rows)

    def test_real_branch_to_epilogue_breaks_publication_dominance(self):
        b=bytearray(self.data);site=0x5caddf5;target=0x5cae3c8
        struct.pack_into('<i',b,self.offset(site)+1,target-(site+5))
        rows,_=subject.native_rows(b);cert=subject.cfg_certificate(rows)
        self.assertFalse(cert['publication_dominates_returns'])
        with self.assertRaisesRegex(ValueError,'marker reaching-definition'):subject.analyze(b,rows)
        b=self.mutate(0x5cadd7d,0x76)
        rows,_=subject.native_rows(b)
        with self.assertRaisesRegex(ValueError,'operand'):subject.cfg_certificate(rows)

    def test_relocation_writable_extent_fde_and_call_controls(self):
        s=next(s for s in self.secs if s['name']=='.rela.dyn')
        p=next(p for p in range(s['offset'],s['offset']+s['size'],24) if struct.unpack_from('<Q',self.data,p)[0]==0x64dfa60)
        b=bytearray(self.data);b[p+16]^=8
        with self.assertRaisesRegex(ValueError,'relocation binding'):subject.analyze(b,self.rows)
        shoff=struct.unpack_from('<Q',self.data,40)[0];width=struct.unpack_from('<H',self.data,58)[0]
        b=bytearray(self.data);b[shoff+self.secs.index(self.spec['cache_region'])*width+8]^=1
        with self.assertRaisesRegex(ValueError,'write region'):subject.analyze(b,self.rows)
        fde=int(self.report['frames']['fde']['va'],16)
        with self.assertRaises(ValueError):subject.analyze(self.mutate(fde+12),self.rows)
        b=self.mutate(0x5cae04d)
        rows,_=subject.native_rows(b)
        with self.assertRaisesRegex(ValueError,'call binding'):subject.analyze(b,rows)

    def test_complete_identity_precedes_output_and_native_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad=Path(tmp)/'bad';out=Path(tmp)/'out'
            bad.write_bytes(self.mutate(0x5cae3b2,2))
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(bad,out)
            bad.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError,'pinned node115'):subject.generate(bad,out)
            with self.assertRaisesRegex(ValueError,'pinned node115'):
                subject.generate(subject.ROOT/'artifacts/node/94/hl-node',out)
            self.assertFalse(out.exists())
