"""Pinned diagnostic/call arguments, independent native exports and byte controls."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import aqav2_diagnostic_drift as subject
from elf_index import sections


class Aqav2DiagnosticDriftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec=subject.specification();cls.images={}
        for r,t in cls.spec.items():
            p=subject.TARGETS[r]
            if not p.is_file() or p.stat().st_size != t['size']:
                raise unittest.SkipTest('both materialized pinned captures required')
            d=p.read_bytes()
            if hashlib.sha256(d).hexdigest()!=t['sha256']:raise ValueError('wrong capture')
            cls.images[r]=d
        cls.report=subject.analyze(cls.images)
        cls.sections={r:sections(d) for r,d in cls.images.items()}

    def offset(self,r,va):
        s=next(s for s in self.sections[r] if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,r,va,value=None):
        out=dict(self.images);b=bytearray(out[r]);off=self.offset(r,va)
        b[off]=b[off]^1 if value is None else value;out[r]=b
        return out

    def test_exact_native_regeneration_and_full_fde_denominator(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        owners=[o for t in self.report['targets'].values() for o in t['owners']]
        self.assertEqual((len(owners),sum(o['bytes'] for o in owners),sum(o['instructions'] for o in owners)),(3,29286,5698))
        with tempfile.TemporaryDirectory() as tmp:
            subject.generate(subject.TARGETS,Path(tmp))
            for p in Path(tmp).iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_cardinality_and_selected_immediate_argument_drift(self):
        for r,count,values in [('94',5,[0,0,1,1,2,2,3,3,4,4]),('115',8,[0,0,1,1,2,2,3,3,5,5])]:
            report=self.report['targets'][r]
            self.assertEqual(report['diagnostic_count'],count)
            self.assertEqual(sorted(row['raw_esi'] for row in report['references']),values)
            self.assertEqual(len(report['references']),10)
            self.assertEqual(len({row['callee'] for row in report['references']}),1)

    def test_actual_digit_changes_extracted_cardinality_before_rejection(self):
        prefix=len(b'struct Aqav2TokenInfo with ')
        for r,count in [('94',5),('115',8)]:
            changed=self.mutate(r,self.spec[r]['text_va']+prefix,ord(str(count+1)))
            self.assertEqual(subject.metadata(changed[r],self.spec[r])['diagnostic_count'],count+1)
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_actual_mov_immediate_changes_call_argument_before_rejection(self):
        for r,value,replacement in [('94',4,5),('115',5,4)]:
            for ref in self.report['targets'][r]['references']:
                if ref['raw_esi']!=value:continue
                changed=self.mutate(r,ref['ordinal_site']+1,replacement)
                facts=subject.metadata(changed[r],self.spec[r])
                row=next(row for row in facts['references'] if row['site']==ref['site'])
                self.assertEqual(row['raw_esi'],replacement)
                with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_actual_argument_relocation_and_transfer_controls(self):
        for r,t in self.spec.items():
            ref=self.report['targets'][r]['references'][0]
            for va in [ref['site']+3,ref['site']+10,ref['call_site']+1]:
                with self.assertRaises(ValueError):subject.analyze(self.mutate(r,va))
            for address in t['argument_records']:
                with self.assertRaisesRegex(ValueError,'argument record changed'):subject.analyze(self.mutate(r,int(address)+8))
            sec=next(s for s in self.sections[r] if s['name']=='.rela.dyn')
            d=self.images[r]
            pos=next(p for p in range(sec['offset'],sec['offset']+sec['size'],24) if struct.unpack_from('<Q',d,p)[0]==t['slot'])
            b=bytearray(d);b[pos+16]^=1;images=dict(self.images);images[r]=b
            with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(images)
            for owner in self.report['targets'][r]['owners']:
                va=int(owner['frames']['fde']['va'],16)
                with self.assertRaises(ValueError):subject.analyze(self.mutate(r,va+12))

    def test_both_full_identities_precede_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad=Path(tmp)/'bad';out=Path(tmp)/'out'
            for r,t in self.spec.items():
                site=t['text_va']+len(b'struct Aqav2TokenInfo with ')
                bad.write_bytes(self.mutate(r,site)[r]);paths=dict(subject.TARGETS);paths[r]=bad
                with self.assertRaisesRegex(ValueError,f'pinned node{r}'):subject.generate(paths,out)
                bad.write_bytes(self.images[r][:1024])
                with self.assertRaisesRegex(ValueError,f'pinned node{r}'):subject.generate(paths,out)
            with self.assertRaisesRegex(ValueError,'pinned node94'):
                subject.generate({'94':subject.TARGETS['115'],'115':subject.TARGETS['94']},out)
            self.assertFalse(out.exists())
