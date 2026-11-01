"""Cross-capture local rounding proof, resolved dispatch and actual operand controls."""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import ema_fused_release_drift as subject
from elf_index import sections


class EMAFusedReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec=subject.specification();cls.images={}
        for r,t in cls.spec['targets'].items():
            if not subject.TARGETS[r].is_file() or subject.TARGETS[r].stat().st_size!=t['size']:
                raise unittest.SkipTest('materialized node94 and115 required')
            d=subject.TARGETS[r].read_bytes()
            if hashlib.sha256(d).hexdigest()!=t['sha256']:raise ValueError('wrong capture')
            cls.images[r]=d
        cls.secs={r:sections(d) for r,d in cls.images.items()}
        cls.report=subject.analyze(cls.images);cls.params=subject.parameters(cls.images['94'],cls.images['115'])

    def offset(self,r,va):
        s=next(s for s in self.secs[r] if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def mutate(self,r,va,value=None):
        images=dict(self.images);b=bytearray(images[r]);o=self.offset(r,va);b[o]=b[o]^1 if value is None else value
        images[r]=b;return images

    def test_native_regeneration_and_six_complete_bodies(self):
        self.assertEqual(self.report,json.loads((subject.PACKET/'records.json').read_text()))
        owners=[o for t in self.report['targets'].values() for o in t['owners']]
        self.assertEqual((len(owners),sum(o['bytes'] for o in owners),sum(o['instructions'] for o in owners)),(6,1350,316))
        with tempfile.TemporaryDirectory() as directory:
            out=Path(directory);subject.generate(subject.TARGETS,out)
            for p in out.iterdir():self.assertEqual(p.read_bytes(),(subject.PACKET/p.name).read_bytes(),p.name)

    def test_positive_exact_rational_one_ulp_witness_and_exact_control(self):
        # 10*binary64(0.1)=1+2^-54 exactly; adding2^-53 gives1+3*2^-54.
        self.assertEqual(Fraction(10.)*Fraction(.1),1+Fraction(1,1<<54))
        self.assertEqual(Fraction(10.)*Fraction(.1)+Fraction(2.**-53),1+Fraction(3,1<<54))
        r=subject.accumulation(self.params,10.,.1,2.**-53,1.,1.)
        self.assertEqual(r['old_num'],1.)
        self.assertEqual(r['hardware3_num'],math.nextafter(1.,math.inf))
        self.assertEqual(r['hardware3_num']-r['old_num'],math.ulp(1.))
        self.assertEqual(r['old_den'],r['new_den'])
        r=subject.accumulation(self.params,3.,2.,4.,5.,.5)
        self.assertEqual((r['old_num'],r['hardware3_num'],r['old_den'],r['new_den']),(8.,8.,4.5,4.5))
        with self.assertRaises(ValueError):subject.accumulation(self.params,math.inf,1.,1.,1.,1.)

    def test_actual_old_opcode_fused_order_field_and_mask_counterfactuals(self):
        inputs=(10.,.1,2.**-53,1.,1.)
        baseline=subject.accumulation(self.params,*inputs)
        for r,va,value,key in [('94',0x14792a1,0x58,'old_num'),('115',0x63f0683,0x99,'hardware3_num'),
                               ('115',0x5a7281f,0,'new_den')]:
            changed=self.mutate(r,va,value);p=subject.parameters(changed['94'],changed['115'])
            self.assertNotEqual(subject.accumulation(p,*inputs)[key],baseline[key])
            with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)
        changed=self.mutate('115',0x63f06bf,0x20);p=subject.parameters(changed['94'],changed['115'])
        word=(1<<31)|0x40
        self.assertEqual(subject.selected_target(self.params,word),'hardware3')
        self.assertEqual(subject.selected_target(p,word),'unclosed-fallback')
        with self.assertRaisesRegex(ValueError,'relation changed'):subject.analyze(changed)

    def test_resolved_mask_classes_and_actual_dataflow_controls(self):
        for b6 in [0,1]:
            for b7 in [0,1]:
                word=(1<<31)|(b6<<6)|(b7<<7)
                expected='hardware3' if b6 else 'hardware4' if b7 else 'unclosed-fallback'
                self.assertEqual(subject.selected_target(self.params,word),expected)
                self.assertEqual(subject.selected_target(self.params,word^(1<<31)),'unclosed-initializer')
        for r,va in [('94',0x14792b5),('94',0x14792a7),('115',0x5a72828),('115',0x5a7282e),
                      ('115',0x5a72838),('115',0x63f0695),('115',0x63f06a9),('115',0x63f06bc),
                      ('115',0x63f06cd),('115',0x63f06dd),('115',0x63f0702)]:
            with self.assertRaisesRegex(ValueError,'dataflow changed|RIP binding changed'):subject.analyze(self.mutate(r,va))
        for r,t in self.spec['targets'].items():
            for o in t['owners']:
                for site in o['direct_calls']:
                    with self.assertRaisesRegex(ValueError,'direct call changed'):subject.analyze(self.mutate(r,int(site)+1))
                site,row=next(iter(o['rip_bindings'].items())) if o['rip_bindings'] else (None,None)
                if site:
                    with self.assertRaisesRegex(ValueError,'RIP binding changed'):subject.analyze(self.mutate(r,int(site)+len(bytes.fromhex(row['prefix']))))

    def test_actual_relocations_source_locations_and_fde_extents(self):
        for r,t in self.spec['targets'].items():
            d=self.images[r];s=next(s for s in self.secs[r] if s['name']=='.rela.dyn')
            offsets={struct.unpack_from('<Q',d,p)[0]:p for p in range(s['offset'],s['offset']+s['size'],24)}
            for slot in t['relocations']:
                images=dict(self.images);changed=bytearray(d);changed[offsets[int(slot)]+16]^=1;images[r]=changed
                with self.assertRaisesRegex(ValueError,'relocation changed'):subject.analyze(images)
            for slot,loc in t['source_locations'].items():
                for va in [loc['path_va'],int(slot)+16]:
                    with self.assertRaisesRegex(ValueError,'Location changed'):subject.analyze(self.mutate(r,va))
            for o in self.report['targets'][r]['owners']:
                fde=int(o['frames']['fde']['va'],16)
                with self.assertRaisesRegex(ValueError,'FDE changed'):subject.analyze(self.mutate(r,fde+12))

    def test_both_public_capture_identities_precede_output(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad';out=Path(directory)/'out'
            for r,site in [('94',0x14792a1),('115',0x63f0683)]:
                p.write_bytes(self.mutate(r,site)[r]);binaries=dict(subject.TARGETS);binaries[r]=p
                with self.assertRaisesRegex(ValueError,f'pinned node{r}'):subject.generate(binaries,out)
                p.write_bytes(self.images[r][:4096])
                with self.assertRaisesRegex(ValueError,f'pinned node{r}'):subject.generate(binaries,out)
            swapped={'94':subject.TARGETS['115'],'115':subject.TARGETS['94']}
            with self.assertRaisesRegex(ValueError,'pinned node94'):subject.generate(swapped,out)
            self.assertFalse(out.exists())
