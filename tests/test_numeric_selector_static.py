"""Actual-byte controls and integer proofs; never execute captured instructions."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import numeric_selector_static as n


class NumericSelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=n.TARGET.read_bytes()
        if len(cls.data)!=n.SIZE or hashlib.sha256(cls.data).hexdigest()!=n.SHA:raise ValueError('materialized pinned node115 required')
        cls.spec=n.specification();cls.params=n.parameters(cls.data);cls.report,_=n.analyze(cls.data)
        cls.table=bytes.fromhex(cls.spec['decimal_pair_table']['bytes_hex']);cls.sections,_=n.reader(cls.data)

    def offset(self,va):
        s=next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        return s['offset']+va-s['address']

    def edit(self,name,value,data=None):
        result=bytearray(self.data if data is None else data);va,fmt=n.FIELDS[name]
        struct.pack_into('<'+fmt,result,self.offset(va),value);return result

    def test_full_four_fdes_native_regeneration_and_imports(self):
        self.assertEqual(self.report,json.loads((n.PACKET/'records.json').read_text()))
        self.assertEqual(sum(f['end']-f['start'] for f in self.report['functions']),3411)
        self.assertEqual(sum(f['instructions'] for f in self.report['functions']),741)
        self.assertEqual(self.report['relocations'][str(0x64df9f8)]['symbol'],'bcmp')
        self.assertEqual(self.report['relocations'][str(0x64df508)]['symbol'],'memcpy')
        with tempfile.TemporaryDirectory() as tmp:
            n.generate(n.TARGET,Path(tmp))
            self.assertEqual((Path(tmp)/'records.json').read_bytes(),(n.PACKET/'records.json').read_bytes())
            # Native text is retained unnormalized, but its presentation is not
            # claimed byte-identical across different GNU binutils versions.
            for owner in self.spec['functions']:
                text=(Path(tmp)/f"{owner['start']:x}.objdump.txt").read_text()
                self.assertIn('<authenticated-node115>',text)

    def test_all_domain_division_certificates_and_independent_decimal_boundaries(self):
        certificates=n.division_certificates(self.params)
        self.assertEqual([c['excess'] for c in certificates],[2,432,12,3])
        values={0,1,9,10,99,100,999,1000,9999,10000,n.U64,n.U64-100000000}
        for e in range(1,20):values.update([10**e-1,10**e,10**e+1])
        x=0x13579bdf2468ace0
        for _ in range(1000):x=(x*6364136223846793005+1442695040888963407)&n.U64;values.add(x)
        for v in values:
            self.assertEqual(n.render_integer(v,self.params,self.table),str(v).encode(),v)
            self.assertEqual((v*self.params['lookup_multiplier'])>>67,v//10)
            self.assertEqual((v*self.params['format_multiplier'])>>75,v//10000)
        for v in range(10000):self.assertEqual((v*5243)>>19,v//100)
        for v in range(1000):self.assertEqual((((v>>2)*5243)>>17),v//100)

    def test_numeric_and_copied_string_states_are_not_assigned_error_types(self):
        expected={b'PURR/USDC':0,b'@1':1,b'@99999999':99999999,b'#0':100000000,b'#1':100000001,b'#18446744073709551615':n.U64}
        for text,value in expected.items():self.assertEqual(n.numeric_projection(text,self.params,self.table),{'tag':0x1a2,'value':value})
        for text in [b'',b'@0',b'@100000000',b'#',b'@',b'#01',b'#+1',b'#-1',b'#18446744073709551616',b'purr/usdc',b'PURR/USDC\0',b'#\xff',b'#'+b'0'*5000]:
            self.assertEqual(n.numeric_projection(text,self.params,self.table),{'tag':0x68,'copied_bytes_hex':text.hex()})

    def test_namespace_residues_and_saturating_tail_reach_only_the_selected_zero_branch(self):
        base=100000000;maximum=(n.U64-base)//10
        for q in [0,1,2,11,1000000,maximum-1,maximum]:
            for r in range(10):
                value=base+10*q+r
                if value>n.U64:continue
                fact=n.lookup_projection(value,self.params)
                self.assertEqual((fact['quotient'],fact['remainder']),(q,r))
                if r in [0,1]:self.assertEqual((fact['path'],fact['selector_offset']),('context-dependent-table',32*r))
                else:self.assertEqual((fact['path'],fact['rax'],fact['rdx']),('fast-zero',0,r))
        for v in [n.U64-base,n.U64-base+1,n.U64]:
            projected=n.numeric_projection(b'#'+str(v).encode(),self.params,self.table)
            self.assertEqual(projected,{'tag':0x1a2,'value':n.U64})
            self.assertEqual(n.lookup_projection(projected['value'],self.params)['remainder'],5)
            for which in ['a','b']:self.assertFalse(n.early_caller_gate(projected['tag'],0,self.params,which))
        for which in ['a','b']:
            self.assertTrue(n.early_caller_gate(0x1a2,1,self.params,which))
            self.assertFalse(n.early_caller_gate(0x68,1,self.params,which))
        # No statement about later opaque caller paths or terminal result tags.

    def test_actual_prefix_bound_offset_and_tag_operands_change_projected_facts(self):
        b=self.edit('prefix_hash',ord('$'));p=n.parameters(b)
        self.assertEqual(n.numeric_projection(b'$1',p,self.table)['tag'],0x1a2)
        self.assertEqual(n.numeric_projection(b'$1',self.params,self.table)['tag'],0x68)
        changes=[(b,b'$1'),(self.edit('at_bound',100000001),b'@100000000')]
        b=self.edit('hash_sub_immediate',-100000001);b=self.edit('hash_add_immediate',100000001,b);changes.append((b,b'#0'))
        changes.append((self.edit('numeric_tag',0x1a3),b'PURR/USDC'))
        changes.append((self.edit('zero_prefix',ord('#')),b'@0'))
        changes.append((self.edit('output_at_prefix',ord('#')),b'#1'))
        for image,value in changes:
            p=n.parameters(image)
            self.assertNotEqual(n.numeric_projection(value,p,self.table),n.numeric_projection(value,self.params,self.table))
            with self.assertRaisesRegex(ValueError,'parameters changed'):n.analyze(image)

    def test_actual_lookup_multiplier_remainder_and_decimal_data_change_facts(self):
        cases=[('lookup_multiplier',self.params['lookup_multiplier']-1,100000010),('lookup_second_remainder',2,100000002),('lookup_bound',100000100,100000002)]
        for name,value,raw in cases:
            image=self.edit(name,value);p=n.parameters(image)
            self.assertNotEqual(n.lookup_projection(raw,p),n.lookup_projection(raw,self.params))
            with self.assertRaisesRegex(ValueError,'parameters changed'):n.analyze(image)
        image=bytearray(self.data);image[self.offset(0x46ea12)+3]=ord('A')
        table=bytes(image[self.offset(0x46ea12):self.offset(0x46ea12)+200])
        self.assertEqual(n.render_integer(1,self.params,table),b'A')
        self.assertNotEqual(n.numeric_projection(b'@1',self.params,table),n.numeric_projection(b'@1',self.params,self.table))
        with self.assertRaisesRegex(ValueError,'decimal_pair_table'):n.analyze(image)

    def test_actual_caller_zero_branch_and_direct_call_bindings(self):
        image=bytearray(self.data);site=0x2c6fa59;target=0x2c6fa5f
        struct.pack_into('<i',image,self.offset(site)+2,target-(site+6))
        self.assertEqual(n.caller_branches(image)[str(site)],target)
        self.assertNotEqual(n.caller_branches(image),self.spec['caller_zero_branches'])
        with self.assertRaisesRegex(ValueError,'destination changed'):n.analyze(image)
        image=bytearray(self.data);image[self.offset(0x2c6fa2e)]^=1
        facts,_=n.extract(image)
        owner=next(f for f in facts['functions'] if f['start']==0x2c6fa00)
        old=next(f for f in self.spec['functions'] if f['start']==0x2c6fa00)
        self.assertNotEqual(owner['direct_calls'],old['direct_calls'])
        with self.assertRaisesRegex(ValueError,'functions bindings'):n.analyze(image)

    def test_actual_import_fde_and_executable_section_controls(self):
        image=bytearray(self.data);s=next(s for s in self.sections if s['name']=='.rela.dyn')
        off=next(o for o in range(s['offset'],s['offset']+s['size'],24) if struct.unpack_from('<Q',image,o)[0]==0x64df9f8)
        struct.pack_into('<Q',image,off+8,(7<<32)|6)
        facts,_=n.extract(image)
        self.assertEqual(facts['relocations'][str(0x64df9f8)]['symbol'],'memcpy')
        with self.assertRaisesRegex(ValueError,'relocations bindings'):n.analyze(image)
        image=bytearray(self.data);f=self.spec['functions'][0];image[self.offset(f['fde'])+12]^=1
        with self.assertRaises(ValueError):n.analyze(image)
        image=bytearray(self.data);text=next(s for s in self.sections if s['name']=='.text');index=self.sections.index(text)
        shoff=struct.unpack_from('<Q',image,40)[0];stride=struct.unpack_from('<H',image,58)[0]
        image[shoff+index*stride+8]^=4
        with self.assertRaises(ValueError):n.analyze(image)

    def test_public_input_identity_precedes_native_calls_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);bad=tmp/'bad';out=tmp/'out'
            changed=bytearray(self.data);changed[0]^=1
            for data in [b'not an ELF',self.data[:4096],changed]:
                bad.write_bytes(data)
                with mock.patch.object(n.subprocess,'check_output',side_effect=AssertionError('native analysis forbidden')):
                    with self.assertRaisesRegex(ValueError,'pinned node115'):n.generate(bad,out)
                self.assertFalse(out.exists())
