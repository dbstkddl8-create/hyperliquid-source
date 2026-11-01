#!/usr/bin/env python3
"""RE-014: conditional EMA numerator fusion across captures, static only."""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

PACKET=ROOT/'research/work-items/RE-014-ema-fused-release-drift'
TARGETS={r:ROOT/f'artifacts/node/{r}/hl-node' for r in ['94','115']}
SPEC_SHA='9b13afc71d14c1ade2bef8adb475f623cbddcba3409f1a1c422d2e854b9ea888'


def specification():
    raw=(PACKET/'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA:raise ValueError('EMA fusion specification changed')
    return json.loads(raw)


def read(data,va,n):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    if len(matches)!=1:raise ValueError('expected unique file-backed mapping')
    s=matches[0];off=s['offset']+va-s['address'];return off,bytes(data[off:off+n])


def parameters(old,new):
    for data,va,raw in [(old,0x147929f,'f20f'),(new,0x63f0680,'c4e2f1'),
                        (new,0x63f06be,'a8'),(new,0x5a7281a,'f2410f5946')]:
        b=bytes.fromhex(raw)
        if read(data,va,len(b))[1]!=b:raise ValueError('EMA arithmetic opcode changed')
    return {'old_sample_opcode':read(old,0x14792a1,1)[1][0],
            'hardware3_opcode':read(new,0x63f0683,1)[1][0],
            'resolver_first_mask':read(new,0x63f06bf,1)[1][0],
            'new_denominator_offset':read(new,0x5a7281f,1)[1][0]}


def selected_target(p,mask):
    """Resolved-cache branch equation only; CPU detection is not modelled."""
    if not 0<=mask<(1<<32):raise ValueError('outside raw u32 mask domain')
    if not mask&(1<<31):return 'unclosed-initializer'
    if mask&p['resolver_first_mask']:return 'hardware3'
    if mask&0x80:return 'hardware4'
    return 'unclosed-fallback'


def accumulation(p,sample,dt,num,den,decay):
    """Independent finite binary64 RNE boundary reference; never an ISA emulator."""
    if not all(math.isfinite(x) for x in [sample,dt,num,den,decay]):raise ValueError('finite operands required')
    prior=num*decay
    if p['old_sample_opcode']==0x59:product=sample*dt
    elif p['old_sample_opcode']==0x58:product=sample+dt
    else:raise ValueError('unsupported old scalar arithmetic')
    old=product+prior
    if p['hardware3_opcode']==0xa9:exact=Fraction(sample)*Fraction(dt)+Fraction(prior)
    elif p['hardware3_opcode']==0x99:exact=Fraction(sample)*Fraction(prior)+Fraction(dt)
    else:raise ValueError('unsupported hardware fused operand order')
    new=float(exact)
    if p['new_denominator_offset']==8:selected_den=den
    elif p['new_denominator_offset']==0:selected_den=num
    else:raise ValueError('unsupported denominator field')
    result={'old_num':old,'hardware3_num':new,'old_den':dt+den*decay,'new_den':dt+selected_den*decay}
    if not all(math.isfinite(x) for x in result.values()):raise ValueError('finite result domain required')
    return result


def analyze(images):
    spec=specification();p=parameters(images['94'],images['115'])
    if p!={'old_sample_opcode':0x59,'hardware3_opcode':0xa9,'resolver_first_mask':0x40,'new_denominator_offset':8}:
        raise ValueError('EMA fusion relation changed')
    controls={
      '94':{0x147929f:'f20f59d3',0x14792a3:'660f100b',0x14792a7:'660f14c0',
            0x14792ab:'660f59c1',0x14792af:'660f14d3',0x14792b3:'660f58d0',0x14792b7:'660f1113'},
      '115':{0x5a72811:'f2410f1016',0x5a72816:'f20f59d0',0x5a7281a:'f2410f594608',
             0x5a72820:'f20f11442438',0x5a72826:'f20f10442440',0x5a7282c:'f20f104c2420',
             0x5a72838:'f2410f1106',0x5a7283d:'f20f10442438',0x5a72843:'f20f58442420',
             0x5a72849:'f2410f114608',0x63f021b:'ffd05dc30f0b',
             0x63f0680:'c4e2f1a9c2c3',0x63f0690:'c4e3f96bc210c3',
             0x63f06a6:'85c0792a',0x63f06aa:'84c0',0x63f06ba:'480f49d1',
             0x63f06c7:'480f44c2',0x63f06d2:'ffe0',
             0x63f06dc:'f20f1155e8f20f114df0f20f1145f8',
             0x63f06f0:'f20f1045f8f20f104df0f20f1055e8',
             0x63f06ff:'0d00000080',0x63f070f:'eb99'}}
    for release,rows in controls.items():
        for va,raw in rows.items():
            b=bytes.fromhex(raw)
            if read(images[release],va,len(b))[1]!=b:raise ValueError('EMA arithmetic/dispatch dataflow changed')
    reports={}
    for release,t in spec['targets'].items():
        data=images[release]
        for o in t['owners']:
            for site,target in o['direct_calls'].items():
                site=int(site);code=read(data,site,5)[1]
                if code[0]!=0xe8 or site+5+struct.unpack_from('<i',code,1)[0]!=target:raise ValueError('EMA direct call changed')
            for site,row in o['rip_bindings'].items():
                site=int(site);prefix=bytes.fromhex(row['prefix']);code=read(data,site,len(prefix)+4)[1]
                if code[:len(prefix)]!=prefix or site+len(code)+struct.unpack_from('<i',code,len(prefix))[0]!=row['target']:raise ValueError('EMA RIP binding changed')
        s=next(s for s in sections(data) if s['name']=='.rela.dyn')
        rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[s['offset']:s['offset']+s['size']])}
        if any(rels.get(int(a))!=tuple(row) for a,row in t['relocations'].items()):raise ValueError('EMA relocation changed')
        for slot,loc in t['source_locations'].items():
            path=bytes.fromhex(loc['path_hex'])
            if read(data,loc['path_va'],len(path))[1]!=path or read(data,int(slot)+8,16)[1]!=struct.pack('<QII',len(path),loc['line'],loc['column']):raise ValueError('EMA source Location changed')
        _,fs,_=fde_extents(data);frames={(f['start'],f['end']):f for f in fs};owners=[]
        for o in t['owners']:
            a,b=o['start'],o['end']
            if (a,b) not in frames:raise ValueError('EMA FDE changed')
            off,body=read(data,a,b-a)
            if hashlib.sha256(body).hexdigest()!=o['sha256']:raise ValueError('EMA complete body changed')
            rawframes={}
            for kind in ['fde','cie']:
                va=frames[a,b][kind];n=struct.unpack('<I',read(data,va,4)[1])[0]+4
                rawframes[kind]={'va':hex(va),'bytes_hex':read(data,va,n)[1].hex()}
            owners.append({'start':hex(a),'end':hex(b),'bytes':b-a,'instructions':o['instructions'],'file_offset':hex(off),'sha256':o['sha256'],'frames':rawframes})
        for a,row in t.get('unmeasured',{}).items():
            if (int(a),row['end']) not in frames:raise ValueError('EMA unmeasured-target boundary changed')
        reports[release]={'sha256':t['sha256'],'owners':owners,'source_locations':t['source_locations'],
                          'unmeasured_bounds':t.get('unmeasured',{})}
    witness=accumulation(p,10.,.1,2.**-53,1.,1.)
    return {'targets':reports,'spec_sha256':SPEC_SHA,'parameters':p,
            'witness_operands_hex':{'sample':(10.).hex(),'dt':(.1).hex(),'num':(2.**-53).hex(),'den':(1.).hex(),'decay':(1.).hex()},
            'witness_results_hex':{k:v.hex() for k,v in witness.items()},
            'local_relation':'node94 rounds sample*dt before adding rounded num*decay; node115 selected hardware leaves fuse sample*dt plus rounded num*decay. Denominator uses separate multiplication/addition in both.',
            'captured_code_executed':False,
            'limits':'Conditional local arithmetic and resolved dispatch only. Unmeasured fallback/detector, actual CPU selection, time/exp/window paths, original source equivalence, caller reachability, nondefault FP modes, full EMA behavior and component gates remain unproved.'}


def generate(binaries,output):
    spec=specification();images={}
    # Authenticate BOTH complete inputs before interpretation/output/native calls.
    for release,t in spec['targets'].items():
        data=binaries[release].read_bytes()
        if len(data)!=t['size'] or hashlib.sha256(data).hexdigest()!=t['sha256']:raise ValueError(f'expected pinned node{release}')
        images[release]=data
    report=analyze(images);output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        for release,t in spec['targets'].items():
            data=images[release];snapshot=Path(directory)/f'node{release}.elf';snapshot.write_bytes(data)
            frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True);frame_lines=[]
            for o in t['owners']:
                a,b=o['start'],o['end'];rows=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l]
                if len(rows)!=1:raise ValueError('native EMA FDE disagreement')
                frame_lines.extend(rows)
                asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(snapshot)],text=True)
                ins=decode_export(asm,a,b,read(data,a,b-a)[1]);required={int(v) for v in o['direct_calls']}|{int(v) for v in o['rip_bindings']}
                required|={v for v in controls_for_native(release) if a<=v<b}
                if len(ins)!=o['instructions'] or not required<=set(ins):raise ValueError('native EMA instruction disagreement')
                (output/f'{release}-{a:x}.objdump.txt').write_bytes(asm.replace(str(snapshot),f'<authenticated-node{release}>').encode('utf-8'))
            (output/f'{release}-frames.txt').write_bytes(('\n'.join(frame_lines)+'\n').encode('utf-8'))
            raw=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
            rows=[l for l in raw.splitlines() if any(l.startswith(f'{int(a):016x} ') for a in t['relocations'])]
            if len(rows)!=len(t['relocations']):raise ValueError('native EMA relocation disagreement')
            (output/f'{release}-relocations.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


def controls_for_native(release):
    return [0x147929f,0x14792ab,0x14792b3] if release=='94' else [
        0x5a72811,0x5a72816,0x5a7281a,0x5a72826,0x5a7282c,0x5a72832,0x5a72838,0x5a72843,
        0x63f0214,0x63f021b,0x63f0680,0x63f0690,0x63f06a0,0x63f06a8,0x63f06be,0x63f06cb,0x63f06d2]


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--node94',type=Path,default=TARGETS['94'])
    ap.add_argument('--node115',type=Path,default=TARGETS['115'])
    ap.add_argument('--output',type=Path,default=ROOT/'work/ema-fused-drift');args=ap.parse_args()
    r=generate({'94':args.node94,'115':args.node115},args.output)
    print(json.dumps({'functions':sum(len(t['owners']) for t in r['targets'].values()),'bytes':sum(o['bytes'] for t in r['targets'].values() for o in t['owners']),'executed':False}))
