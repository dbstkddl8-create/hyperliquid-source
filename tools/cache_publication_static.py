#!/usr/bin/env python3
"""RE-002: static CFG/definition certificate and three cache-store equations."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-002-node115-cache-publication'
PRIOR=ROOT/'research/work-items/RE-002-node115-runtime-tag/spec.json'
SPEC_SHA='189ef7fae41b8453a0492692c85c044a228e162a126d8212e626321622e4b8d4'
H=1<<63
U64=(1<<64)-1


def specification():
    raw=(PACKET/'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA:raise ValueError('cache-publication spec changed')
    return json.loads(raw)


def reader(data):
    secs=sections(data)
    def read(va,n):
        matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
        if len(matches)!=1:raise ValueError('expected one complete file-backed mapping')
        s=matches[0];o=s['offset']+va-s['address'];return bytes(data[o:o+n])
    return secs,read


def parameters(data):
    _,rd=reader(data)
    for a,raw in [(0x5cae39b,'4c89e84809f8'),(0x5cae3a1,'488b0d'),(0x5cae3a8,'4889014889d0'),
                  (0x5cae3ae,'4c0fa4e8'),(0x5cae3b3,'4809f8'),(0x5cae3b6,'488941'),
                  (0x5cae3ba,'4889d0'),(0x5cae3bd,'48c1e8'),(0x5cae3c1,'4809f8'),
                  (0x5cae3c4,'488941'),(0x5cae3c8,'4c89e8'),(0x5cae3cb,'4883c4485b415c415d415e415f5dc3')]:
        b=bytes.fromhex(raw)
        if rd(a,len(b))!=b:raise ValueError('publication dataflow changed')
    return {'middle_shift':rd(0x5cae3b2,1)[0],'last_shift':rd(0x5cae3c0,1)[0],
            'middle_offset':rd(0x5cae3b9,1)[0],'last_offset':rd(0x5cae3c7,1)[0],
            'cache_slot':0x5cae3a8+struct.unpack('<i',rd(0x5cae3a4,4))[0]}


def store_equations(a,b,p,marker=H):
    """Three closed-form symbolic store values, not an instruction evaluator."""
    if not 0<=a<=U64 or not 0<=b<=U64 or not 0< p['middle_shift']<64 or not 0<=p['last_shift']<64:
        raise ValueError('outside the bounded unsigned-word equation domain')
    q=p['middle_shift']
    writes=[(0,a|marker),(p['middle_offset'],(((b<<q)&U64)|(a>>(64-q)))|marker),
            (p['last_offset'],(b>>p['last_shift'])|marker)]
    return {'ordered_writes':writes,'final_words':dict(writes),'raw_return':a}


def unpack(words):
    if set(words)!={0,8,16} or any(not 0<=v<=U64 or not v&H for v in words.values()) or words[16]&~(H|3):
        raise ValueError('not the proved three-word representation')
    a=(words[0]&(H-1))|((words[8]&1)<<63)
    b=((words[8]>>1)&((1<<62)-1))|((words[16]&3)<<62)
    return a,b


def native_rows(data):
    """GNU reads a private snapshot. No instruction or hardware probe executes."""
    spec=specification();a,b=spec['owner']['start'],spec['owner']['end'];_,rd=reader(data)
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/'node115.elf';path.write_bytes(data)
        asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(path)],text=True)
        decode_export(asm,a,b,rd(a,b-a))
        rows=[]
        for line in asm.splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(\S+)\s*(.*)$',line)
            if m:rows.append({'va':int(m[1],16),'bytes_hex':bytes.fromhex(m[2]).hex(),'mnemonic':m[3],
                              'operands':m[4].split('#')[0].split('<')[0].strip()})
        return rows,asm.replace(str(path),'<authenticated-node115>')


def cfg_certificate(rows):
    """Finite reaching-definition sets over a CFG; no values/flags are simulated."""
    allowed={'push','mov','sub','xor','cpuid','xchg','movabs','test','je','cmp','jb','jmp','shl','or','and',
             'shr','lea','cmove','jne','not','call','jbe','add','cmovb','sete','cmovne','shld','pop','ret'}
    by={r['va']:r for r in rows};edges={};constants={};returns=[];calls={}
    for row in rows:
        a=row['va'];raw=bytes.fromhex(row['bytes_hex']);n=a+len(raw);m=row['mnemonic']
        if m not in allowed:raise ValueError('unreviewed CFG instruction')
        if m=='ret':
            if raw!=b'\xc3':raise ValueError('unreviewed return')
            out=[];returns.append(a)
        elif m=='jmp' or m.startswith('j'):
            if len(raw)==2 and (raw[0]==0xeb or 0x70<=raw[0]<=0x7f):t=n+struct.unpack('<b',raw[1:])[0]
            elif raw[0]==0xe9 and len(raw)==5:t=n+struct.unpack('<i',raw[1:])[0]
            elif raw[:1]==b'\x0f' and 0x80<=raw[1]<=0x8f and len(raw)==6:t=n+struct.unpack('<i',raw[2:])[0]
            else:raise ValueError('unreviewed branch encoding')
            if int(row['operands'],16)!=t:raise ValueError('native branch target disagreement')
            out=[t] if m=='jmp' else [n,t]
        else:
            out=[n]
            if m=='call':
                if len(raw)!=5 or raw[0]!=0xe8:raise ValueError('unreviewed call encoding')
                calls[a]=n+struct.unpack('<i',raw[1:])[0]
        if any(t not in by for t in out):raise ValueError('CFG edge leaves complete body or enters an operand')
        edges[a]=out
        if raw[:2]==b'\x48\xbf' and len(raw)==10:
            constants[a]=int.from_bytes(raw[2:],'little')
    entry=rows[0]['va'];state={a:set() for a in by};state[entry]={'entry-unknown'};pending=collections.deque([entry])
    while pending:
        a=pending.popleft();r=by[a];m=r['mnemonic'];parts=[p.strip() for p in r['operands'].split(',')]
        out=set(state[a]);aliases={'rdi','edi','di','dil'}
        if a in constants:out={f'constant@{a:x}:{constants[a]:x}'}
        elif (m=='call' or (m not in {'cmp','test','push'} and parts[0] in aliases)
              or m=='xchg' and any(p in aliases for p in parts)):
            # Nonconstant writes and normal-returning opaque calls may clobber
            # RDI. Retaining old definitions too is a conservative overestimate.
            out.add(f'unknown-write@{a:x}')
        for t in edges[a]:
            joined=state[t]|out
            if joined!=state[t]:state[t]=joined;pending.append(t)
    publication=specification()['publication_start']
    reachable=set();pending=collections.deque([entry])
    while pending:
        a=pending.popleft()
        if a==publication or a in reachable:continue
        reachable.add(a);pending.extend(edges[a])
    return {'edges':{hex(a):list(map(hex,v)) for a,v in edges.items()},
            'constant_definitions':{hex(a):hex(v) for a,v in constants.items()},
            'at_publication':sorted(state[publication]),'at_returns':{hex(a):sorted(state[a]) for a in returns},
            'publication_dominates_returns':not any(a in reachable for a in returns),
            'structurally_reachable_rows':sum(bool(s) for s in state.values()),
            'direct_calls':{str(a):v for a,v in calls.items()}}


def analyze(data,rows):
    spec=specification();secs,rd=reader(data);p=parameters(data);cert=cfg_certificate(rows)
    if p!={'middle_shift':1,'last_shift':62,'middle_offset':8,'last_offset':16,'cache_slot':0x64dfa60}:
        raise ValueError('publication equation changed')
    expected={f'constant@{a:x}:{H:x}' for a in spec['sentinel_sites']}
    if set(cert['at_publication'])!=expected or not cert['publication_dominates_returns'] or len(cert['at_returns'])!=1:
        raise ValueError('marker reaching-definition proof changed')
    if cert['direct_calls']!=spec['call_bindings']:raise ValueError('opaque call binding changed')
    prior=PRIOR.read_bytes()
    if hashlib.sha256(prior).hexdigest()!=spec['prior_spec_sha256']:raise ValueError('prior selector binding changed')
    prior=json.loads(prior)
    sec=next(s for s in secs if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    for a,value in spec['relocations'].items():
        if rels.get(int(a))!=tuple(value) or prior['relocations'][a]!=value:raise ValueError('cache relocation binding changed')
    cache=spec['cache_address']
    region=[s for s in secs if s['address']<=cache and cache+24<=s['address']+s['size']]
    if region!=[spec['cache_region']] or not region[0]['flags']&1:raise ValueError('cache write region changed')
    _,fs,_=fde_extents(data);o=spec['owner'];owners=[f for f in fs if (f['start'],f['end'])==(o['start'],o['end'])]
    if len(owners)!=1:raise ValueError('cache owner FDE changed')
    if len(rows)!=o['instructions'] or hashlib.sha256(rd(o['start'],o['end']-o['start'])).hexdigest()!=o['sha256']:
        raise ValueError('cache owner bytes changed')
    frames={}
    for kind in ['fde','cie']:
        va=owners[0][kind];n=int.from_bytes(rd(va,4),'little')+4;frames[kind]={'va':hex(va),'bytes_hex':rd(va,n).hex()}
    if not any([f['start'],f['end']]==spec['unmeasured_callee_bounds'] for f in fs):raise ValueError('unmeasured call boundary changed')
    return {'target_sha256':spec['target_sha256'],'owner':o,'frames':frames,'parameters':p,'cfg':cert,
            'cache_region':region[0],'prior_spec_sha256':spec['prior_spec_sha256'],
            'relation':'For raw A=R13,B=RDX at publication and valid writable cache: C0=A|H; C1=((B<<1 mod2^64)|(A>>63))|H; C2=(B>>62)|H; raw RAX return=A. H=2^63.',
            'captured_instructions_executed':False,
            'limits':'Static marker/CFG and local publication equations only. Prefix feature values/meaning, CPUID/XGETBV behavior, opaque callee effects, input reachability, concurrent coherence, source/Rust ABI, whole-detector equivalence and component gates remain unproved.'}


def generate(binary,output):
    spec=specification();data=binary.read_bytes()
    if len(data)!=spec['target_size'] or hashlib.sha256(data).hexdigest()!=spec['target_sha256']:
        raise ValueError('expected pinned node115')
    rows,asm=native_rows(data);report=analyze(data,rows)
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/'node115.elf';path.write_bytes(data)
        raw=subprocess.check_output(['readelf','-wf',str(path)],text=True);o=spec['owner']
        frames=[l for l in raw.splitlines() if f"pc={o['start']:016x}..{o['end']:016x}" in l]
        if len(frames)!=1:raise ValueError('native FDE disagreement')
        raw=subprocess.check_output(['readelf','-rW',str(path)],text=True)
        rels=[l for l in raw.splitlines() if any(l.startswith(f'{int(a):016x} ') for a in spec['relocations'])]
        if len(rels)!=len(spec['relocations']):raise ValueError('native relocation disagreement')
    output.mkdir(parents=True,exist_ok=True)
    for name,text in [('owner.objdump.txt',asm),('frames.txt','\n'.join(frames)+'\n'),('relocations.txt','\n'.join(rels)+'\n'),('records.json',json.dumps(report,indent=2)+'\n')]:
        (output/name).write_bytes(text.encode('utf-8'))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'work/cache-publication')
    args=parser.parse_args();r=generate(TARGET,args.output)
    print(json.dumps({'bytes':r['owner']['end']-r['owner']['start'],'instructions':r['owner']['instructions'],'executed':False}))
