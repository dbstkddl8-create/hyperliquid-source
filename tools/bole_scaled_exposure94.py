#!/usr/bin/env python3
"""Digest-bound byte record for two node 94 scaled-exposure readers."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
D = 100_000_000_000_000
MAX = (1 << 64) - 1
WINDOWS = {
    0x28db270: (0x28db4dd, '99140fa7f7f397e169c335392278f3b507679743f168bbaa92406e3435cb52e0'),
    0x394b660: (0x394b7d3, 'eea30202f0d06a2a2fb6803a855e6d4b5a0c6aea1344cbedac9f1b77c51bad12'),
}
# Byte positions of conditional branches, manually identified in these FDEs.
BRANCHES = {
    0x28db270: [0x28db287, 0x28db2b6, 0x28db2d6, 0x28db2df, 0x28db2f7,
                0x28db313, 0x28db328, 0x28db356, 0x28db376, 0x28db37f,
                0x28db397, 0x28db3b7, 0x28db3f3, 0x28db410, 0x28db419,
                0x28db427, 0x28db46e, 0x28db495, 0x28db4ac, 0x28db4b1],
    0x394b660: [0x394b6d1, 0x394b6ff, 0x394b708, 0x394b70f, 0x394b751,
                0x394b77a, 0x394b77f, 0x394b786, 0x394b7c2],
}
JCC = ('o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g')

class Image:
    def __init__(self, data, digest=DIGEST):
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('target digest mismatch')
        self.data = data
        self.sections = sections(data)
        _, fdes, _ = fde_extents(data)
        self.frames = {}
        for f in fdes:
            if f['start'] in WINDOWS:
                if f['start'] in self.frames:
                    raise ValueError('duplicate FDE start')
                self.frames[f['start']] = f
        if set(self.frames) != set(WINDOWS):
            raise ValueError('missing FDE')
        for start, (end, h) in WINDOWS.items():
            if self.frames[start]['end'] != end:
                raise ValueError('unexpected FDE extent')
            if hashlib.sha256(self.read(start, end-start)).hexdigest() != h:
                raise ValueError('unexpected function bytes')

    def read(self, va, size):
        if size < 0:
            raise ValueError('negative size')
        matches = [s for s in self.sections if s['type'] != 8 and s['size'] and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address outside unique file-backed section')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off+size]

    def offset(self, va, size):
        self.read(va, size)
        s = next(s for s in self.sections if s['type'] != 8 and s['size'] and
                 s['address'] <= va and va + size <= s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def branch(self, va):
        op = self.read(va, 2)
        if 0x70 <= op[0] <= 0x7f:
            size, condition = 2, JCC[op[0] & 15]
            disp = struct.unpack('<b', op[1:])[0]
        elif op[0] == 0x0f and 0x80 <= op[1] <= 0x8f:
            size, condition = 6, JCC[op[1] & 15]
            disp = struct.unpack('<i', self.read(va+2, 4))[0]
        else:
            raise ValueError('unexpected conditional branch')
        return {'site': hex(va), 'bytes': self.read(va,size).hex(),
                'condition': condition, 'target': hex(va+size+disp)}

    def rel_target(self, va):
        raw = self.read(va, 6)
        if raw[:2] != b'\xff\x15':
            raise ValueError('expected indirect call')
        return va + 6 + struct.unpack_from('<i',raw,2)[0]

    def relocation(self, va):
        found = []
        for s in self.sections:
            if s['type'] == 4:
                if s['size'] % 24:
                    raise ValueError('truncated RELA')
                for pos in range(s['offset'], s['offset'] + s['size'], 24):
                    offset, info, addend = struct.unpack_from('<QQq', self.data, pos)
                    if offset == va:
                        found.append((info, addend))
        if len(found) != 1 or found[0][0] != 8:
            raise ValueError('expected one RELATIVE relocation')
        return found[0][1]


def scale(a, b, up):
    """Conditional mathematical model; quotient helper is assumed exact."""
    if not (0 <= a <= MAX and 0 <= b <= MAX and up in (0, 1)):
        raise ValueError('inputs outside u64/boolean domain')
    product = a * b
    q, rem = divmod(product, D)
    q += bool(up and rem)
    return (q if q <= MAX else None), rem


def machine_scale(a, b, up):
    """Model the multiply, helper return, remainder reconstruction and carry.

    This is not an instruction interpreter. The quotient helper is an explicit
    assumption, and the digest-locked body records tie the modeled sequence to
    the inspected instruction bytes.
    """
    if not (0 <= a <= MAX and 0 <= b <= MAX and up in (0, 1)):
        raise ValueError('inputs outside u64/boolean domain')
    product = a * b
    low, high = product & MAX, product >> 64
    quotient = product // D
    qlo, qhi = quotient & MAX, quotient >> 64
    low_product = qlo * D
    reconstructed_low = low_product & MAX
    reconstructed_high = ((low_product >> 64) + qhi * D) & MAX
    low_remainder = (low - reconstructed_low) & MAX
    borrow = int(low < reconstructed_low)
    high_remainder = (high - reconstructed_high - borrow) & MAX
    add = int(bool(up) and bool(high_remainder | low_remainder))
    summed = qlo + add
    qlo = summed & MAX
    qhi = (qhi + (summed >> 64)) & MAX
    return (None if qhi else qlo), (high_remainder << 64) | low_remainder


# A deliberately narrow interpreter for the arithmetic slice of the first
# reader. Each entry must match exactly; unsupported bytes fail closed.
OPS = {
    0x28db43e:'4c89f0', 0x28db441:'49f7e0', 0x28db444:'4989d7',
    0x28db447:'4989c4', 0x28db44a:'49bd00407a10f35a0000',
    0x28db454:'4889c7', 0x28db457:'4889d6', 0x28db45a:'4c89ea',
    0x28db45d:'31c9', 0x28db45f:'ff15432de902', 0x28db465:'4889c1',
    0x28db468:'4889d6', 0x28db46b:'4084ed', 0x28db46e:'7422',
    0x28db470:'4889c8', 0x28db473:'49f7e5', 0x28db476:'4c0fafee',
    0x28db47a:'4901d5', 0x28db47d:'4929c4', 0x28db480:'4d19ef',
    0x28db483:'31c0', 0x28db485:'4d09e7', 0x28db488:'0f95c0',
    0x28db48b:'4801c1', 0x28db48e:'4883d600', 0x28db492:'4885f6',
    0x28db495:'7412', 0x28db497:'c6430103', 0x28db4a9:'4d85f6',
    0x28db4ac:'7515', 0x28db4ae:'4885c9', 0x28db4b1:'7410',
    0x28db4b3:'c6430102', 0x28db4c3:'48894b08',
}


def run_first_slice(image, a, b, up, quotient=None):
    """Interpret the selected real instruction slice, with division stubbed.

    Input registers r14=a, r8=b, bpl=up correspond to the point immediately
    after the two tree lookups. Stop at the local result or error store.
    """
    if not (0 <= a <= MAX and 0 <= b <= MAX and up in (0, 1)):
        raise ValueError('inputs outside u64/boolean domain')
    r = dict(rax=0,rcx=0,rdx=0,rsi=0,rdi=0,r8=b,r12=0,r13=0,r14=a,r15=0)
    pc=0x28db43e
    zf=cf=0
    visited=[]
    for _ in range(64):
        expected = OPS.get(pc)
        if expected is None:
            raise ValueError('unsupported instruction')
        actual = image.read(pc,len(expected)//2)
        if actual.hex() != expected:
            raise ValueError('unexpected instruction bytes')
        visited.append(pc)
        next_pc=pc+len(actual)
        if pc == 0x28db43e: r['rax']=r['r14']
        elif pc in (0x28db441,0x28db473):
            rhs=r['r8'] if pc==0x28db441 else r['r13']
            value=r['rax']*rhs
            r['rax'],r['rdx']=value & MAX,value >> 64
        elif pc == 0x28db444: r['r15']=r['rdx']
        elif pc == 0x28db447: r['r12']=r['rax']
        elif pc == 0x28db44a: r['r13']=struct.unpack_from('<Q',actual,2)[0]
        elif pc == 0x28db454: r['rdi']=r['rax']
        elif pc == 0x28db457: r['rsi']=r['rdx']
        elif pc == 0x28db45a: r['rdx']=r['r13']
        elif pc == 0x28db45d: r['rcx']=0
        elif pc == 0x28db45f:
            if image.rel_target(pc) != 0x576e1a8:
                raise ValueError('wrong divide slot')
            divisor=(r['rcx'] << 64) | r['rdx']
            if divisor == 0:
                raise ValueError('division by zero')
            dividend=(r['rsi'] << 64) | r['rdi']
            q=dividend // divisor if quotient is None else quotient(dividend,divisor)
            if not 0 <= q < 1 << 128:
                raise ValueError('invalid helper result')
            r['rax'],r['rdx']=q & MAX,q >> 64
        elif pc == 0x28db465: r['rcx']=r['rax']
        elif pc == 0x28db468: r['rsi']=r['rdx']
        elif pc == 0x28db46b: zf=int(up==0)
        elif pc in (0x28db46e,0x28db495,0x28db4b1):
            if zf: next_pc=pc+2+struct.unpack('<b',actual[1:])[0]
        elif pc == 0x28db4ac:
            if not zf: next_pc=pc+2+struct.unpack('<b',actual[1:])[0]
        elif pc == 0x28db470: r['rax']=r['rcx']
        elif pc == 0x28db476: r['r13']=(r['r13']*r['rsi']) & MAX
        elif pc == 0x28db47a: r['r13']=(r['r13']+r['rdx']) & MAX
        elif pc == 0x28db47d:
            cf=int(r['r12']<r['rax']);r['r12']=(r['r12']-r['rax']) & MAX
        elif pc == 0x28db480:
            rhs=r['r13']+cf;cf=int(r['r15']<rhs);r['r15']=(r['r15']-rhs) & MAX
        elif pc == 0x28db483: r['rax']=0;cf=0;zf=1
        elif pc == 0x28db485: r['r15'] |= r['r12'];zf=int(r['r15']==0);cf=0
        elif pc == 0x28db488: r['rax']=(r['rax'] & ~255) | int(not zf)
        elif pc == 0x28db48b:
            v=r['rcx']+r['rax'];r['rcx']=v & MAX;cf=int(v>MAX)
        elif pc == 0x28db48e: r['rsi']=(r['rsi']+cf) & MAX
        elif pc == 0x28db492: zf=int(r['rsi']==0)
        elif pc == 0x28db4a9: zf=int(r['r14']==0)
        elif pc == 0x28db4ae: zf=int(r['rcx']==0)
        elif pc == 0x28db497: return ('error',3,None), visited
        elif pc == 0x28db4b3: return ('error',2,None), visited
        elif pc == 0x28db4c3: return ('ok',0,r['rcx']), visited
        else: raise ValueError('unhandled instruction')
        pc=next_pc
    raise ValueError('instruction limit reached')


SECOND_OPS = {
 0x394b693:'48f7641158',0x394b698:'4989c6',0x394b69b:'4889d5',
 0x394b69e:'4c894c2418',0x394b6a3:'48897c2420',0x394b6a8:'48bb00407a10f35a0000',
 0x394b6b2:'4889c7',0x394b6b5:'4889d6',0x394b6b8:'4889da',0x394b6bb:'31c9',
 0x394b6bd:'ff15e52ae201',0x394b6c3:'4889c1',0x394b6c6:'4989d5',
 0x394b6c9:'4489642404',0x394b6ce:'4585e4',0x394b6d1:'7422',
 0x394b6d3:'4889c8',0x394b6d6:'48f7e3',0x394b6d9:'490fafdd',
 0x394b6dd:'4801d3',0x394b6e0:'4929c6',0x394b6e3:'4819dd',
 0x394b6e6:'31c0',0x394b6e8:'4c09f5',0x394b6eb:'0f95c0',
 0x394b6ee:'4801c1',0x394b6f1:'4983d500',0x394b6f5:'b003',
 0x394b6f7:'4d85ed',0x394b6fa:'4c8b742420',0x394b6ff:'0f8583000000',
 0x394b705:'4d85ff',0x394b708:'7507',0x394b70a:'b002',
 0x394b70c:'4885c9',0x394b70f:'7577',0x394b711:'4989cc',
 0x394b714:'4889c8',0x394b717:'488b4c2418',0x394b71c:'48f7e1',
 0x394b71f:'4989c7',0x394b722:'4c0fafe9',0x394b726:'4901d5',
 0x394b729:'48bb00407a10f35a0000',0x394b733:'4889c7',0x394b736:'4c89ee',
 0x394b739:'4889da',0x394b73c:'31c9',0x394b73e:'ff15642ae201',
 0x394b744:'4889c7',0x394b747:'4889d1',0x394b74a:'8b742404',
 0x394b74e:'4084f6',0x394b751:'7422',0x394b753:'4889f8',
 0x394b756:'48f7e3',0x394b759:'480fafd9',0x394b75d:'4801d3',
 0x394b760:'4929c7',0x394b763:'4919dd',0x394b766:'31c0',
 0x394b768:'4d09fd',0x394b76b:'0f95c0',0x394b76e:'4801c7',
 0x394b771:'4883d100',0x394b775:'b003',0x394b777:'4885c9',
 0x394b77a:'750c',0x394b77c:'4d85e4',0x394b77f:'7522',
 0x394b781:'b002',0x394b783:'4885ff',0x394b786:'741b',
 0x394b788:'41884601',0x394b7a3:'4c8b442460',
}


def run_second_slice(image, a, b, factor, up):
    """Interpret both products from the selected-lane multiply to the helper.

    The pointed-to word for the first multiply is supplied as b. Divide calls
    use exact integer division; output stops before the downstream helper.
    """
    if not (0 <= a <= MAX and 0 <= b <= MAX and 0 <= factor <= MAX and up in (0,1)):
        raise ValueError('inputs outside u64/boolean domain')
    r={k:0 for k in ('rax','rbx','rcx','rdx','rsi','rdi','r12','r13','r14','r15','rbp')}
    r.update(rax=a,r15=a,r12=up)
    pc=0x394b693; zf=cf=0; visited=[]; first=None
    for _ in range(128):
        expected=SECOND_OPS.get(pc)
        if expected is None: raise ValueError('unsupported second-slice instruction')
        actual=image.read(pc,len(expected)//2)
        if actual.hex()!=expected: raise ValueError('unexpected second-slice instruction bytes')
        visited.append(pc); next_pc=pc+len(actual)
        if pc in (0x394b693,0x394b6d6,0x394b71c,0x394b756):
            rhs={0x394b693:b,0x394b6d6:r['rbx'],0x394b71c:r['rcx'],0x394b756:r['rbx']}[pc]
            v=r['rax']*rhs;r['rax'],r['rdx']=v & MAX,v>>64
        elif pc==0x394b698:r['r14']=r['rax']
        elif pc==0x394b69b:r['rbp']=r['rdx']
        elif pc in (0x394b69e,0x394b6a3,0x394b6c9,0x394b6fa):pass
        elif pc in (0x394b6a8,0x394b729):r['rbx']=struct.unpack_from('<Q',actual,2)[0]
        elif pc in (0x394b6b2,0x394b733,0x394b744):r['rdi']=r['rax']
        elif pc==0x394b6b5:r['rsi']=r['rdx']
        elif pc in (0x394b6b8,0x394b739):r['rdx']=r['rbx']
        elif pc in (0x394b6bb,0x394b73c):r['rcx']=0
        elif pc in (0x394b6bd,0x394b73e):
            if image.rel_target(pc)!=0x576e1a8:raise ValueError('wrong divide slot')
            divisor=(r['rcx']<<64)|r['rdx']
            if not divisor:raise ValueError('division by zero')
            q=((r['rsi']<<64)|r['rdi'])//divisor
            r['rax'],r['rdx']=q & MAX,q>>64
        elif pc==0x394b6c3:r['rcx']=r['rax']
        elif pc==0x394b6c6:r['r13']=r['rdx']
        elif pc==0x394b6ce:zf=int((r['r12'] & 0xffffffff)==0)
        elif pc in (0x394b6d1,0x394b6ff,0x394b708,0x394b70f,0x394b751,0x394b77a,0x394b77f,0x394b786):
            branch=image.branch(pc); take=zf if branch['condition']=='e' else not zf
            if branch['condition'] not in ('e','ne'):raise ValueError('unexpected branch')
            if take:next_pc=int(branch['target'],16)
        elif pc in (0x394b6d3,0x394b714):r['rax']=r['rcx']
        elif pc==0x394b6d9:r['rbx']=(r['rbx']*r['r13']) & MAX
        elif pc in (0x394b6dd,0x394b75d):r['rbx']=(r['rbx']+r['rdx']) & MAX
        elif pc==0x394b6e0:
            cf=int(r['r14']<r['rax']);r['r14']=(r['r14']-r['rax']) & MAX
        elif pc==0x394b6e3:
            rhs=r['rbx']+cf;cf=int(r['rbp']<rhs);r['rbp']=(r['rbp']-rhs) & MAX
        elif pc in (0x394b6e6,0x394b766):r['rax']=0;zf=1;cf=0
        elif pc==0x394b6e8:r['rbp']|=r['r14'];zf=int(r['rbp']==0);cf=0
        elif pc in (0x394b6eb,0x394b76b):r['rax']=(r['rax'] & ~255)|int(not zf)
        elif pc==0x394b6ee:
            v=r['rcx']+r['rax'];r['rcx']=v & MAX;cf=int(v>MAX)
        elif pc==0x394b6f1:r['r13']=(r['r13']+cf) & MAX
        elif pc in (0x394b6f5,0x394b775):r['rax']=(r['rax'] & ~255)|3
        elif pc==0x394b6f7:zf=int(r['r13']==0)
        elif pc==0x394b705:zf=int(r['r15']==0)
        elif pc in (0x394b70a,0x394b781):r['rax']=(r['rax'] & ~255)|2
        elif pc in (0x394b70c,0x394b777):zf=int(r['rcx']==0)
        elif pc==0x394b711:r['r12']=r['rcx'];first=r['rcx']
        elif pc==0x394b717:r['rcx']=factor
        elif pc==0x394b71f:r['r15']=r['rax']
        elif pc==0x394b722:r['r13']=(r['r13']*r['rcx']) & MAX
        elif pc==0x394b726:r['r13']=(r['r13']+r['rdx']) & MAX
        elif pc==0x394b736:r['rsi']=r['r13']
        elif pc==0x394b747:r['rcx']=r['rdx']
        elif pc==0x394b74a:r['rsi']=up
        elif pc==0x394b74e:zf=int((r['rsi'] & 255)==0)
        elif pc==0x394b753:r['rax']=r['rdi']
        elif pc==0x394b759:r['rbx']=(r['rbx']*r['rcx']) & MAX
        elif pc==0x394b760:
            cf=int(r['r15']<r['rax']);r['r15']=(r['r15']-r['rax']) & MAX
        elif pc==0x394b763:
            rhs=r['rbx']+cf;cf=int(r['r13']<rhs);r['r13']=(r['r13']-rhs) & MAX
        elif pc==0x394b768:r['r13']|=r['r15'];zf=int(r['r13']==0);cf=0
        elif pc==0x394b76e:
            v=r['rdi']+r['rax'];r['rdi']=v & MAX;cf=int(v>MAX)
        elif pc==0x394b771:r['rcx']=(r['rcx']+cf) & MAX
        elif pc==0x394b77c:zf=int(r['r12']==0)
        elif pc==0x394b783:zf=int(r['rdi']==0)
        elif pc==0x394b788:return ('error',r['rax'] & 255,first,None),visited
        elif pc==0x394b7a3:return ('helper',0,first,r['rdi']),visited
        else:raise ValueError('unhandled second-slice instruction')
        pc=next_pc
    raise ValueError('second-slice instruction limit reached')


def single(a, b, up):
    q, rem = scale(a, b, up)
    if q is None:
        return ('error', 3, None, rem)
    if a == 0 and q != 0:
        return ('error', 2, None, rem)
    return ('ok', 0, q, rem)


def double(a, b, factor, up, helper_ok=True, helper_value=0):
    first = single(a, b, up)
    if first[0] != 'ok':
        return ('first-error', first[1], first[2], None, first[3], None)
    q1 = first[2]
    second = single(q1, factor, up)
    if second[0] != 'ok':
        return ('second-error', second[1], q1, None, first[3], second[3])
    return ('helper-ok' if helper_ok else 'helper-error', 0 if helper_ok else 7,
            q1, second[2], first[3], second[3])


def build(image, out):
    out.mkdir(parents=True, exist_ok=True)
    windows=[]
    for start,(end,h) in sorted(WINDOWS.items()):
        f=image.frames[start]
        windows.append({'start':hex(start),'end_exclusive':hex(end),'file_offset':hex(image.offset(start,end-start)),
                        'fde':hex(f['fde']),'size':end-start,'sha256':h,'bytes':image.read(start,end-start).hex(),
                        'branches':[image.branch(x) for x in BRANCHES[start]]})
    sites=[0x28db45f,0x394b6bd,0x394b73e,0x394b7ba]
    calls=[]
    for site in sites:
        slot=image.rel_target(site)
        calls.append({'site':hex(site),'bytes':image.read(site,6).hex(),'slot':hex(slot),
                      'relative_addend':hex(image.relocation(slot))})
    constants=[]
    for site in (0x28db44c,0x394b6aa,0x394b72b):
        raw=image.read(site,8); value=struct.unpack('<Q',raw)[0]
        if value != D:
            raise ValueError('unexpected scale')
        constants.append({'address':hex(site),'bytes':raw.hex(),'value':value})
    record={'target_sha256':DIGEST,'address_coordinate':'ELF virtual address',
            'functions':windows,'calls':calls,'scale_immediates':constants,
            'scope_note':'Selected FDEs and listed branches only; no indirect-call census or function-completeness claim.'}
    (out/'evidence.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    # Windows follow instruction boundaries inspected for this digest. These are
    # local slices, not a disassembly or a claim of all control-flow edges.
    slices = [
        (0x28db270,0x28db280,0x28db31e,'first-tree-search'),
        (0x28db270,0x28db31e,0x28db3bd,'fallback-tree-search'),
        (0x28db270,0x28db3bd,0x28db433,'lane-and-second-tree-search'),
        (0x28db270,0x28db433,0x28db44a,'load-and-wide-product'),
        (0x28db270,0x28db44a,0x28db465,'constant-and-quotient-call'),
        (0x28db270,0x28db465,0x28db492,'conditional-remainder-and-increment'),
        (0x28db270,0x28db492,0x28db4bb,'width-and-zero-checks'),
        (0x28db270,0x28db4bb,0x28db4dd,'missing-row-and-result-stores'),
        (0x394b660,0x394b66e,0x394b693,'lane-selection-and-loads'),
        (0x394b660,0x394b693,0x394b6c3,'first-wide-product-and-quotient'),
        (0x394b660,0x394b6c3,0x394b6f5,'first-conditional-rounding'),
        (0x394b660,0x394b6f5,0x394b711,'first-width-and-zero-checks'),
        (0x394b660,0x394b711,0x394b744,'second-wide-product-and-quotient'),
        (0x394b660,0x394b744,0x394b775,'second-conditional-rounding'),
        (0x394b660,0x394b775,0x394b7a3,'second-width-zero-and-error-stores'),
        (0x394b660,0x394b7a3,0x394b7d3,'final-helper-and-result-stores'),
    ]
    lines = ['function\tstart\tend_exclusive\trole\tbytes']
    for function, start, end, role in slices:
        if not function <= start < end <= WINDOWS[function][0]:
            raise ValueError('slice outside FDE')
        lines.append(f'{function:#x}\t{start:#x}\t{end:#x}\t{role}\t{image.read(start,end-start).hex()}')
    (out/'steps.tsv').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    # Boundary combinations for both the single-stage and two-stage rule.
    vals=[0,1,2,D//2,D-1,D,D+1,2*D,(MAX*D)//(D+1),(MAX*D)//(D+1)+1,MAX//2,MAX-1,MAX]
    lines=['kind\ta\tb\tfactor\tup\thelper_ok\tresult\tstatus\tq1\tq2\trem1\trem2']
    coverage = {}
    for a in vals:
        for b in vals:
            for up in (0,1):
                state,status,q,rem=single(a,b,up)
                mq,mrem=machine_scale(a,b,up)
                actual, visits=run_first_slice(image,a,b,up)
                if actual != (state,status,q):
                    raise ValueError('instruction slice disagrees with model')
                for pc in visits:
                    coverage[pc]=coverage.get(pc,0)+1
                if (q,rem) != (mq,mrem):
                    raise ValueError('limb reconstruction disagrees with model')
                lines.append(f'single\t{a}\t{b}\t-\t{up}\t-\t{state}\t{status}\t{q if q is not None else "-"}\t-\t{rem}\t-')
    triples=[(1,1,D),(2,D*3//4,D*3//4),(1,D+1,D+1),
             (MAX,MAX,1),(MAX,D,MAX),(MAX,D, D),(0,MAX,MAX),
             (1,D,MAX),(MAX,D+1,1),(D,D,0)]
    triples += [(a,b,z) for a in vals for b in vals for z in (0,1,D,D+1,MAX)]
    second_coverage = {}
    for a,b,z in triples:
        for up in (0,1):
            for hook in (False,True):
                state,status,q1,q2,r1,r2=double(a,b,z,up,hook)
                observed, visits = run_second_slice(image,a,b,z,up)
                expected = ('error',status,q1,None) if state.endswith('error') and state != 'helper-error' else ('helper',0,q1,q2)
                if observed != expected:
                    raise ValueError(f'second instruction slice disagrees: {observed} {expected}')
                for pc in visits:
                    second_coverage[pc]=second_coverage.get(pc,0)+1
                fmt=lambda x:'-' if x is None else str(x)
                lines.append(f'double\t{a}\t{b}\t{z}\t{up}\t{int(hook)}\t{state}\t{status}\t{fmt(q1)}\t{fmt(q2)}\t{fmt(r1)}\t{fmt(r2)}')
    (out/'cases.tsv').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    rows=['address\tbytes\tvisits']
    for pc, encoded in sorted(OPS.items()):
        rows.append(f'{pc:#x}\t{encoded}\t{coverage.get(pc,0)}')
    for pc, encoded in sorted(SECOND_OPS.items()):
        rows.append(f'{pc:#x}\t{encoded}\t{second_coverage.get(pc,0)}')
    (out/'slice-coverage.tsv').write_text('\n'.join(rows)+'\n',encoding='utf-8')
    max_product = MAX * MAX
    max_rounded = (max_product + D - 1) // D
    if max_product >= 1 << 128 or max_rounded >= 1 << 128:
        raise ValueError('unexpected arithmetic bounds')
    proof = {'u64_max':MAX, 'divisor':D, 'maximum_product':max_product,
             'maximum_ceil_quotient':max_rounded,
             'floor_first_error_product_at_least':D * (MAX + 1),
             'ceil_first_error_product_above':D * MAX,
             'limb_model_boundary_comparisons':len(vals) * len(vals) * 2,
             'double_model_cases':len(triples) * 4,
             'first_slice_interpreter_runs':len(vals) * len(vals) * 2,
             'first_slice_instruction_sites_reached':len(coverage),
             'first_slice_instruction_sites_defined':len(OPS),
             'second_slice_interpreter_runs':len(triples)*4,
             'second_slice_instruction_sites_reached':len(second_coverage),
             'second_slice_instruction_sites_defined':len(SECOND_OPS),
             'selected_conditional_branches':sum(map(len, BRANCHES.values())),
             'scope':'The limb equations assume an exact unsigned 128-bit quotient helper; no target code executed.'}
    (out/'summary.json').write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    build(Image(TARGET.read_bytes()),args.out)

if __name__=='__main__':
    main()
