#!/usr/bin/env python3
"""Read-only independent ELF proof coordinates; stdlib and native objdump only."""
from pathlib import Path
import hashlib, struct, json, subprocess, datetime, re

ROOT=Path('/tmp/hl-resume-20261101/source-peer')
TARGET=Path('/tmp/hl-resume-20261101/main/artifacts/node/94/hl-node')
raw=TARGET.read_bytes()
assert len(raw)==91774280
assert hashlib.sha256(raw).hexdigest()=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
assert raw[:6]==b'\x7fELF\x02\x01'
hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
shoff,shentsize,shnum,shstrndx=hdr[6],hdr[11],hdr[12],hdr[13]
assert shentsize==64
headers=[struct.unpack_from('<IIQQQQIIQQ',raw,shoff+i*shentsize) for i in range(shnum)]
ss=headers[shstrndx];names=raw[ss[4]:ss[4]+ss[5]]
secs={names[h[0]:].split(b'\0',1)[0].decode():h for h in headers}
def offset(va,size):
    found=[h[4]+va-h[3] for h in headers if h[1]!=8 and h[3]<=va and va+size<=h[3]+h[5]]
    assert len(found)==1,(hex(va),found)
    return found[0]
def at(va,size):
    o=offset(va,size);return raw[o:o+size]

# The exact observed CIE's zR augmentation supplies signed4 PC-relative code
# addresses and4-byte ranges. Reject any selected FDE using another CIE.
cieva=0xce1518
cieraw=bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
assert at(cieva,len(cieraw))==cieraw
eh=secs['.eh_frame'];cursor=0;fdes={}
while cursor<eh[5]:
    o=eh[4]+cursor;va=eh[3]+cursor
    length=struct.unpack_from('<I',raw,o)[0]
    if length==0: break
    assert length!=0xffffffff and length>=4 and cursor+length+4<=eh[5]
    pointer=struct.unpack_from('<I',raw,o+4)[0]
    if pointer and va+4-pointer==cieva:
        start=va+8+struct.unpack_from('<i',raw,o+8)[0]
        size=struct.unpack_from('<I',raw,o+12)[0]
        fdes[start]=(start+size,va,raw[o:o+4+length].hex())
    cursor+=4+length

specs=[('selector',0x14f7660,0x14f774b,63),('decimal',0x1570470,0x157062c,114),
       ('reader-u32',0x466d850,0x466d975,0),('reader-u64',0x466d980,0x466dabc,0),
       ('reader-error',0x466dac0,0x466dace,0)]
results=[]
for name,start,end,expected_rows in specs:
    assert fdes[start][0]==end
    body=at(start,end-start)
    bodypath=ROOT/(name+'.raw');bodypath.write_bytes(body)
    argv=['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16',f'--adjust-vma={start:#x}',str(bodypath)]
    process=subprocess.run(argv,check=True,capture_output=True)
    (ROOT/(name+'.objdump.txt')).write_bytes(process.stdout)
    (ROOT/(name+'.objdump.stderr')).write_bytes(process.stderr)
    rows=[]
    for line in process.stdout.decode().splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
        if match:rows.append((int(match[1],16),bytes.fromhex(match[2])))
    assert b''.join(b for _,b in rows)==body
    assert rows[0][0]==start and rows[-1][0]+len(rows[-1][1])==end
    for (a,b),(c,_) in zip(rows,rows[1:]): assert a+len(b)==c
    if expected_rows:assert len(rows)==expected_rows
    results.append({'name':name,'start':hex(start),'end':hex(end),'file_offset':hex(offset(start,end-start)),
                    'bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'rows':len(rows),
                    'FDE_VA':hex(fdes[start][1]),'FDE_raw':fdes[start][2],
                    'objdump_sha256':hashlib.sha256(process.stdout).hexdigest(),'argv':argv,'stderr_bytes':len(process.stderr)})

assert sum(x['bytes'] for x in results if x['name'].startswith('reader-'))==623
assert sum(x['rows'] for x in results if x['name'].startswith('reader-'))==188
assert results[0]['body_sha256']=='a75d854d6221139a2355ae4d87451bf768029a2879b92e915213b41acc7526bf'
assert results[1]['body_sha256']=='bfb36d8c87aa851a74c630c9c02413d987ad0a348cd1e8cd5655c44b089bde3f'

# Real data and jump-table destinations; no inferred labels/code are executed.
tables={}
for name,va,expected in [('lower',0x208620,b'0123456789abcdef'),('upper',0x203830,b'0123456789ABCDEF'),('prefix',0x252bed,b'0x')]:
    assert at(va,len(expected))==expected
    tables[name]={'va':hex(va),'raw':expected.hex()}
tables['reader-u32']={'va':'0x6f6ec8','targets':[]}
tables['reader-u64']={'va':'0x6f6ed8','targets':[]}
for name,va,expected in [('reader-u32',0x6f6ec8,[0x466d8b7,0x466d8c4,0x466d945,0x466d92d]),('reader-u64',0x6f6ed8,[0x466d9e7,0x466da01,0x466d9f4,0x466da8c])]:
    targets=[va+x for x in struct.unpack('<iiii',at(va,16))]
    assert targets==expected
    tables[name]['raw']=at(va,16).hex();tables[name]['targets']=[hex(x) for x in targets]

rela=secs['.rela.dyn'];relocations={}
expected_relas={0x566fb18:0x14f7660,0x576e2d8:0x15723b0,0x57745e8:0x466dac0,
                0x5775138:0x466d850,0x57745e0:0x466d980}
for o in range(rela[4],rela[4]+rela[5],24):
    slot,info,addend=struct.unpack_from('<QQq',raw,o)
    if slot in expected_relas:
        assert info==8 and addend==expected_relas[slot]
        relocations[hex(slot)]={'addend':hex(addend),'info':info,'file_offset':hex(o),'raw':raw[o:o+24].hex()}
assert len(relocations)==len(expected_relas)

result={'schema':'independent-selector-reader-native-review/1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'target_sha256':hashlib.sha256(raw).hexdigest(),'target_bytes':len(raw),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'profiles':'GNU bounded raw disassembly, complete bytes and FDE/actual data/RELA checks; no REA/Ghidra profile claimed',
        'objdump_version':subprocess.run(['objdump','--version'],check=True,capture_output=True).stdout.decode().splitlines()[0],
        'functions':results,'tables':tables,'relocations':relocations,
        'source_or_target_execution':False,'repository_modules_imported':False,'PC_register_opcode_evaluation':False}
path=ROOT/'NATIVE-REVIEW.json';path.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({'receipt_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'functions':[{k:x[k] for k in ['name','bytes','rows','body_sha256']} for x in results]},sort_keys=True))
