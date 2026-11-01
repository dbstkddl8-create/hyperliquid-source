import json,hashlib,re,subprocess,sys,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
r=Path('/Users/shawwalters/hlsource/hyperliquid-source/work/merge-latest-1153-1160/integration')
b=Path(__file__).resolve().parent;p=r/'research/work-items/foundation-span-count-94'
sys.path.insert(0,str(r/'tools'));import elf_index,fde_extents
raw=(r/'artifacts/node/94/hl-node').read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
e=json.loads((p/'evidence.json').read_text());secs=elf_index.sections(raw);_,fdes=fde_extents.eh_frame_records(raw,secs);frame=next(s for s in secs if s['name']=='.eh_frame')
by_start={f['start']:f for f in fdes};md=Cs(CS_ARCH_X86,CS_MODE_64);ranges=[]
for key in ['function','callee','jump_target']:
 v=e[key];start,end=int(v['start_va'],16),int(v['end_va_exclusive'],16);f=by_start[start];assert f['end']==end;assert f['fde']-frame['address']==int(v['fde_section_offset'],16);assert f['cie']-frame['address']==int(v['fde_cie'],16)
 s=next(s for s in secs if s['address']<=start<end<=s['address']+s['size']);offset=s['offset']+start-s['address'];code=raw[offset:offset+end-start];digest=hashlib.sha256(code).hexdigest();assert len(code)==v['bytes']
 if 'sha256' in v:assert digest==v['sha256']
 rows={i.address:bytes(i.bytes) for i in md.disasm(code,start)};assert b''.join(rows.values())==code
 exports={}
 for tool in ['gnu','llvm']:
  cmd=(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16'] if tool=='gnu' else ['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d','--x86-asm-syntax=intel'])+[f'--start-address={start}',f'--stop-address={end}',str(r/'artifacts/node/94/hl-node')]
  text=subprocess.check_output(cmd,text=True);(b/f'{key}.{tool}.txt').write_text(text)
  decoded={int(m[1],16):bytes.fromhex(m[2]) for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)}
  standalone_lock_rows=[]
  if tool=='llvm':
   for address in list(decoded):
    if decoded.get(address)==b'\xf0':
     assert address+1 in decoded
     standalone_lock_rows.append(hex(address))
     decoded[address]+=decoded.pop(address+1)
  assert decoded==rows,(key,tool)

  exports[tool]={'command':cmd,'sha256':hashlib.sha256(text.encode()).hexdigest(),'standalone_lock_rows_coalesced':standalone_lock_rows}
 ranges.append({'role':key,'start':hex(start),'end':hex(end),'bytes':len(code),'rows':len(rows),'sha256':digest,'exports':exports})
 if key in ['function','callee']:
  assert raw[offset+len(code):offset+len(code)+v['padding_bytes']]==b'\xcc'*v['padding_bytes']
  n=by_start[int(v['next_fde_start'],16)];assert n['fde']-frame['address']==int(v['next_fde_section_offset'],16);assert n['cie']-frame['address']==int(v['next_fde_cie'],16)
textsec=next(s for s in secs if s['name']=='.text');text=raw[textsec['offset']:textsec['offset']+textsec['size']]
callers={0x53c7490:[],0x53c6e80:[]};i=0
while True:
 i=text.find(b'\xe8',i)
 if i<0:break
 if i+5<=len(text):
  va=textsec['address']+i;target=va+5+struct.unpack_from('<i',text,i+1)[0]
  if target in callers:callers[target].append(va)
 i+=1
assert callers[0x53c7490]==[]
assert callers[0x53c6e80]==[0x53c7478,0x53c7498,0x53c74ee]
manifest=[]
for line in (p/'MANIFEST.sha256').read_text().splitlines():
 digest,name=line.split(None,1);assert hashlib.sha256((p/name).read_bytes()).hexdigest()==digest;manifest.append({'file':name,'sha256':digest})
unit=(b/'unit.log').read_bytes();assert re.search(rb'Ran 26 tests in [0-9.]+s',unit) and b'\nOK\n' in unit
receipt={'status':'PASS','target_sha256':sha,'test_count':26,'test_returncode':0,'skips':0,'test_sha256':hashlib.sha256((r/'tests/test_foundation_span_count.py').read_bytes()).hexdigest(),'test_log_sha256':hashlib.sha256(unit).hexdigest(),'tool_sha256':hashlib.sha256((r/'tools/foundation_span_count.py').read_bytes()).hexdigest(),'test_command':['/opt/miniconda3/bin/python3','-m','unittest','discover','-s','tests','-p','test_foundation_span_count.py','-v'],'cwd':str(r),'native_ranges':ranges,'fde_associations_verified':5,'manifest_files':manifest,'native_partition_note':'GNU/Capstone partitions match exactly; LLVM prints two lock prefixes as standalone rows at 0x53c73d3 and 0x53c73f3, coalesced only with the contiguous instruction. All raw bytes unchanged.', 'raw_e8_candidates':{hex(k):[hex(x) for x in v] for k,v in callers.items()},'original_test_count':24,'original_test_result':'PASS, but existing-offset swap wrongly accepted','initial_counterexample':'initial-swapped-frame.log','fix':'Bind offset/CIE/start/end in one retained row and to shared-parser records from the authenticated ELF; add existing offset and CIE swap rejection tests. Remove unsupported corpus uniqueness/similarity assertions. Model inputs explicitly post-callee; endpoint side effects excluded.','limits':'Native body partitions and bounded arithmetic only; endpoint semantics, full xrefs, reconstructed Rust and binary equivalence remain open. No component completion credit.'}
(b/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print('PASS',len(ranges),'ranges',sum(x['bytes'] for x in ranges),'bytes',sum(x['rows'] for x in ranges),'rows',receipt['test_count'],'tests')
