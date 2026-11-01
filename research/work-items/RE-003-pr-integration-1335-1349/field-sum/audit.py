import sys,json,re,hashlib,subprocess
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
r=Path('/Users/shawwalters/hlsource/hyperliquid-source/work/merge-latest-1153-1160/integration')
b=Path(__file__).resolve().parent
sys.path.insert(0,str(r/'tools'))
import elf_index,fde_extents
raw=(r/'artifacts/node/94/hl-node').read_bytes();sha=hashlib.sha256(raw).hexdigest();assert sha=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
packet=r/'research/work-items/RE-001-field-sum-94'
e=json.loads((packet/'records.json').read_text())
sections=elf_index.sections(raw);_,fdes=fde_extents.eh_frame_records(raw,sections)
md=Cs(CS_ARCH_X86,CS_MODE_64);results=[];all_ins={}
for role in ['function','callee']:
 f=e[role];start,end=int(f['start_va'],16),int(f['end_va_exclusive'],16)
 assert any(v['start']==start and v['end']==end for v in fdes)
 s=next(s for s in sections if s['address']<=start<end<=s['address']+s['size']);off=s['offset']+start-s['address'];code=raw[off:off+end-start]
 assert hashlib.sha256(code).hexdigest()==f['sha256'];cap={x.address:bytes(x.bytes) for x in md.disasm(code,start)}
 all_ins.update({x.address:x for x in md.disasm(code,start)})
 assert b''.join(cap.values())==code
 gnucmd=['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(r/'artifacts/node/94/hl-node')]
 llvmcmd=['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d','--x86-asm-syntax=intel',f'--start-address={start}',f'--stop-address={end}',str(r/'artifacts/node/94/hl-node')]
 exports={}
 for name,cmd in [('gnu',gnucmd),('llvm',llvmcmd)]:
  text=subprocess.check_output(cmd,text=True);(b/f'{start:x}.{name}.txt').write_text(text)
  rows={int(m[1],16):bytes.fromhex(m[2]) for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)}
  assert rows==cap,(name,hex(start))
  exports[name]={'command':cmd,'sha256':hashlib.sha256(text.encode()).hexdigest()}
 results.append(dict(role=role,start=hex(start),end=hex(end),bytes=len(code),rows=len(cap),body_sha256=hashlib.sha256(code).hexdigest(),exports=exports))
for v in e['branches']+e['calls']:
 ins=all_ins[int(v['site'],16)];assert int(ins.op_str,16)==int(v['target'],16)
# Function end is followed by eight int3 bytes, not part of the function.
f=e['function'];end=int(f['end_va_exclusive'],16);s=next(s for s in sections if s['address']<=end<s['address']+s['size']);off=s['offset']+end-s['address'];assert raw[off:off+8]==b'\xcc'*8
manifest=[]
for line in (packet/'MANIFEST.sha256').read_text().splitlines():
 digest,name=line.split(None,1);assert hashlib.sha256((packet/name).read_bytes()).hexdigest()==digest;manifest.append(name)
# Explicitly bind the discarded return and independent field accumulator.
assert all_ins[0x514bd12].mnemonic=='call'
assert all_ins[0x514bd17].mnemonic=='mov' and all_ins[0x514bd17].op_str=='rax, qword ptr [rbx - 0x10]'
assert all_ins[0x514bd1b].mnemonic=='add' and all_ins[0x514bd1b].op_str=='rbp, qword ptr [rax + 0x50]'
result={'target_sha256':sha,'tool_sha256':hashlib.sha256((r/'tools/foundation_field_sum.py').read_bytes()).hexdigest(),'test_sha256':hashlib.sha256((r/'tests/test_foundation_field_sum.py').read_bytes()).hexdigest(),'original_test_sha256':hashlib.sha256((b/'original-test.py').read_bytes()).hexdigest(),'test_count':15,'test_returncode':0,'test_log_sha256':None,'initial_test_count':15,'initial_failures':5,'initial_log_sha256':hashlib.sha256((b/'initial-unit.log').read_bytes()).hexdigest(),'native_ranges':results,'branch_records_confirmed':2,'call_records_confirmed':1,'manifest_files':manifest,'observations':['Two full authenticated FDEs; function padding checked separately.','The call at 0x514bd12 targets 0x5032f40; next instruction reloads rax from entry, discarding the return before adding slot+0x50.','Empty range stores zero; 16-byte stride; qword wrapping accumulator; success return 1.'],'test_fix':'Canonical artifact path; excerpt regeneration in copied temporary packet, compares ordered instruction addresses and raw bytes; checks original files remain unchanged.','limits':'Static evidence and Python projection; no captured execution, Rust build, runtime equivalence or component completion credit.'}
(b/'native-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS',len(results),'FDEs',sum(x['bytes'] for x in results),'bytes',sum(x['rows'] for x in results),'rows',len(manifest),'manifest files')

unit=(b/'unit.log').read_bytes()
assert re.search(rb"Ran 15 tests in [0-9.]+s",unit) and unit.rstrip().endswith(b"OK")
result.update(status='PASS',test_count=15,test_returncode=0,test_log_sha256=hashlib.sha256(unit).hexdigest(),skips=0,
 test_command=['/opt/miniconda3/bin/python3','-m','unittest','discover','-s','tests','-p','test_foundation_field_sum.py','-v'],
 cwd=str(r),path_prefix=['/opt/homebrew/opt/binutils/bin','/opt/homebrew/opt/llvm/bin'],
 native_versions={'gnu':'2.47.20260726','llvm':'22.1.4','capstone':'5.0.7'},
 packet_modified=False,imported_artifacts_modified=False)
(b/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
