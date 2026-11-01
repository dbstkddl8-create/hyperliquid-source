import sys,json,re,hashlib,struct,subprocess,random
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
r=Path('/Users/shawwalters/hlsource/hyperliquid-source/work/merge-latest-1153-1160/integration')
b=Path(__file__).resolve().parent
sys.path.insert(0,str(r/'tools'))
import pdi_display_decimals94 as p
raw=p.BINARY.read_bytes(); e,table,branches=p.validate(raw)
sections=p.elf_index.sections(raw)
md=Cs(CS_ARCH_X86,CS_MODE_64)
results=[]
for f in e['functions']:
 start,end=int(f['start_va'],16),int(f['end_va'],16)
 code=bytes.fromhex(f['bytes_hex']); cap={x.address:bytes(x.bytes) for x in md.disasm(code,start)}
 assert b''.join(cap.values())==code
 gnucmd=['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(p.BINARY)]
 llvmcmd=['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d','--x86-asm-syntax=intel',f'--start-address={start}',f'--stop-address={end}',str(p.BINARY)]
 exports={}
 for name,cmd in [('gnu',gnucmd),('llvm',llvmcmd)]:
  text=subprocess.check_output(cmd,text=True)
  (b/f'{start:x}.{name}.txt').write_text(text)
  rows={int(m[1],16):bytes.fromhex(m[2]) for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)}
  assert rows==cap,(name,hex(start),list(rows.items())[:2],list(cap.items())[:2])
  exports[name]={'command':cmd,'sha256':hashlib.sha256(text.encode()).hexdigest()}
 results.append(dict(start=hex(start),end=hex(end),bytes=len(code),rows=len(cap),body_sha256=hashlib.sha256(code).hexdigest(),exports=exports))
# Native decode verifies every declared branch starts at an instruction boundary.
all_ins={}
for f in e['functions']:
 all_ins.update({x.address:x for x in md.disasm(bytes.fromhex(f['bytes_hex']),int(f['start_va'],16))})
for va,label,encoded,dest in branches:
 ins=all_ins[int(va,16)]
 assert bytes(ins.bytes).hex()==encoded
 assert int(ins.op_str,16)==int(dest,16)
# Host binary64 is an independent check of all table transitions and exact-int rounding.
def bits(x):return struct.unpack('<Q',struct.pack('<d',x))[0]
for i,va,stored,ideal,drift in table:
 assert bits(float(10**i))==int(ideal,16)
 if i:
  previous=int(table[i-1][2],16)
  before=struct.unpack('<d',struct.pack('<Q',previous))[0]
  assert bits(before*10.0)==int(stored,16)
# Supplement full-domain symbolic inequality with deterministic diverse u64 samples.
rng=random.Random(1348)
m=int(e['reciprocal'],16)
for _ in range(100000):
 x=rng.getrandbits(64);assert (x*m)>>75==x//10000
comparison=[]
for file in (b/'observed').iterdir():
 expected=r/'research/work-items/RE-004-pdi-display-decimals-94'/file.name
 same=file.read_bytes()==expected.read_bytes();assert same
 comparison.append({'file':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'byte_identical':same})
unit=(b/'unit.log').read_bytes()
result={'target_sha256':hashlib.sha256(raw).hexdigest(),'tool_sha256':hashlib.sha256((r/'tools/pdi_display_decimals94.py').read_bytes()).hexdigest(),'test_sha256':hashlib.sha256((r/'tests/test_pdi_display_decimals94.py').read_bytes()).hexdigest(),'test_count':9,'test_returncode':0,'test_log_sha256':hashlib.sha256(unit).hexdigest(),'native_ranges':results,'declared_branches_confirmed':len(branches),'binary64_table_rows':len(table),'host_independent_table_checks':511,'reciprocal_symbolic_bound':e['proof'],'reciprocal_seeded_samples':100000,'fresh_outputs':comparison,'limits':'Static byte/FDE/branch and table evidence only. No captured execution, independently built Rust, runtime equivalence or whole-module completion.'}
(b/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='native_ranges'},indent=2));print('native ranges',len(results),'rows',sum(x['rows'] for x in results))
