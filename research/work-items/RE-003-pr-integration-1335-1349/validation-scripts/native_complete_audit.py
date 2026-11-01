import hashlib,json,pathlib,re,subprocess,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'));import elf_index,fde_extents
binary=r/'artifacts/node/94/hl-node';data=binary.read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f';secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);out=b/'native';out.mkdir(exist_ok=True);md=Cs(CS_ARCH_X86,CS_MODE_64);cache={}
def number(x):return int(x,16)if isinstance(x,str)else x

def walk(x,path=''):
 if isinstance(x,dict):
  yield path,x
  for k,v in x.items():yield from walk(v,path+'/'+k)
 elif isinstance(x,list):
  for i,v in enumerate(x):yield from walk(v,path+'/'+str(i))

def native(start,end):
 if (start,end)not in cache:
  s=next(s for s in secs if s['type']!=8 and s['address']<=start<end<=s['address']+s['size']);raw=data[s['offset']+start-s['address']:s['offset']+end-s['address']];rows={i.address:bytes(i.bytes)for i in md.disasm(raw,start)};assert b''.join(rows.values())==raw,(hex(start),'capstone gap')
  text=subprocess.check_output(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}','artifacts/node/94/hl-node'],text=True);gnu={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)};assert rows==gnu,(hex(start),'GNU mismatch');(out/f'{start:x}-{end:x}.txt').write_text(text);cache[start,end]=(hashlib.sha256(raw).hexdigest(),len(rows),hashlib.sha256(text.encode()).hexdigest())
 return cache[start,end]
cs=json.loads((b/'changes.json').read_text());cs['1348']=['A\tresearch/work-items/RE-004-pdi-display-decimals-94/evidence.json'];cs['1349']=['A\tresearch/work-items/RE-001-field-sum-94/records.json'];results=[]
for pr,paths in cs.items():
 if int(pr)in [1342,1345]:continue
 for p in [line.split('\t')[-1]for line in paths if line.endswith(('/records.json','/evidence.json','/inventory.json','/windows.json'))]:
  x=json.loads((r/p).read_text());ranges=[]
  for pointer,v in walk(x):
   start=v.get('start_va',v.get('start',v.get('address')));end=v.get('end_va_exclusive',v.get('end_va',v.get('end_exclusive',v.get('end'))));digest=next((v[k]for k in ('sha256','body_sha256','code_sha256')if k in v),None)
   if start is None or end is None or digest is None:continue
   try:start,end=number(start),number(end)
   except (ValueError,TypeError):continue
   if not isinstance(start,int)or not 0<end-start<100000 or start<0x100000:continue
   owners=[f for f in fdes if f['start']==start and f['end']==end]
   if not owners:continue
   actual,n,export=native(start,end);assert actual==digest,(p,pointer,'hash');ranges.append({'record':pointer,'start':hex(start),'end':hex(end),'bytes':end-start,'rows':n,'body_sha256':actual,'export_sha256':export})
  results.append({'pr':int(pr),'packet':p,'complete_fde_records':ranges});print(pr,p,len(ranges),flush=True)
(out/'result.json').write_text(json.dumps({'target_sha256':sha,'packets':results,'unique_ranges':len(cache),'unique_instruction_rows':sum(v[1]for v in cache.values()),'limits':'Complete declared FDE byte partitions only; no general CFG, ownership, call closure or runtime equivalence.'},indent=2)+'\n')
