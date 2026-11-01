import bisect,hashlib,json,pathlib,re,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import elf_index,fde_extents
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
data=(r/'artifacts/node/94/hl-node').read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f';secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);fdes=sorted(fdes,key=lambda f:f['start']);starts=[f['start']for f in fdes];md=Cs(CS_ARCH_X86,CS_MODE_64);out=b/'foundation-native';out.mkdir(exist_ok=True);cache={};issues=[]
def number(v):return int(v,16)if isinstance(v,str)else v

def read(start,size):
 matches=[s for s in secs if s['type']!=8 and s['address']<=start and start+size<=s['address']+s['size']];assert len(matches)==1,(hex(start),size);s=matches[0];off=s['offset']+start-s['address'];return data[off:off+size]
def owner(va):
 i=bisect.bisect_right(starts,va)-1;f=fdes[i];assert f['start']<=va<f['end'],hex(va);return f

def decode(start,end):
 if (start,end)not in cache:
  raw=read(start,end-start);rows={i.address:bytes(i.bytes)for i in md.disasm(raw,start)};assert b''.join(rows.values())==raw,(hex(start),'capstone gap')
  text=subprocess.check_output(['/opt/homebrew/Cellar/binutils/2.47/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start}',f'--stop-address={end}',str(r/'artifacts/node/94/hl-node')],text=True);(out/f'{start:x}-{end:x}.txt').write_text(text);gnu={int(m[1],16):bytes.fromhex(m[2])for m in re.finditer(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S+',text,re.M)};assert gnu==rows,(hex(start),'GNU/Capstone disagreement');cache[start,end]=(rows,hashlib.sha256(text.encode()).hexdigest())
 return cache[start,end]
def walk(x,path=''):
 if isinstance(x,dict):
  yield path,x
  for k,v in x.items():yield from walk(v,path+'/'+k)
 elif isinstance(x,list):
  for i,v in enumerate(x):yield from walk(v,path+'/'+str(i))
changes=json.loads((b/'full-file-changes.json').read_text());reports=[]
for pr,paths in changes.items():
 for path in [x.split('\t')[-1]for x in paths if ('/foundation-'in x or '/RE-001-recursive-destructor-'in x or '/RE-001-string-ctor-cstr-'in x)and x.endswith(('evidence.json','records.json'))]:
  x=json.loads((r/path).read_text());spans=[];ins=0
  for p,v in walk(x):
   start=v.get('start_va',v.get('start',v.get('address')));end=v.get('end_va_exclusive',v.get('end'))
   if start is not None and end is not None and 'sha256'in v:
    try:start,end=number(start),number(end)
    except (ValueError,TypeError):continue
    if not isinstance(start,int)or not 0<end-start<200000:continue
    f=owner(start);assert (f['start'],f['end'])==(start,end),(path,p,'FDE mismatch');rows,export=decode(start,end);assert hashlib.sha256(read(start,end-start)).hexdigest()==v['sha256'],(path,p,'body hash')
    spans.append({'record':p,'start':hex(start),'end':hex(end),'instruction_rows':len(rows),'body_sha256':v['sha256'],'export_sha256':export})
  for p,v in walk(x):
   va=v.get('va',v.get('address'));raw=v.get('bytes')
   if not isinstance(raw,str)or va is None or not re.fullmatch(r'(?:[0-9a-fA-F]{2})+',raw):continue
   try:va=number(va);f=owner(va)
   except (ValueError,TypeError,AssertionError):continue
   rows,_=decode(f['start'],f['end']);raw=bytes.fromhex(raw);assert read(va,len(raw))==raw,(path,p,'instruction bytes');assert va in rows,(path,p,'not native instruction start')
   cursor=va
   while cursor<va+len(raw):cursor+=len(rows[cursor])
   if cursor!=va+len(raw):issues.append({'packet':path,'record':p,'va':hex(va),'reason':'record ends inside a native instruction','record_bytes':len(raw)})
   ins+=1
  reports.append({'pr':int(pr),'packet':path,'declared_complete_fdes':spans,'instruction_records_checked':ins});print(pr,path,'FDEs',len(spans),'instruction records',ins,flush=True)
summary={'target_sha256':sha,'capstone_version':__import__('capstone').__version__,'packets':reports,'unique_native_exports':len(cache),'unique_native_instruction_rows':sum(len(v[0])for v in cache.values()),'issues':issues,'limits':'Ranges and instruction starts/byte partitions only; no callee semantics, runtime reachability, ABI or target/source equivalence.'};(out/'result.json').write_text(json.dumps(summary,indent=2)+'\n');print('issues',len(issues));assert not issues
