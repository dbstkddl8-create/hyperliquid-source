import hashlib,json,pathlib,re,subprocess,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'));import elf_index,fde_extents
binary=r/'artifacts/node/94/hl-node';data=binary.read_bytes();sha=hashlib.sha256(data).hexdigest();assert sha=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f';secs=elf_index.sections(data);_,fdes=fde_extents.eh_frame_records(data,secs);out=b/'native-1350';out.mkdir(exist_ok=True);md=Cs(CS_ARCH_X86,CS_MODE_64);cache={}
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

p=r/'research/work-items/RE-007-size-decimal-update-94/evidence.json'
x=json.loads(p.read_text());records=[]
for v in x['functions']:
 start,end=number(v['start']),number(v['end'])
 assert any(f['start']==start and f['end']==end for f in fdes)
 digest,n,export=native(start,end)
 assert digest==v['sha256']
 records.append(dict(start=hex(start),end=hex(end),bytes=end-start,rows=n,body_sha256=digest,export_sha256=export))
(out/'result.json').write_text(json.dumps(dict(target_sha256=sha,functions=records,limits='Native FDE byte partitions only; no general CFG or runtime equivalence.'),indent=2)+'\n')
print(len(records),sum(v['bytes'] for v in records),sum(v['rows'] for v in records))
