import hashlib,json,pathlib
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';pairs=[('ema_fused_release_drift','RE-014-ema-fused-release-drift'),('aqav2_diagnostic_drift','RE-014-aqav2-diagnostic-drift'),('cache_publication_static','RE-002-node115-cache-publication'),('numeric_selector_static','RE-001-node115-numeric-selector'),('file_snapshot_localhost_gate','RE-012-file-snapshot-localhost-gate-94'),('evm_state_wire94','RE-009-evm-state-wire-94')];reports=[]
def diff(a,z,path=''):
 if type(a)!=type(z):return [path+':type']
 if isinstance(a,dict):
  ans=[]
  for k in set(a)|set(z):ans.extend([path+'/'+k+':missing']if k not in a or k not in z else diff(a[k],z[k],path+'/'+k))
  return ans
 if isinstance(a,list):
  if len(a)!=len(z):return [path+':length']
  return sum((diff(aa,zz,path+'/'+str(i))for i,(aa,zz)in enumerate(zip(a,z))),[])
 return []if a==z else [path]
for tool,packet in pairs:
 records=[]
 for fresh in sorted((b/'replayed'/tool).iterdir()):
  old=r/'research/work-items'/packet/fresh.name
  if not old.exists():old=r/'research/work-items'/packet/'objdump'/fresh.name
  x={'file':fresh.name,'retained_exists':old.exists(),'fresh_sha256':hashlib.sha256(fresh.read_bytes()).hexdigest()}
  if old.exists():
   x['equal']=fresh.read_bytes()==old.read_bytes()
   if not x['equal']and fresh.suffix=='.json':x['differences']=diff(json.loads(old.read_text()),json.loads(fresh.read_text()))
  records.append(x)
 reports.append({'tool':tool,'packet':packet,'files':records});print(tool,[(x['file'],x.get('equal'),x.get('differences',[])[:12])for x in records])
(b/'replay-comparisons.json').write_text(json.dumps(reports,indent=2)+'\n')
