from pathlib import Path
import subprocess,os,json,time,hashlib
B=Path('/tmp/hl-resume-20261101/formatter');O=B.parent/'formatter-static-fcbabe7c';O.mkdir(exist_ok=False)
def git(p,*a):return subprocess.check_output(['git','-C',str(p),*a],text=True).strip()
pins=json.loads((B/'provenance/sources.json').read_text())['repositories']
def audit():
 files={}
 for s in git(B,'ls-files','-z').split('\0'):
  if s:
   p=B/s
   if p.is_file() and not p.is_symlink():
    h=hashlib.sha256()
    with p.open('rb') as f:
     for z in iter(lambda:f.read(1<<20),b''):h.update(z)
    st=p.stat();files[s]={'sha256':h.hexdigest(),'bytes':st.st_size,'mode':st.st_mode,'mtime_ns':st.st_mtime_ns}
 return {'head':git(B,'rev-parse','HEAD'),'tree':git(B,'rev-parse','HEAD^{tree}'),'status':git(B,'status','--porcelain','--untracked-files=all'),'pins':[{**r,'actual':git(B/r['path'],'rev-parse','HEAD'),'status':git(B/r['path'],'status','--porcelain','--untracked-files=all')} for r in pins],'files':files}
before=audit()
if before['head']!='fcbabe7c5cb9ed27adddba18c19f200819ecc408' or before['status'] or any(r['status'] or r['actual']!=r['commit'] for r in before['pins']):raise ValueError('exact head, clean status or actual pins mismatch')
(O/'BEFORE.json').write_text(json.dumps(before,sort_keys=True)+'\n')
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',TMPDIR='/tmp/hv')
rows=[]
for target in ['doctor','verify','catalogue-check','reproduce']:
 t=time.monotonic();argv=['make','-j1','PYTHON=python3 -B',target]
 with (O/(target+'.stdout')).open('wb') as so,(O/(target+'.stderr')).open('wb') as se:
  p=subprocess.run(argv,cwd=B,env=env,stdout=so,stderr=se)
 rows.append({'target':target,'argv':argv,'exit':p.returncode,'seconds':time.monotonic()-t,'stdout_sha256':hashlib.sha256((O/(target+'.stdout')).read_bytes()).hexdigest(),'stderr_sha256':hashlib.sha256((O/(target+'.stderr')).read_bytes()).hexdigest()})
 print(json.dumps(rows[-1]),flush=True)
 if p.returncode:break
after=audit();(O/'AFTER.json').write_text(json.dumps(after,sort_keys=True)+'\n')
r={'commands':rows,'same_inputs':before==after,'tracked_physical_inputs':len(before['files']),'head':before['head'],'tree':before['tree'],'pins':before['pins'],'full_test':'NOT_RUN pending expanded evaluator authorization','status':'PASS' if len(rows)==4 and all(x['exit']==0 for x in rows) and before==after else 'FAIL'}
(O/'RESULT.json').write_text(json.dumps(r,sort_keys=True,indent=2)+'\n');print(json.dumps(r),flush=True)
if r['status']!='PASS':raise SystemExit(1)
