from pathlib import Path
import subprocess,os,json,hashlib,concurrent.futures
R=Path('/Users/shawwalters/hlsource/hyperliquid-source/work/merge-latest-1153-1160/integration')
P=R/'research/work-items/RE-013-visor-shell-nul-admission'
B=Path(__file__).resolve().parent
PY='/opt/miniconda3/bin/python3'
env=os.environ.copy(); env.update(GNU_OBJDUMP='/opt/homebrew/opt/binutils/bin/gobjdump',GNU_READELF='/opt/homebrew/opt/binutils/bin/greadelf',LLVM_OBJDUMP='/opt/homebrew/opt/llvm/bin/llvm-objdump')
manifest=[]
for line in (P/'MANIFEST.sha256').read_text().splitlines():
 h,n=line.split(None,1); p=P/n; got=hashlib.sha256(p.read_bytes()).hexdigest(); assert h==got,n
 manifest.append({'path':n,'sha256':h})
(B/'manifest-check.json').write_text(json.dumps({'files':len(manifest),'records':manifest},indent=2)+'\n')
def run(name,script,args,opt=False):
 cmd=[PY]+(['-O'] if opt else [])+['-B',str(P/script),'--binary',str(R/'artifacts/visor/captured/hl-visor')]+list(map(str,args))
 out=subprocess.run(cmd,env=env,cwd=R,capture_output=True,text=True)
 (B/(name+'.log')).write_text(out.stdout+out.stderr)
 result={'name':name,'command':cmd,'returncode':out.returncode,'logSha256':hashlib.sha256((out.stdout+out.stderr).encode()).hexdigest()}
 print(name,out.returncode,flush=True); return result
records=[run('survey','survey.py',['--output',B/'observed'])]
if records[0]['returncode']:
 (B/'results.json').write_text(json.dumps(records,indent=2)); raise SystemExit(1)
tasks=[('survey-optimized','survey.py',['--output',B/'observed-optimized'],True),('verify','verify.py',['--records',B/'observed','--receipt',B/'verify.json'],False),('verify-optimized','verify.py',['--records',B/'observed','--receipt',B/'verify-optimized.json'],True),('llvm','crosscheck_llvm.py',['--output',B/'llvm'],False),('llvm-optimized','crosscheck_llvm.py',['--output',B/'llvm-optimized'],True),('algebra','check_algebra.py',['--receipt',B/'algebra.json'],False),('algebra-optimized','check_algebra.py',['--receipt',B/'algebra-optimized.json'],True)]
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
 records+=list(pool.map(lambda t:run(*t),tasks))
(B/'results.json').write_text(json.dumps(records,indent=2)+'\n')
assert all(x['returncode']==0 for x in records)
assert (B/'verify.json').read_bytes()==(B/'verify-optimized.json').read_bytes()
assert (B/'algebra.json').read_bytes()==(B/'algebra-optimized.json').read_bytes()
for source,other in [('observed','observed-optimized'),('llvm','llvm-optimized')]:
 for p in (B/source).rglob('*'):
  if p.is_file(): assert p.read_bytes()==(B/other/p.relative_to(B/source)).read_bytes(),p
old=json.loads((P/'observed/summary.json').read_text()); new=json.loads((B/'observed/summary.json').read_text())
def facts(v):
 if isinstance(v,dict):return {k:facts(w) for k,w in v.items() if k not in ['versions','instruction']}
 if isinstance(v,list):return [facts(x) for x in v]
 return v
assert facts(old)==facts(new)
different=[]; equal=[]
for p in (P/'observed').rglob('*'):
 if p.is_file():
  dest=(B/'observed'/p.relative_to(P/'observed'))
  (equal if p.read_bytes()==dest.read_bytes() else different).append(p.relative_to(P/'observed').as_posix())
report={'status':'PASS','manifestFiles':len(manifest),'normalOptimizedEqual':True,'targetFactsEqualExcludingVersionsAndInstructionText':True,'retainedVersions':old['versions'],'freshVersions':new['versions'],'equalFiles':equal,'differentFiles':different,'admittedAdaptation':'No scripts changed. Original scripts permit installed providers. Verify compared two fresh regenerations to the fresh provider-specific observed records; retained target facts compared separately, preserving VA/raw-byte partitions.','instructionRows':new['instructionRows'],'rangeBytes':new['rangeBytes']}
(B/'review.json').write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps(report),flush=True)
