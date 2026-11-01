# Exact Python stdin text used for the observed four-static-check experiment.
# This retained copy was added after that run; it is not a second execution.
from pathlib import Path
import sys,json,subprocess,os,hashlib,shutil,time
root=Path.cwd();sys.path.insert(0,str(root/'tools'))
import numeric_selector_rust as own
p=root/'work/numeric-selector-static-first';p.mkdir()
provider_path=Path('/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json')
provider=json.loads(provider_path.read_text());prefix=Path('/tmp/hl-resume-20261101/toolchain/prefix')
cc=Path(shutil.which('cc')).resolve();ld=Path(shutil.which('ld.bfd')).resolve()
before=own.audit(prefix,provider,provider_path,cc,ld)
(p/'BEFORE.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
calls=[]
for target in ('doctor','verify','catalogue-check','reproduce'):
    argv=['make','-j1','PYTHON=python3 -B',target];start=time.monotonic()
    r=subprocess.run(argv,cwd=root,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdin=subprocess.DEVNULL,capture_output=True)
    streams={}
    for kind,data in (('stdout',r.stdout),('stderr',r.stderr)):
        name=target+'.'+kind;(p/name).write_bytes(data)
        streams[kind]={'file':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    calls.append({'argv':argv,'cwd':str(root),'exit_code':r.returncode,'seconds':round(time.monotonic()-start,3),'streams':streams})
    (p/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n')
    if r.returncode:
        raise SystemExit(target+' failed; exact streams retained')
after=own.audit(prefix,provider,provider_path,cc,ld)
(p/'AFTER.json').write_text(json.dumps(after,indent=2,sort_keys=True)+'\n')
assert before==after,'Real tracked/source/corpus/pins/provider/linker/head/status changed'
result={'status':'PASS','source_head':before['head'],'source_tree':before['tree'],'physical_input_count':before['physical_file_count'],'pins':len(before['pins']),'provider_payloads':len(before['provider_payloads']),'before_after_identical':True,'full_current_suite':'NOT_RUN','calls':calls}
(p/'RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True))
