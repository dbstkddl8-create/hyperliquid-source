import concurrent.futures,hashlib,json,os,pathlib,subprocess,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';rustc=subprocess.check_output(['rustup','which','--toolchain','1.94.1','rustc'],text=True).strip();python='/opt/miniconda3/bin/python3';target=str(r/'artifacts/node/94/hl-node')
jobs=[]
for n in ['limb_fold','wide_subtract','keyed_mix','mix_div61']:
 jobs.append((n,[python,f'tools/{n}_rust.py','--binary',target,'--rustc',rustc,'--output',str(b/'rust'/n)]))
jobs.append(('roundup',[python,'tools/roundup_rust.py','--binary',target,'--rustc',rustc,'--output-dir',str(b/'rust/roundup')]))
for n in ['wire_qty','bincode_reader','decimal_scaled']:
 jobs.append((n,[python,f'tools/{n}_rust.py','--rustc',rustc,'--output',str(b/'rust'/n),'--controls']))
results=[]
def run(job):
 name,cmd=job;log=b/f'{name}-rust.log';start=time.monotonic()
 with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,env=dict(os.environ,PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH']),stdout=h,stderr=subprocess.STDOUT)
 return {'name':name,'command':cmd,'returncode':p.returncode,'seconds':round(time.monotonic()-start,2),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as ex:
 for x in ex.map(run,jobs):results.append(x);(b/'rust-checks.json').write_text(json.dumps(results,indent=2)+'\n');print(x['name'],x['returncode'],x['seconds'],flush=True)
raise SystemExit(any(x['returncode']for x in results))
