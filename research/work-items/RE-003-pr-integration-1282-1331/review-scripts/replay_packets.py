import concurrent.futures,hashlib,json,os,pathlib,subprocess,sys,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';out=b/'replayed';out.mkdir(exist_ok=True)
jobs=[('ema_fused_release_drift','--output'),('aqav2_diagnostic_drift','--output'),('cache_publication_static','--output'),('numeric_selector_static','--output'),('file_snapshot_localhost_gate','--out'),('evm_state_wire94','--out')];results=[]
def run(j):
 name,arg=j;cmd=[sys.executable,f'tools/{name}.py',arg,str(out/name)];log=b/(name+'-replay.log');start=time.monotonic()
 with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,env=dict(os.environ,PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH']),stdout=h,stderr=subprocess.STDOUT)
 return {'tool':name,'command':cmd,'returncode':p.returncode,'seconds':round(time.monotonic()-start,3),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:
 for x in pool.map(run,jobs):results.append(x);(b/'packet-replays.json').write_text(json.dumps(results,indent=2)+'\n');print(x['tool'],x['returncode'],flush=True)
