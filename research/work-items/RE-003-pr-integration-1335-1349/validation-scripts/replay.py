import concurrent.futures,hashlib,json,os,pathlib,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';jobs=['gossip_rpc_client_inventory','positive_risk_scan94','risk_size_allowance94','bole_scaled_exposure94','lthash_read94','staking_validator_vote_prune94'];records=[]
def run(name):
 out=b/'replayed'/name;out.parent.mkdir(exist_ok=True);log=b/(name+'.log');cmd=[sys.executable,f'tools/{name}.py','--out',str(out)]
 with log.open('wb')as h:p=subprocess.run(cmd,cwd=r,stdout=h,stderr=subprocess.STDOUT)
 return {'tool':name,'command':cmd,'returncode':p.returncode,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
with concurrent.futures.ThreadPoolExecutor(max_workers=6)as pool:
 for x in pool.map(run,jobs):records.append(x);(b/'replay.json').write_text(json.dumps(records,indent=2)+'\n');print(x['tool'],x['returncode'],flush=True)
