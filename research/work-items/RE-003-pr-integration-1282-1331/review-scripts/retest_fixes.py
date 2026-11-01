import concurrent.futures,hashlib,json,os,pathlib,re,subprocess,sys,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';names=['test_bucket_guard_static.py','test_foundation_decimal_index_replace.py','test_foundation_recursive_destructor.py','test_foundation_compaction_stats.py','test_foundation_virtual_dispatch.py','test_abci_state_inventory.py','test_node94_weak_pidfd.py'];out=b/'retests';out.mkdir(exist_ok=True);results=[]
def run(name):
 start=time.monotonic();p=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p',name,'-v'],cwd=r,env=dict(os.environ,PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH']),capture_output=True);raw=p.stdout+p.stderr;(out/(name+'.log')).write_bytes(raw);match=re.search(rb'^Ran (\d+) tests? in',raw,re.M)
 return {'module':name,'returncode':p.returncode,'tests':int(match[1])if match else 0,'skips':0,'seconds':round(time.monotonic()-start,2),'source_sha256':hashlib.sha256((r/'tests'/name).read_bytes()).hexdigest(),'log_sha256':hashlib.sha256(raw).hexdigest()}
with concurrent.futures.ThreadPoolExecutor(max_workers=7)as ex:
 for x in ex.map(run,names):results.append(x);(b/'fix-retests.json').write_text(json.dumps(results,indent=2)+'\n');print(x['module'],x['returncode'],x['tests'],flush=True)
