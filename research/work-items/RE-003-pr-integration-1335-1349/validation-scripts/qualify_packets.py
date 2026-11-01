import concurrent.futures,hashlib,json,os,pathlib,subprocess,sys
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';binary=r/'artifacts/visor/captured/hl-visor';env=dict(os.environ,PATH='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/llvm/bin:'+os.environ['PATH']);results=[]
def command(label,cmd):
 p=subprocess.run(list(map(str,cmd)),cwd=r,env=env,capture_output=True);(b/(label+'.log')).write_bytes(p.stdout+p.stderr);assert p.returncode==0,(label,(p.stdout+p.stderr)[-1000:]);return p.stdout

def qualify(kind):
 if kind=='ceil':
  path=r/'research/work-items/RE-001-ceil-f64-94/verify.py'
  for mode in ([],['-O']):command('ceil-'+('optimized'if mode else 'normal'),[sys.executable,*mode,path])
  return {'packet':'ceil','normal_and_optimized':True}
 origin=r/'research/work-items'/('RE-013-visor-format-requests'if kind=='format'else 'RE-013-visor-descriptor-wait');host=b/('visor-'+kind);host.mkdir(exist_ok=True)
 names=['survey.py','verify.py','crosscheck_llvm.py']if kind=='format'else['collect.py','verify.py','crosscheck.py']
 for name in names:
  s=(origin/name).read_text()
  if kind=='format':s=s.replace('2.42','2.47').replace('18.1.3','22.1.4')
  else:s=s.replace('ROOT = Path(__file__).resolve().parents[3]',f'ROOT = Path({str(r)!r})')
  (host/name).write_text(s)
 collector='survey.py'if kind=='format'else 'collect.py'
 command(kind+'-collect',[sys.executable,host/collector,'--binary',binary,'--output',host/'observed'])
 if kind=='format':
  for mode in ([],['-O']):command(kind+'-'+('optimized'if mode else 'normal'),[sys.executable,*mode,host/'verify.py','--binary',binary,'--receipt',host/('optimized.json'if mode else 'normal.json')])
  command(kind+'-crosscheck',[sys.executable,host/'crosscheck_llvm.py','--binary',binary,'--output',host/'llvm'])
 else:
  for mode in ([],['-O']):
   raw=command(kind+'-'+('optimized'if mode else 'normal'),[sys.executable,*mode,host/'verify.py','--binary',binary]);(host/('optimized.json'if mode else 'normal.json')).write_bytes(raw)
  command(kind+'-crosscheck',[sys.executable,host/'crosscheck.py','--binary',binary,'--output',host/'llvm'])
 a=json.loads((host/'normal.json').read_text());z=json.loads((host/'optimized.json').read_text());assert a==z
 return {'packet':kind,'normal_and_optimized':True,'receipt':a,'provider_override':'GNU2.47 and LLVM22.1.4 version admission only in ignored copies'if kind=='format'else 'Installed GNU2.47/LLVM22.1.4 with original scope checks'}
with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:
 for kind in ['ceil','format','descriptor']:
  pass
 futures={pool.submit(qualify,k):k for k in ['ceil','format','descriptor']}
 for f in concurrent.futures.as_completed(futures):
  k=futures[f]
  try:x=f.result()
  except Exception as e:x={'packet':k,'error':str(e)}
  results.append(x);(b/'packet-qualification.json').write_text(json.dumps(results,indent=2)+'\n');print(k,'PASS'if 'error'not in x else x['error'],flush=True)
