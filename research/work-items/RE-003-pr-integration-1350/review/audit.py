import json,hashlib,re,subprocess,sys
from pathlib import Path
r=Path('/Users/shawwalters/hlsource/hyperliquid-source/work/merge-latest-1153-1160/integration')
b=Path(__file__).resolve().parent
p=r/'research/work-items/RE-007-size-decimal-update-94'
unit=(b/'unit.log').read_bytes()
assert re.search(rb'Ran 10 tests in [0-9.]+s',unit) and unit.rstrip().endswith(b'OK')
cmd=['/opt/miniconda3/bin/python3','tools/risk_size_decimal_update94.py','--out',str(b/'observed')]
with (b/'replay.log').open('wb') as f:
 status=subprocess.run(cmd,cwd=r,stdout=f,stderr=subprocess.STDOUT).returncode
assert status==0
fresh=[]
for f in (b/'observed').iterdir():
 assert (p/f.name).read_bytes()==f.read_bytes()
 fresh.append({'file':f.name,'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'byte_identical':True})
manifest=[]
for line in (p/'MANIFEST.sha256').read_text().splitlines():
 digest,name=line.split(None,1);assert hashlib.sha256((p/name).read_bytes()).hexdigest()==digest
 manifest.append({'file':name,'sha256':digest})
e=json.loads((b/'observed/evidence.json').read_text())
receipt={'status':'PASS','target_sha256':e['binary_sha256'],
 'test_command':['/opt/miniconda3/bin/python3','-m','unittest','discover','-s','tests','-p','test_risk_size_decimal_update94.py','-v'],
 'cwd':str(r),'test_count':10,'test_returncode':0,'skips':0,
 'test_sha256':hashlib.sha256((r/'tests/test_risk_size_decimal_update94.py').read_bytes()).hexdigest(),
 'test_log_sha256':hashlib.sha256(unit).hexdigest(),
 'tool_sha256':hashlib.sha256((r/'tools/risk_size_decimal_update94.py').read_bytes()).hexdigest(),
 'replay_command':cmd,'replay_returncode':status,'replay_log_sha256':hashlib.sha256((b/'replay.log').read_bytes()).hexdigest(),
 'regenerated_files':fresh,'manifest_files':manifest,
 'evidence_counts':{k:len(e[k]) for k in ['functions','controls','branches','indirect_calls','direct_calls']},
 'observations':['The authenticated updater and its empty/nonempty gate agree with prior independently reviewed PDI byte-writer evidence.',
 'Fresh native vote-arm excerpt confirms count/status checks, name length >=101 rejection, resolver status gate, immediate update call and per-item continuation.',
 'Fresh complete seed-generator excerpt confirms 32-byte stride, dex*10000+index, zeroed inner root/count, multiplication and addition overflow exits, and empty interval before multiplication.',
 'Fresh nested-map excerpt confirms 20-byte comparison and 64-byte return/replace on equality.',
 'The source keeps collector completeness, inferred field names, helper behavior and byte admission explicitly unresolved. No gate credit is requested.'],
 'native_auxiliary_exports':{name:hashlib.sha256((b/name).read_bytes()).hexdigest() for name in ['vote-arm.gnu.txt','row-seed.gnu.txt','nested-map.gnu.txt']},
 'native_overscan_note':'vote-arm-overscan.gnu.txt retained as initial overscan with incomplete next-arm tail; excluded from verification. vote-arm.gnu.txt ends at exact 0x23576e0 instruction boundary.',
 'files_modified':[],
 'limits':'Static observation plus supplied-result Python models only. Parent independently checking all seven FDE partitions; no target execution, Rust equivalence, full collector claim or component completion.'}
(b/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k in ['status','test_count','test_returncode','test_sha256','test_log_sha256','tool_sha256','regenerated_files','evidence_counts']},indent=2))
