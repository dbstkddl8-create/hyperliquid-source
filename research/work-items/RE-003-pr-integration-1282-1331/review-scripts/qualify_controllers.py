import hashlib,json,os,pathlib,subprocess,sys,time
b=pathlib.Path(__file__).resolve().parent;r=b.parent/'merge-latest-1153-1160/integration';sys.path.insert(0,str(r/'tools'))
import format_request_protocol as fmt,numeric_selector_rust as sel
rustc=subprocess.check_output(['rustup','which','--toolchain','1.94.1','rustc'],text=True).strip();version=subprocess.check_output([rustc,'-vV'],text=True);assert 'release: 1.94.1' in version
out=b/'controller-host';out.mkdir(exist_ok=True);commands=[]
def digest(raw):return hashlib.sha256(raw).hexdigest()
def execute(label,args,input=None,env=None,want=0):
 start=time.monotonic();p=subprocess.run(list(map(str,args)),cwd=r,input=input,capture_output=True,env=env);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);commands.append({'label':label,'args':list(map(str,args)),'exit_code':p.returncode,'seconds':round(time.monotonic()-start,3),'stdin_sha256':digest(input)if input is not None else None,'stdout_sha256':digest(p.stdout),'stderr_sha256':digest(p.stderr)});(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');assert p.returncode==want,(label,p.stderr[-1000:]);return p.stdout

def flags(opt):return [rustc,'--edition=2021','-D','warnings','-C','overflow-checks=yes','-C',f'opt-level={opt}']
def library(label,source,crate,opt,folder,extern=()):
 folder.mkdir(parents=True,exist_ok=True);lib=folder/f'lib{crate}.rlib';execute(label,[*flags(opt),'--crate-name',crate,'--crate-type=rlib',source,*extern,'-o',lib]);return lib
profiles=[];mutants=[];target=fmt.admit_target(r/'artifacts/node/94/hl-node');inputs,answers,expected=fmt.fixtures();(out/'formatter-input.tsv').write_bytes(inputs)
for opt in (0,3):
 folder=out/f'formatter-o{opt}';lib=library(f'formatter-{opt}-lib',fmt.COMPONENT/'lib.rs','node94_format_request_protocol',opt,folder);external=['--extern',f'node94_format_request_protocol={lib}'];client=folder/'client';execute(f'formatter-{opt}-link',[*flags(opt),fmt.COMPONENT/'input_only.rs',*external,'-o',client]);raw=execute(f'formatter-{opt}-run',[client],inputs);assert not fmt.compare(raw,expected)
 unit=folder/'tests';execute(f'formatter-{opt}-unit-build',[*flags(opt),'--test',fmt.COMPONENT/'independent_tests.rs',*external,'-o',unit]);execute(f'formatter-{opt}-unit-run',[unit]);profiles.append({'component':'formatter','opt':opt,'cases':len(expected),'matched':True,'library_sha256':digest(lib.read_bytes())})
source=(fmt.COMPONENT/'lib.rs').read_text()
for name,old,new in [('direct-canonicalized','return Ok(requests.write(writer.method.get(), writer.destination, bytes));','return Ok(u8::from(requests.write(writer.method.get(), writer.destination, bytes) != 0));'),('index-not-rebased','next_index = index.wrapping_add(1);','next_index = next_index.wrapping_add(1);'),('quantity-from-first-word','?.second.get() as u16','?.data.get() as u16'),('outer-method-reloaded','requests.write(cached_method, writer.destination, literal)','requests.write({ let _ = cached_method; writer.method.get() }, writer.destination, literal)')]:
 assert old in source;folder=out/('formatter-mutant-'+name);folder.mkdir();changed=folder/'lib.rs';changed.write_text(source.replace(old,new));lib=library('fm-'+name+'-lib',changed,'node94_format_request_protocol',3,folder);client=folder/'client';execute('fm-'+name+'-link',[*flags(3),fmt.COMPONENT/'input_only.rs','--extern',f'node94_format_request_protocol={lib}','-o',client]);raw=execute('fm-'+name+'-run',[client],inputs);differences=fmt.compare(raw,expected);assert differences;mutants.append({'component':'formatter','name':name,'different_cases':len(differences)})
print('formatter 1066 cases at O0/O3 and four compiled controls pass',flush=True)
# The original Linux/103-payload receipt remains intact. This is an independent
# host build with explicitly recorded host/compiler identity, not a replay of it.
inputs=(sel.FROZEN/'inputs.tsv').read_bytes();expected=(sel.FROZEN/'expected.tsv').read_bytes();assert digest(inputs)==sel.INPUT_SHA and digest(expected)==sel.EXPECTED_SHA;assert digest(sel.DEPENDENCY.read_bytes())==sel.DEPENDENCY_SHA
inputfile=out/'selector-input.tsv';inputfile.write_bytes(inputs);env=dict(os.environ,NODE94_SELECTOR_FIXTURES=str(sel.FROZEN))
for opt in (0,3):
 folder=out/f'selector-o{opt}';decimal=library(f'selector-{opt}-decimal',sel.DEPENDENCY,sel.DECIMAL,opt,folder);external=['--extern',f'{sel.DECIMAL}={decimal}'];lib=library(f'selector-{opt}-lib',sel.SOURCE,sel.CRATE,opt,folder,external);client=folder/'client';execute(f'selector-{opt}-link',[*flags(opt),sel.DRIVER,'--extern',f'{sel.CRATE}={lib}',*external,'-L',f'dependency={folder}','-o',client],env=env);raw=execute(f'selector-{opt}-run',[client,inputfile],env=env);assert not sel.compare(raw,expected)
 for label,source,extern in [('decimal',sel.DEPENDENCY,[]),('selector',sel.SOURCE,external)]:
  unit=folder/(label+'-tests');execute(f'selector-{opt}-{label}-unit-build',[*flags(opt),'--test',source,*extern,'-o',unit],env=env);execute(f'selector-{opt}-{label}-unit-run',[unit],env=env)
 profiles.append({'component':'selector','opt':opt,'cases':sel.CASES,'matched':True,'library_sha256':digest(lib.read_bytes())})
source=sel.SOURCE.read_text();decimal=out/'selector-o0'/f'lib{sel.DECIMAL}.rlib'
for name,old,new,relation in sel.mutations(source):
 folder=out/('selector-mutant-'+name);folder.mkdir();changed=folder/'lib.rs';changed.write_text(source.replace(old,new));external=['--extern',f'{sel.DECIMAL}={decimal}'];lib=library('sm-'+name+'-lib',changed,sel.CRATE,0,folder,external);client=folder/'client';execute('sm-'+name+'-link',[*flags(0),sel.DRIVER,'--extern',f'{sel.CRATE}={lib}',*external,'-L',f'dependency={decimal.parent}','-o',client],env=env);raw=execute('sm-'+name+'-run',[client,inputfile],env=env);differences=sel.compare(raw,expected);assert differences;mutants.append({'component':'selector','name':name,'different_cases':len(differences)})
print('selector 8892 cases at O0/O3 and nine compiled controls pass',flush=True)
result={'host_compiler':version,'host_rustc_sha256':digest(pathlib.Path(rustc).read_bytes()),'target':target,'profiles':profiles,'compiled_mutants':mutants,'limits':'Native macOS arm64 replay of independently authored Rust with frozen inputs and supplied callbacks. Original pinned Linux provider receipts unchanged; no claim of repeating their provider audit, original ABI or captured execution.'};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
