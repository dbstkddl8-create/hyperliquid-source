#!/usr/bin/env python3
"""Build an independent Rust ASCII address projection against byte-bound equations.

Static captured-data parsing only. No captured instruction evaluator or native
node is run. Only independently authored Rust compiler products execute.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import address_parser_static as native

ROOT = native.ROOT
TARGET = ROOT/native.BINARY
COMPONENT = ROOT/'src/node94-ascii-address'
SOURCE = COMPONENT/'lib.rs'
PACKET = ROOT/'research/work-items/RE-005-address-ascii-rust-94'


def need(condition,message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parameters(data):
    image = native.Image(data)
    def byte(va):
        return image.read(va,1)[0]
    return {'prefix':image.read(0x1444a2c,2),'padding':byte(0x1444a76),
            'tail':byte(0x1444a3b),'bytes':byte(0x1444bd4),
            'upper_offset':byte(0x4eb653c),'upper_bound':byte(0x4eb6540),'upper_bias':byte(0x4eb654a),
            'lower_offset':byte(0x4eb655e),'lower_bound':byte(0x4eb6562),'lower_bias':byte(0x4eb656c),
            'digit_offset':byte(0x4eb6580),'digit_bound':byte(0x4eb6584)}


def relation(raw,p):
    if not raw.isascii():
        return 'outside'
    if len(raw)<2:
        return 'reject'
    body = raw[2:] if raw[:2] == p['prefix'] else raw
    if len(body)<p['tail']:
        return 'reject'
    padding,tail = body[:-p['tail']],body[-p['tail']:]
    if any(byte != p['padding'] for byte in padding) or tail[:2] == b'0x':
        return 'reject'
    values=[]
    for byte in tail:
        if (byte+p['upper_offset']) & 255 < p['upper_bound']:
            value=(byte+p['upper_bias']) & 255
        elif (byte+p['lower_offset']) & 255 < p['lower_bound']:
            value=(byte+p['lower_bias']) & 255
        elif (byte+p['digit_offset']) & 255 < p['digit_bound']:
            value=(byte+p['digit_offset']) & 255
        else:
            return 'reject'
        values.append(value)
    need(len(values) == p['bytes']*2,'qualified pair-count relation changed')
    return bytes(((values[i]<<4)|values[i+1]) & 255 for i in range(0,len(values),2)).hex()


def stimuli():
    tail=b'0123456789aBcDeF0123456789aBcDeF01234567'
    rows=[]
    for prefix in (b'',b'0x'):
        for pos in range(40):
            for byte in range(128):
                rows.append(prefix+tail[:pos]+bytes([byte])+tail[pos+1:])
    for count in range(97):
        for prefix in (b'',b'0x',b'0X'):
            for pad in (b'0'*count,b'1'*count):
                rows.append(prefix+pad+tail)
    rows.extend(b'f'*length for length in range(40))
    rows.extend([b'0x'+b'f'*40,b'0x'+b'f'*38,b'0x0x'+b'f'*38,
                 b'f'*39+b' ',b'f'*39+b'\t',b'f'*39+b'\n',b'0'*1040,
                 b'\x80','é'.encode(),b'0x'+b'f'*39+b'\xff'])
    return rows


def oracle(binary=TARGET):
    data = Path(binary).read_bytes()
    need(len(data)==91774280 and sha(data)==native.SHA256,'pinned node94 identity mismatch')
    record = native.build(data)
    need(record==json.loads((native.PACKET/'records.json').read_text()),'accepted native records differ')
    params=parameters(data)
    need((params['prefix'],params['padding'],params['tail'],params['bytes'])==(b'0x',48,40,20),
         'framing parameters changed')
    pattern=re.compile(rb'(?:0x)?0*[0-9a-fA-F]{40}')
    inputs,expected=[],[]
    smoke=[]
    for index,raw in enumerate(stimuli()):
        result=relation(raw,params)
        if raw.isascii():
            value=native.ascii_decode(raw)
            need(result==('reject' if value is None else value.hex()),'operand relation differs from accepted model')
            need((result!='reject')==(pattern.fullmatch(raw) is not None),'independent ASCII language differs')
            if value is not None:
                need(value==bytes.fromhex(raw[-40:].decode('ascii')),'independent payload decoder differs')
        inputs.append(f'{index}\t{raw.hex() or "-"}\n')
        expected.append(f'{index}\t{result}\n')
    for raw in [b'',b'f'*39,b'f'*40,b'0x'+b'f'*40,b'0X'+b'f'*40,
                b'000'+b'f'*40,b'1'+b'f'*40,b'0x0x'+b'f'*38,
                b'0'*40,b'A'+b'f'*39,b'a'+b'f'*39,b'f'*39+b' ',b'\x80','é'.encode()]:
        smoke.append(f'{raw.hex() or "-"}\t{relation(raw,params)}\n')
    return {'inputs':''.join(inputs).encode(),'expected':''.join(expected).encode(),
            'smoke':''.join(smoke).encode(),'count':len(inputs),
            'ascii_cases':sum(raw.isascii() for raw in stimuli()),
            'distinct_inputs':len(set(stimuli())),'record':record}


def target_controls(binary=TARGET):
    data=Path(binary).read_bytes()
    native.build(data)
    image=native.Image(data)
    controls=[]
    for name,va,replacement,raw in (
        ('uppercase-outer-prefix',0x1444a2d,0x58,b'0X'+b'f'*40),
        ('padding-one',0x1444a76,0x31,b'1'+b'f'*40),
        ('upper-digit-bias',0x4eb654a,0xc8,b'A'+b'f'*39)):
        changed=bytearray(data)
        changed[image.off(va,1)]=replacement
        before,after=relation(raw,parameters(data)),relation(raw,parameters(changed))
        need(before!=after,'actual operand counterfactual lacks changed acceptance/payload')
        try:
            native.observe(changed)
        except ValueError as error:
            rejected=str(error)
        else:
            raise ValueError('actual native operand mutation accepted')
        controls.append({'name':name,'address':hex(va),'input_hex':raw.hex(),
                         'before':before,'after':after,'rejected':rejected,
                         'captured_instruction_evaluation':False})
    return controls


DRIVER='''extern crate node94_ascii_address;
use node94_ascii_address::parse_ascii_address;
use std::io::{self,Write};
fn main() {
    let text=std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut out=io::BufWriter::new(io::stdout().lock());
    for line in text.lines() {
        let f:Vec<_>=line.split_whitespace().collect();
        let input:Vec<u8>=if f[1]=="-" {Vec::new()} else {
            (0..f[1].len()).step_by(2).map(|at|u8::from_str_radix(&f[1][at..at+2],16).unwrap()).collect()
        };
        let actual=match parse_ascii_address(&input) {
            Ok(Some(bytes))=>bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),
            Ok(None)=>"reject".to_owned(),Err(_)=>"outside".to_owned(),
        };
        writeln!(out,"{}\\t{}",f[0],actual).unwrap();
    }
}
'''


def build(binary,rustc,output,controls=False):
    output=Path(output).absolute()
    need(not output.exists(),'output directory must be new')
    expected=oracle(binary)
    freeze=json.loads((PACKET/'PRE-RUST-FREEZE.json').read_text())
    need((freeze['input_sha256'],freeze['expected_sha256'])==
         (sha(expected['inputs']),sha(expected['expected'])),'frozen corpus identity differs')
    need((COMPONENT/'target-smoke.tsv').read_bytes()==expected['smoke'],'smoke fixture differs')
    rustc=Path(rustc).absolute()
    version=subprocess.check_output([str(rustc),'-vV'],text=True)
    need(version.startswith('rustc 1.94.1 '),'repository research compiler must be Rust1.94.1')
    linker=os.environ.get('RECONSTRUCTION_LINKER') or shutil.which('cc')
    need(linker is not None,'host linker required')
    files=[SOURCE,COMPONENT/'target-smoke.tsv',Path(__file__),rustc,Path(linker)]
    before=[sha(p.read_bytes()) for p in files]
    output.mkdir(parents=True)
    (output/'inputs.tsv').write_bytes(expected['inputs'])
    (output/'expected.tsv').write_bytes(expected['expected'])
    (output/'driver.rs').write_text(DRIVER)
    commands=[]
    def execute(label,args,fail=False):
        p=subprocess.run(list(map(str,args)),cwd=ROOT,capture_output=True,stdin=subprocess.DEVNULL)
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            (output/(label+'.'+kind)).write_bytes(raw)
        commands.append({'label':label,'exit':p.returncode,
                         'argv':[str(a).replace(str(output),'$OUTPUT').replace(str(ROOT),'$REPO')
                                 .replace(str(rustc),'$RUSTC').replace(linker,'$LINKER') for a in args],
                         'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
        need(p.returncode!=0 if fail else p.returncode==0,label+' unexpected exit; raw logs retained')
        return p.stdout
    def compile_compare(name,source,opt):
        folder=output/name
        folder.mkdir()
        flags=['--edition=2021','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=on',
               '-C','codegen-units=1','-C','linker='+linker,'--remap-path-prefix',str(ROOT)+'=/reconstruction']
        library=folder/'libnode94_ascii_address.rlib'
        execute(name+'-library',[rustc,'--crate-name','node94_ascii_address','--crate-type=rlib',source,
                                 '-o',library,*flags])
        driver=folder/'driver'
        execute(name+'-link',[rustc,output/'driver.rs','--extern','node94_ascii_address='+str(library),
                             '-o',driver,*flags])
        actual=execute(name+'-run',[driver,output/'inputs.tsv'])
        need(len(actual.splitlines())==expected['count'],'production output count differs')
        return {'name':name,'opt_level':opt,'matches':actual==expected['expected'],
                'mismatches':sum(a!=b for a,b in zip(actual.splitlines(),expected['expected'].splitlines())),
                'actual_sha256':sha(actual),'library_sha256':sha(library.read_bytes())},flags,folder
    profiles=[]
    for name,opt in [('debug',0),('optimized',3)]:
        result,flags,folder=compile_compare(name,SOURCE,opt)
        need(result['matches'],'ASCII Rust differs from target-bound equations')
        unit=folder/'tests'
        execute(name+'-test-build',[rustc,'--crate-name','node94_ascii_address','--test',SOURCE,'-o',unit,*flags])
        tests=execute(name+'-tests',[unit])
        need(b'1 passed; 0 failed' in tests,'ordinary frozen smoke test did not run')
        profiles.append(result)
    repeated,_,_=compile_compare('optimized-repeat',SOURCE,3)
    need(repeated['library_sha256']==profiles[1]['library_sha256'],'own optimized library not reproducible')
    mutants=[]
    if controls:
        source=SOURCE.read_text()
        for name,old,new in [
            ('uppercase-prefix','strip_prefix(b"0x")','strip_prefix(b"0X")'),
            ('nonzero-padding',"byte != b'0'","byte != b'1'"),
            ('upper-nibble-nine',"byte - b'A' + 10","byte - b'A' + 9")]:
            need(source.count(old)==1,'ambiguous ASCII Rust mutation site')
            private=output/('source-'+name)
            private.mkdir()
            path=private/'lib.rs';path.write_text(source.replace(old,new))
            (private/'target-smoke.tsv').write_bytes(expected['smoke'])
            result,flags,folder=compile_compare('mutant-'+name,path,0)
            need(not result['matches'] and result['mismatches']>0,'compiled ASCII mutation escaped comparator')
            unit=folder/'tests'
            execute(name+'-test-build',[rustc,'--crate-name','node94_ascii_address','--test',path,'-o',unit,*flags])
            execute(name+'-tests',[unit],fail=True)
            mutants.append(result)
    need(before==[sha(p.read_bytes()) for p in files],'source/compiler/linker changed')
    need(sha(Path(binary).read_bytes())==native.SHA256,'capture changed during comparison')
    report={'status':'PASS','target_sha256':native.SHA256,'compiler':version,
            'linker_version':subprocess.check_output([linker,'--version'],text=True),
            'sdkroot':os.environ.get('SDKROOT'),'case_count':expected['count'],
            'ascii_cases':expected['ascii_cases'],'distinct_input_strings':expected['distinct_inputs'],
            'input_sha256':sha(expected['inputs']),'expected_sha256':sha(expected['expected']),
            'source_compiler_linker_sha256':before,'profiles':profiles,
            'own_optimized_rlib_raw_reproducible':True,'rust_mutants':mutants,
            'target_controls':target_controls(binary) if controls else [],'commands':commands,
            'captured_program_executed_or_emulated':False,
            'limits':'ASCII acceptance/20-byte payload only; errors assume normal opaque helper return; no Unicode/error allocation/object ABI/caller/full-function claim.'}
    (output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args()
    try:
        report=build(args.binary,args.rustc,args.output,args.controls)
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        parser.exit(1,str(error)+'\n')
    print(json.dumps({'status':report['status'],'cases_per_profile':report['case_count']}))
