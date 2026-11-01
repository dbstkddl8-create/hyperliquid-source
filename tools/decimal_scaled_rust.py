#!/usr/bin/env python3
"""Compare independent Rust with freshly revalidated Decimal evaluator fixtures.

The --controls path uses the separately authorized offline Python instruction
evaluator on private byte arrays. It never launches a native captured binary.
Only independently authored Rust compiler products are executed natively.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

import decimal_scaled_u64 as native

ROOT = native.ROOT
COMPONENT = ROOT/'src/node94-fixed-point'
SOURCE = COMPONENT/'src/lib.rs'
DECIMAL = COMPONENT/'src/decimal_scaled.rs'
OLD = ROOT/'research/work-items/RE-004-decimal-scaled-u64-94'
PACKET = ROOT/'research/work-items/RE-004-decimal-scaled-rust-94'
PINS = {'evidence.json':'de559f5c502d7d927ffbdba68b8ac2d2ce43c3558d8d2a401d69ff15ce499980',
        'vectors.tsv':'2da89f6dae659cd91cce487572c10a62fb490d0d02951b00bbcfc627cbe8e699',
        'coverage.tsv':'32345c0cc80210046948b467dc92186f53b31a91012867b81df284bc519afd64',
        'call-sites.tsv':'25db97e83a76d0101d3f2b15136d333a6e9d76e42078201f841b5fa78a83df9a'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def oracle(binary=native.TARGET):
    data = Path(binary).read_bytes()
    need(len(data) == 91774280 and sha(data) == native.SHA256, 'pinned node94 identity mismatch')
    for name, digest in PINS.items():
        need(sha((OLD/name).read_bytes()) == digest, 'accepted '+name+' changed')
    replay = json.loads((PACKET/'PRE-RUST-REPLAY.json').read_text())
    need(replay['status'] == 'PASS' and replay['new_Rust_module_exists'] is False,
         'pre-implementation replay not admitted')
    need(replay['old_evaluator_sha256'] == sha(Path(native.__file__).read_bytes()),
         'replayed Python evaluator changed')
    inputs, expected = [], []
    for index, line in enumerate((OLD/'vectors.tsv').read_text().splitlines()[1:]):
        fields = line.split('\t')
        negative, mantissa, scale, mode, exponent = map(int, fields[1:6])
        observed = (fields[6], None if fields[6] == 'error' else int(fields[7]), fields[8] != '0')
        need(observed == native.model(bool(negative),mantissa,scale,mode,exponent),
             'independent mathematical model differs from replayed fixture')
        inputs.append(f'{index}\t{negative}\t{mantissa}\t{scale}\t{mode}\t{exponent}\n')
        expected.append(f'{index}\t{fields[6]}\t{fields[7] or "-"}\t{int(fields[8] != "0")}\n')
    need(len(inputs) == 25325, 'fixture denominator changed')
    return {'inputs': ''.join(inputs).encode(), 'expected': ''.join(expected).encode(), 'count':len(inputs)}


def target_controls(binary=native.TARGET):
    data = Path(binary).read_bytes()
    native.check_target(data)
    original = native.Image(data)
    def result(image, parts):
        negative,mantissa,scale,mode,exponent = parts
        kind,value,machine = native.evaluate(image,native.pack(negative,mantissa,scale),mode,exponent)
        need(kind != 'panic', 'counterfactual left qualified normal-return comparison')
        return [kind,value,bool(machine.notes)]
    controls = []
    for name,va,changed,parts in (
        ('strict-cap-minus-one',native.CAP_IMMEDIATE_VA,b'\xfd',(False,native.CAP,0,0,0)),
        ('odd-half-tie-mask',native.TIE_TEST_VA+3,b'\x00',(False,35,1,2,0)),
        ('tolerance-times-two',native.TOLERANCE_VA,struct.pack('<IIII',0x30000,0,2,0),
         (False,10015,4,1,0))):
        private = bytearray(data)
        offset = original.file_offset(va)
        private[offset:offset+len(changed)] = changed
        before,after = result(original,parts),result(native.Image(private),parts)
        need(before != after, 'actual instruction/data counterfactual lacks changed value')
        controls.append({'name':name,'address':hex(va),'parts':parts,'before':before,'after':after,
                         'authorized_offline_Python_instruction_evaluation':True,
                         'native_capture_launched':False})
    return controls


DRIVER = '''extern crate node94_fixed_point;
use node94_fixed_point::decimal_to_scaled_u64;
use std::io::{self, Write};
fn main() {
    let text = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in text.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        let result = decimal_to_scaled_u64(f[1]=="1",f[2].parse().unwrap(),f[3].parse().unwrap(),
                                           f[4].parse().unwrap(),f[5].parse().unwrap()).unwrap();
        match result.value {
            Some(value) => writeln!(out,"{}\\tok\\t{}\\t{}",f[0],value,u8::from(result.note_requested)).unwrap(),
            None => writeln!(out,"{}\\terror\\t-\\t{}",f[0],u8::from(result.note_requested)).unwrap(),
        }
    }
}
'''


def build(binary,rustc,output,controls=False):
    output = Path(output).absolute()
    need(not output.exists(), 'output directory must be new')
    expected = oracle(binary)
    rustc = Path(rustc).absolute()
    version = subprocess.check_output([str(rustc),'-vV'],text=True)
    need(version.startswith('rustc 1.94.1 '), 'repository research compiler must be Rust 1.94.1')
    linker = os.environ.get('RECONSTRUCTION_LINKER') or shutil.which('cc')
    need(linker is not None,'host C linker driver required')
    files = sorted((COMPONENT/'src').glob('*.rs'))+[Path(__file__),rustc,Path(linker)]
    before = [sha(p.read_bytes()) for p in files]
    output.mkdir(parents=True)
    (output/'inputs.tsv').write_bytes(expected['inputs'])
    (output/'expected.tsv').write_bytes(expected['expected'])
    (output/'driver.rs').write_text(DRIVER)
    commands = []
    def execute(label,args,fail=False):
        p = subprocess.run(list(map(str,args)),cwd=ROOT,capture_output=True,stdin=subprocess.DEVNULL)
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            (output/(label+'.'+kind)).write_bytes(raw)
        commands.append({'label':label,'exit':p.returncode,
                         'argv':[str(a).replace(str(output),'$OUTPUT').replace(str(ROOT),'$REPO')
                                 .replace(str(rustc),'$RUSTC').replace(linker,'$LINKER') for a in args],
                         'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
        need(p.returncode != 0 if fail else p.returncode == 0,label+' unexpected exit; original logs retained')
        return p.stdout
    def compile_compare(name,source,opt):
        folder = output/name
        folder.mkdir()
        library = folder/'libnode94_fixed_point.rlib'
        flags = ['--edition=2024','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=on',
                 '-C','codegen-units=1','-C','linker='+linker,'--remap-path-prefix',str(ROOT)+'=/reconstruction']
        execute(name+'-library',[rustc,'--crate-name','node94_fixed_point','--crate-type=rlib',source,
                                '-o',library,*flags])
        driver = folder/'driver'
        execute(name+'-link',[rustc,output/'driver.rs','--extern','node94_fixed_point='+str(library),
                             '-o',driver,*flags])
        actual = execute(name+'-run',[driver,output/'inputs.tsv'])
        need(len(actual.splitlines()) == expected['count'], 'production output count differs')
        return {'name':name,'opt_level':opt,'matches':actual == expected['expected'],
                'mismatches':sum(a != b for a,b in zip(actual.splitlines(),expected['expected'].splitlines())),
                'library_sha256':sha(library.read_bytes()),'actual_sha256':sha(actual)},flags,folder,library
    profiles = []
    for name,opt in [('debug',0),('optimized',3)]:
        result,flags,folder,library = compile_compare(name,SOURCE,opt)
        need(result['matches'],name+' Rust differs from replayed target evaluator')
        counts = {}
        for label,path,extra in [('unit',SOURCE,[])] + [
            (p.stem,p,['--extern','node94_fixed_point='+str(library)])
            for p in sorted((COMPONENT/'tests').glob('*.rs'))]:
            unit = folder/label
            execute(name+'-'+label+'-build',[rustc,'--crate-name','node94_fixed_point','--test',path,
                                             '-o',unit,*extra,*flags])
            raw = execute(name+'-'+label+'-tests',[unit])
            match = re.search(rb'test result: ok\. (\d+) passed; 0 failed;',raw)
            need(match is not None,'ordinary Rust test count missing')
            counts[label] = int(match[1])
        result['ordinary_Rust_tests'] = counts
        profiles.append(result)
    repeated,_,_,_ = compile_compare('optimized-repeat',SOURCE,3)
    need(repeated['library_sha256'] == profiles[1]['library_sha256'], 'own optimized rlib not reproducible')
    mutants = []
    if controls:
        original = DECIMAL.read_text()
        for name,old,new in [
            ('inclusive-tolerance','gap * 1000 < divisor','gap * 1000 <= divisor'),
            ('half-up-instead-of-even','quotient & 1 != 0','true'),
            ('cap-plus-one','9_223_372_036_854_775_806','9_223_372_036_854_775_807'),
            ('reject-wide-intermediate','Some(product) if product < MANTISSA_LIMIT => break product,',
             'None => return Ok(ScaledDecimalOutcome::rejected(false)),\n            Some(product) if product < MANTISSA_LIMIT => break product,')]:
            need(original.count(old) == 1,'ambiguous Decimal mutation site')
            private = output/('source-'+name)
            private.mkdir()
            for p in (COMPONENT/'src').glob('*.rs'):
                (private/p.name).write_text(original.replace(old,new) if p == DECIMAL else p.read_text())
            # Only production configuration is built for the copied mutants;
            # their cfg(test) fixture includes are inactive. Rejection here is
            # an actual production value mismatch, not a compile-error credit.
            result,flags,built,library = compile_compare('mutant-'+name,private/'lib.rs',0)
            need(not result['matches'] and result['mismatches'] > 0,'compiled Decimal mutation escaped comparator')
            mutants.append(result)
    need(before == [sha(p.read_bytes()) for p in files], 'source/compiler/linker changed')
    need(sha(Path(binary).read_bytes()) == native.SHA256,'capture changed during comparison')
    report = {'status':'PASS','target_sha256':native.SHA256,'compiler':version,
              'linker_version':subprocess.check_output([linker,'--version'],text=True),
              'sdkroot':os.environ.get('SDKROOT'),'case_count':expected['count'],
              'inputs_sha256':sha(expected['inputs']),'expected_sha256':sha(expected['expected']),
              'source_compiler_linker_sha256':before,'profiles':profiles,
              'own_optimized_rlib_raw_reproducible':True,'rust_mutants':mutants,
              'target_controls':target_controls(binary) if controls else [],'commands':commands,
              'offline_Python_captured_instruction_evaluation_used_for_controls':controls,
              'native_capture_launched':False,
              'limits':'Scalar result/note-request projection conditional on normally returning opaque note callback; no original ABI or full function equivalence.'}
    (output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=native.TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args = parser.parse_args()
    try:
        report = build(args.binary,args.rustc,args.output,args.controls)
    except (ValueError,OSError,native.ToolError,subprocess.CalledProcessError) as error:
        parser.exit(1,str(error)+'\n')
    print(json.dumps({'status':report['status'],'cases_per_profile':report['case_count']}))
