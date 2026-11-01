#!/usr/bin/env python3
"""Target-derived Reader value/cursor equations and independent Rust comparison.

This module reads captured bytes as data. It never executes or interprets the
node instruction stream. The only programs built/executed are new Rust.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

import bincode_varint as bv
import bincode_varint_slow as old

ROOT = bv.ROOT
COMPONENT = ROOT/'src/bincode-varint'
SOURCE = COMPONENT/'src/lib.rs'
PACKET = ROOT/'research/work-items/RE-005-bincode-reader-rust-94'
FIXTURE = PACKET/'target-vectors.tsv'
BODIES = [(0x466d850, 0x466d975, '2f4fb65647ac687706f7f902dd72913232d1fb05aef63a21597a4b4e907d006c'),
          (0x466d980, 0x466dabc, '1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b'),
          (0x466dac0, 0x466dace, 'e9c285d5d073c7afed38f1407c356d1bbd68f7d91948f2527ca58b5c55e64841')]


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parameters(data):
    secs = bv.sections(data)
    def byte(va):
        return bv.bytes_in_section(data, secs, va, 1)[0]
    return {32: {'expected': byte(0x466d931),
                 'total': {251: byte(0x466d8ba), 252: byte(0x466d8c7)},
                 'found': {253: byte(0x466d94e), 254: byte(0x466d936), 255: byte(0x466d966)},
                 'zero_is_little': byte(0x466d8f9) == 0x44},
            64: {'expected': byte(0x466da90),
                 'total': {251: byte(0x466d9ea), 252: byte(0x466da04), 253: byte(0x466d9f7)},
                 'found': {254: byte(0x466da95), 255: byte(0x466daad)},
                 'zero_is_little': byte(0x466da57) == 0x44}}


def inspect(data):
    need(len(data) == 91774280 and sha(data) == bv.SHA256, 'pinned node94 identity mismatch')
    secs = bv.sections(data)
    fdes = bv.fde_extents(data, secs)
    relocs = bv.relative_relocs(data, secs)
    old._got_target(relocs, 0x57745e8, 0x466dac0)
    records = []
    for lo, hi, expected in BODIES:
        need(fdes.get(lo) == hi, 'Reader/error FDE changed')
        body = bv.bytes_in_section(data, secs, lo, hi-lo)
        need(sha(body) == expected, 'complete Reader/error instruction body changed')
        records.append({'start': hex(lo), 'end': hex(hi), 'bytes': hi-lo,
                        'body_sha256': sha(body), 'body_hex': body.hex()})
    for name, lo, hi, anchors, table, targets, _, _ in old.READERS:
        old._check_anchors(data, secs, name, lo, hi, anchors)
        old._check_table(data, secs, name, table, targets)
    old._check_anchors(data, secs, 'error builder', *old.ERROR_BUILDER[:2], old.ERROR_BUILDER_ANCHORS)
    return {'target_sha256': bv.SHA256, 'bodies': records,
            'error_got': {'slot': '0x57745e8', 'target': '0x466dac0'},
            'parameters': parameters(data)}


def stimuli():
    values = {b''}
    for tag in range(256):
        values.update((bytes([tag]), bytes([tag])+bytes(range(1, 10))))
    for tag in range(251, 256):
        for count in range(10):
            for payload in (bytes(count), b'\xff'*count, bytes(range(1, count+1))):
                values.add(bytes([tag])+payload)
    state = 0x94b1c0de
    for size in range(13):
        for _ in range(16):
            raw = bytearray()
            for _ in range(size):
                state = (state*1664525+1013904223) & 0xffffffff
                raw.append(state >> 24)
            values.add(bytes(raw))
    return [(width, big, raw) for width in (32, 64) for big in (0, 1) for raw in sorted(values)]


def relation(width, big, raw, params):
    """Piecewise integer/slice equations, no instruction dispatch or CPU state."""
    if not raw:
        return 'end\t1\t0\t-'
    tag = raw[0]
    p = params[width]
    if tag < 251:
        result, consumed = f'ok\t{tag}', 1
    elif tag in p['found']:
        result, consumed = f"type\t{p['expected']}:{p['found'][tag]}", 1
    elif len(raw) < p['total'][tag]:
        result, consumed = f"end\t{p['total'][tag]-len(raw)}", 1
    else:
        width_bytes = {251: 2, 252: 4, 253: 8}[tag]
        order = 'little' if (big == 0) == p['zero_is_little'] else 'big'
        number = int.from_bytes(raw[1:1+width_bytes], order)
        result, consumed = f'ok\t{number}', 1+width_bytes
    return f'{result}\t{consumed}\t{raw[consumed:].hex() or "-"}'


def oracle(binary=bv.TARGET):
    data = Path(binary).read_bytes()
    record = inspect(data)
    params = parameters(data)
    inputs, answers = [], []
    for index, (width, big, raw) in enumerate(stimuli()):
        inputs.append(f'{index}\t{width}\t{big}\t{raw.hex() or "-"}\n')
        answers.append(f'{index}\t{relation(width, big, raw, params)}\n')
    return {'inputs': ''.join(inputs).encode(), 'fixture': ''.join(answers).encode(),
            'record': record, 'count': len(answers)}


def target_controls(binary=bv.TARGET):
    data = Path(binary).read_bytes()
    inspect(data)
    secs = bv.sections(data)
    results = []
    for name, va, replacement, width, raw in (
        ('payload-required-total', 0x466d8ba, 4, 32, b'\xfb\x34\x12'),
        ('u64-expected-type', 0x466da90, 2, 64, b'\xfe'),
        ('u32-endian-selector', 0x466d8f9, 0x45, 32, b'\xfb\x34\x12')):
        changed = bytearray(data)
        changed[bv.va_to_off(secs, va)] = replacement
        before = relation(width, 0, raw, parameters(data))
        after = relation(width, 0, raw, parameters(changed))
        need(before != after, 'actual operand counterfactual lacks changed output')
        try:
            for reader, lo, hi, anchors, *_ in old.READERS:
                old._check_anchors(changed, secs, reader, lo, hi, anchors)
        except bv.EvidenceError as error:
            rejected = str(error)
        else:
            # The endian CMOVE was not covered by the historical anchor set;
            # the new complete-body authentication rejects that changed opcode.
            need(sha(bv.bytes_in_section(changed, secs, BODIES[0][0], 293)) != BODIES[0][2],
                 'changed native instruction unexpectedly equal')
            rejected = 'new complete-body authentication differs'
        results.append({'name': name, 'address': hex(va), 'width': width, 'input_hex': raw.hex(),
                        'before': before, 'after': after, 'rejected': rejected})
    return results


DRIVER = '''extern crate hl_bincode_varint;
use hl_bincode_varint::{PayloadOrder, ReaderError, read_u32, read_u64};
use std::io::{self, Write};
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_owned(); }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let text = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in text.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        let bytes: Vec<u8> = if f[3] == "-" { Vec::new() } else {
            (0..f[3].len()).step_by(2).map(|i| u8::from_str_radix(&f[3][i..i+2],16).unwrap()).collect()
        };
        let mut input = bytes.as_slice();
        let order = if f[2] == "0" { PayloadOrder::Little } else { PayloadOrder::Big };
        let result = if f[1] == "32" { read_u32(&mut input,order).map(u64::from) }
                     else { read_u64(&mut input,order) };
        let status = match result {
            Ok(n) => format!("ok\\t{n}"),
            Err(ReaderError::UnexpectedEnd{needed}) => format!("end\\t{needed}"),
            Err(ReaderError::InvalidIntegerType{expected_code,found_code}) =>
                format!("type\\t{expected_code}:{found_code}"),
        };
        writeln!(out,"{}\\t{}\\t{}\\t{}",f[0],status,bytes.len()-input.len(),hex(input)).unwrap();
    }
}
'''


def build(binary, rustc, output, controls=False):
    output = Path(output).absolute()
    need(not output.exists(), 'output directory must be new')
    expected = oracle(binary)
    need(FIXTURE.read_bytes() == expected['fixture'], 'frozen fixture differs')
    need((PACKET/'target-inputs.tsv').read_bytes() == expected['inputs'], 'frozen input corpus differs')
    rustc = Path(rustc).absolute()
    version = subprocess.check_output([str(rustc), '-vV'], text=True)
    need(version.startswith('rustc 1.94.1 '), 'repository compiler must be Rust 1.94.1')
    linker = os.environ.get('RECONSTRUCTION_LINKER') or shutil.which('cc')
    need(linker is not None, 'host C linker driver required')
    paths = [SOURCE, FIXTURE, Path(__file__), rustc, Path(linker)]
    before = [sha(p.read_bytes()) for p in paths]
    output.mkdir(parents=True)
    (output/'inputs.tsv').write_bytes(expected['inputs'])
    (output/'expected.tsv').write_bytes(expected['fixture'])
    (output/'driver.rs').write_text(DRIVER)
    commands = []
    def execute(label, args, fail=False):
        p = subprocess.run(list(map(str, args)), cwd=ROOT, capture_output=True, stdin=subprocess.DEVNULL)
        for kind, raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            (output/(label+'.'+kind)).write_bytes(raw)
        commands.append({'label':label,'exit':p.returncode,
                         'argv':[str(a).replace(str(output),'$OUTPUT').replace(str(ROOT),'$REPO')
                                 .replace(str(rustc),'$RUSTC').replace(linker,'$LINKER') for a in args],
                         'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
        need(p.returncode != 0 if fail else p.returncode == 0, label+' unexpected exit; raw logs retained')
        return p.stdout
    def compile_compare(name, source, opt):
        folder = output/name
        folder.mkdir()
        library = folder/'libhl_bincode_varint.rlib'
        flags = ['--edition=2024','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=on',
                 '-C','codegen-units=1','-C','linker='+linker,'--remap-path-prefix',str(ROOT)+'=/reconstruction']
        execute(name+'-library',[rustc,'--crate-name','hl_bincode_varint','--crate-type=rlib',source,'-o',library,*flags])
        driver = folder/'driver'
        execute(name+'-link',[rustc,output/'driver.rs','--extern','hl_bincode_varint='+str(library),'-o',driver,*flags])
        actual = execute(name+'-run',[driver,output/'inputs.tsv'])
        need(len(actual.splitlines()) == expected['count'], 'production output count differs')
        return {'name':name,'opt_level':opt,'matches':actual == expected['fixture'],
                'mismatches':sum(a != b for a,b in zip(actual.splitlines(),expected['fixture'].splitlines())),
                'library_sha256':sha(library.read_bytes()),'actual_sha256':sha(actual)}, flags, folder, library
    profiles = []
    for name, opt in [('debug',0),('optimized',3)]:
        result, flags, folder, library = compile_compare(name,SOURCE,opt)
        need(result['matches'], 'production Rust disagrees with target-grounded Reader equations')
        for testfile in sorted((COMPONENT/'tests').glob('*.rs')):
            unit = folder/testfile.stem
            execute(name+'-'+testfile.stem+'-build',[rustc,'--test',testfile,'--extern',
                    'hl_bincode_varint='+str(library),'-o',unit,*flags])
            execute(name+'-'+testfile.stem+'-tests',[unit])
        profiles.append(result)
    repeated, _, _, _ = compile_compare('optimized-repeat',SOURCE,3)
    need(repeated['library_sha256'] == profiles[1]['library_sha256'], 'own optimized rlib not reproducible')
    mutants = []
    if controls:
        source = SOURCE.read_text()
        for name, old_text, new_text in [
            ('skip-marker-consumption','*input = rest;','let _ = rest; /* incorrect: retain marker */'),
            ('shortfall-off-by-one','needed: width - input.len()','needed: width - input.len() + 1'),
            ('ignore-payload-order','PayloadOrder::Big => payload\n            .iter()',
             'PayloadOrder::Big => payload\n            .iter().rev()')]:
            need(source.count(old_text) == 1, 'ambiguous Rust mutation site')
            folder = output/('source-'+name)
            folder.mkdir()
            path = folder/'lib.rs'
            path.write_text(source.replace(old_text,new_text))
            r, flags, built, library = compile_compare('mutant-'+name,path,0)
            need(not r['matches'] and r['mismatches'] > 0, 'compiled Reader mutation escaped comparison')
            unit = built/'reader-tests'
            execute(name+'-tests-build',[rustc,'--test',COMPONENT/'tests/reader_vectors.rs',
                    '--extern','hl_bincode_varint='+str(library),'-o',unit,*flags])
            execute(name+'-tests',[unit],fail=True)
            mutants.append(r)
    need(before == [sha(p.read_bytes()) for p in paths], 'source/compiler/linker changed')
    need(sha(Path(binary).read_bytes()) == bv.SHA256, 'capture changed during comparison')
    report = {'status':'PASS','target_sha256':bv.SHA256,'compiler':version,
              'linker_version':subprocess.check_output([linker,'--version'],text=True),
              'sdkroot':os.environ.get('SDKROOT'),'case_count':expected['count'],
              'expected_sha256':sha(expected['fixture']),'inputs_sha256':sha(expected['inputs']),
              'source_compiler_linker_sha256':before,'profiles':profiles,
              'own_optimized_rlib_raw_reproducible':True,'rust_mutants':mutants,
              'target_controls':target_controls(binary) if controls else [],'commands':commands,
              'captured_program_executed_or_emulated':False,
              'limits':'Reader normal-return values and cursor effects; no original Rust ABI, caller or full wrapper claim.'}
    (output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=bv.TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args = parser.parse_args()
    try:
        report = build(args.binary,args.rustc,args.output,args.controls)
    except (ValueError,OSError,bv.EvidenceError,subprocess.CalledProcessError) as error:
        parser.exit(1,str(error)+'\n')
    print(json.dumps({'status':report['status'],'cases_per_profile':report['case_count']}))
