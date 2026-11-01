#!/usr/bin/env python3
"""RE-014: Aqav2 diagnostic cardinality and selected immediate-call arguments."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

PACKET = ROOT / 'research/work-items/RE-014-aqav2-diagnostic-drift'
TARGETS = {r: ROOT / f'artifacts/node/{r}/hl-node' for r in ['94', '115']}
SPEC_SHA = '02e94643cfa0585c7f908e6dc594eb03b14ea8a80e28ab60a644adab4464e24f'


def specification():
    raw = (PACKET / 'spec.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != SPEC_SHA:
        raise ValueError('Aqav2 specification changed')
    return json.loads(raw)


def reader(data):
    secs = sections(data)
    def read(va, n):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + n <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('expected one complete file-backed mapping')
        s = matches[0]; off = s['offset'] + va - s['address']
        return bytes(data[off:off+n])
    return secs, read


def metadata(data, target):
    """Extract actual text and immediate arguments before checking the relation."""
    secs, rd = reader(data)
    slot = target['slot']; length = int.from_bytes(rd(slot+8, 8), 'little')
    if not 0 < length < 128:
        raise ValueError('invalid diagnostic length')
    text = rd(target['text_va'], length)
    match = re.fullmatch(rb'struct Aqav2TokenInfo with ([0-9]+) elements', text)
    if not match:
        raise ValueError('Aqav2 diagnostic changed')
    references = []
    for owner in target['owners']:
        for site in owner['sites']:
            if rd(site, 3) != bytes.fromhex('488d15') or rd(site+7, 3) != bytes.fromhex('488d0d'):
                raise ValueError('argument LEA changed')
            diagnostic = site+7+struct.unpack('<i', rd(site+3, 4))[0]
            record = site+14+struct.unpack('<i', rd(site+10, 4))[0]
            p = site+14
            if rd(p, 5) == bytes.fromhex('488d7c2410'):
                p += 5
            ordinal_site = p
            if rd(p, 2) == bytes.fromhex('31f6'):
                ordinal = 0; p += 2
            elif rd(p, 1) == b'\xbe':
                ordinal = int.from_bytes(rd(p+1, 4), 'little'); p += 5
            else:
                raise ValueError('unsupported immediate ESI setup')
            transfer = p; opcode = rd(p, 1)[0]
            if opcode == 0xe9:
                p += 5+struct.unpack('<i', rd(p+1, 4))[0]
            elif opcode == 0xeb:
                p += 2+struct.unpack('<b', rd(p+1, 1))[0]
            elif opcode != 0xe8:
                raise ValueError('unsupported call transfer')
            if not owner['start'] <= p < owner['end'] or rd(p, 1) != b'\xe8':
                raise ValueError('transfer does not reach a local direct call')
            callee = p+5+struct.unpack('<i', rd(p+1, 4))[0]
            references.append({'site': site, 'diagnostic_slot': diagnostic, 'argument_record': record,
                               'ordinal_site': ordinal_site, 'raw_esi': ordinal,
                               'transfer_site': transfer, 'call_site': p, 'callee': callee})
    return {'text': text.decode('ascii'), 'diagnostic_count': int(match[1]), 'references': references}


def analyze(images):
    spec = specification(); reports = {}
    for r, t in spec.items():
        data = images[r]; secs, rd = reader(data); observed = metadata(data, t)
        expected_ordinals = [0, 0, 1, 1, 2, 2, 3, 3, 4, 4] if r == '94' else [0, 0, 1, 1, 2, 2, 3, 3, 5, 5]
        if observed['diagnostic_count'] != t['count'] or sorted(x['raw_esi'] for x in observed['references']) != expected_ordinals:
            raise ValueError('diagnostic/immediate relation changed')
        expected_callee = 0x1703e70 if r == '94' else 0x17fbb40
        for ref in observed['references']:
            if ref['diagnostic_slot'] != t['slot'] or str(ref['argument_record']) not in t['argument_records'] or ref['callee'] != expected_callee:
                raise ValueError('diagnostic argument/call binding changed')
        sec = next(s for s in secs if s['name'] == '.rela.dyn')
        rels = {a:(i,v) for a,i,v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset']+sec['size']])}
        if rels.get(t['slot']) != (8, t['text_va']):
            raise ValueError('diagnostic relocation changed')
        for address, record in t['argument_records'].items():
            if rd(int(address), 32).hex() != record['bytes_hex']:
                raise ValueError('argument record changed')
            for a, value in record['relocations'].items():
                if rels.get(int(a)) != tuple(value):
                    raise ValueError('argument-record relocation changed')
        _, fs, _ = fde_extents(data); frames = {(f['start'],f['end']):f for f in fs}; owners = []
        for owner in t['owners']:
            a,b = owner['start'],owner['end']
            if (a,b) not in frames:
                raise ValueError('reference owner FDE changed')
            if hashlib.sha256(rd(a,b-a)).hexdigest() != owner['sha256']:
                raise ValueError('reference owner bytes changed')
            raw_frames = {}
            for kind in ['fde','cie']:
                va = frames[a,b][kind]; n = int.from_bytes(rd(va,4),'little')+4
                raw_frames[kind] = {'va':hex(va),'bytes_hex':rd(va,n).hex()}
            owners.append({**owner, 'bytes':b-a, 'frames':raw_frames})
        callee = [f for f in fs if f['start'] == expected_callee]
        if len(callee) != 1:
            raise ValueError('unmeasured callee entry is not a unique FDE start')
        reports[r] = {'sha256':t['sha256'], **observed, 'owners':owners,
                      'unmeasured_callee_bounds': [callee[0]['start'],callee[0]['end']],
                      'argument_records':t['argument_records']}
    return {'targets':reports, 'spec_sha256':SPEC_SHA, 'captured_code_executed':False,
            'limits':'Diagnostic text and selected immediate ESI/call bindings only. Helpers, argument-record roles, formats, field names/defaults/order, required wire arity, caller reachability and whole-type/ABI equivalence remain unproved. No component gates.'}


def generate(paths, output):
    spec = specification(); images = {}
    for r,t in spec.items():
        data = paths[r].read_bytes()
        if len(data) != t['size'] or hashlib.sha256(data).hexdigest() != t['sha256']:
            raise ValueError(f'expected pinned node{r}')
        images[r] = data
    report = analyze(images)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        for r,t in spec.items():
            data = images[r]; _,rd = reader(data); path = Path(temporary)/('node'+r+'.elf'); path.write_bytes(data)
            frames = subprocess.check_output(['readelf','-wf',str(path)],text=True); frame_rows=[]
            refs = report['targets'][r]['references']
            for o in t['owners']:
                a,b = o['start'],o['end']
                rows = [line for line in frames.splitlines() if f'pc={a:016x}..{b:016x}' in line]
                if len(rows) != 1:
                    raise ValueError('native FDE disagreement')
                frame_rows.extend(rows)
                asm = subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(path)],text=True)
                ins = decode_export(asm,a,b,rd(a,b-a))
                sites = {row[key] for row in refs if a <= row['site'] < b for key in ['site','ordinal_site','transfer_site','call_site']}
                if len(ins) != o['instructions'] or not sites <= set(ins):
                    raise ValueError('native instruction boundary/count disagreement')
                (output/f'{r}-{a:x}.objdump.txt').write_bytes(asm.replace(str(path),f'<authenticated-node{r}>').encode('utf-8'))
            (output/f'{r}-frames.txt').write_bytes(('\n'.join(frame_rows)+'\n').encode('utf-8'))
            wanted = {t['slot']} | {int(a) for rec in t['argument_records'].values() for a in rec['relocations']}
            rels = subprocess.check_output(['readelf','-rW',str(path)],text=True)
            rows = [line for line in rels.splitlines() if any(line.startswith(f'{a:016x} ') for a in wanted)]
            if len(rows) != len(wanted):
                raise ValueError('native relocation disagreement')
            (output/f'{r}-relocations.txt').write_bytes(('\n'.join(rows)+'\n').encode('utf-8'))
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'work/aqav2-diagnostic-drift')
    args = parser.parse_args()
    result = generate(TARGETS,args.output)
    print(json.dumps({'reference_sites':sum(len(t['references']) for t in result['targets'].values()),'executed':False}))
