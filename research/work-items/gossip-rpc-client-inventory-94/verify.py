#!/usr/bin/env python3
"""Verify whitelist, manifest, derived reports and exact regeneration (MIT)."""
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'instructions.json', 'verify.py'})
EXPECTED = {'locations': 15, 'location_leas': 28, 'scoped_fdes': 11,
            'diagnostics_probed': 11, 'diagnostics_bound': 10, 'diagnostics_unresolved': 0,
            'diagnostics_absent': 1, 'pointer_length_anchors': 9, 'counted_fragment_anchors': 16,
            'constants_bound': 0, 'constants_unresolved': 9, 'scoped_rel32_calls': 10,
            'scoped_rel32_jumps': 0}
EXPECTED_LOCS = (('0x5692cb0',65,96), ('0x5692cc8',67,13), ('0x569e630',19,60),
 ('0x569e648',29,64), ('0x569e660',65,96), ('0x571cf28',47,13),
 ('0x571cf40',39,111), ('0x571cf58',59,17), ('0x571cf70',19,60),
 ('0x571cf88',65,96), ('0x571cfa0',67,13), ('0x572ecf8',19,60),
 ('0x572ed10',65,96), ('0x5738568',19,60), ('0x5738580',65,96))


def check(ok, message):
    if not ok:
        raise ValueError(message)


def verify_manifest(here):
    names = set()
    for p in here.iterdir():
        check(not p.is_symlink(), 'packet symlink')
        if p.name == '__pycache__' and p.is_dir():
            check(all(x.is_file() and not x.is_symlink() and x.suffix == '.pyc' for x in p.iterdir()), 'unexpected cache')
            continue
        check(p.is_file(), 'unexpected packet directory')
        names.add(p.name)
    check(names == MANIFEST | {'MANIFEST.sha256'}, 'packet whitelist differs')
    raw = (here/'MANIFEST.sha256').read_text(encoding='ascii')
    check(raw.endswith('\n'), 'manifest missing newline')
    entries = {}
    for line in raw.splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(m is not None, 'malformed manifest')
        digest, name = m.groups()
        check(name in MANIFEST and name not in entries, 'unexpected or duplicate manifest entry')
        entries[name] = digest
    check(set(entries) == MANIFEST, 'missing manifest member')
    for name, digest in entries.items():
        check(hashlib.sha256((here/name).read_bytes()).hexdigest() == digest, 'manifest mismatch: '+name)


def load_tool():
    spec = importlib.util.spec_from_file_location('gossip_rpc_client_inventory', ROOT/'tools/gossip_rpc_client_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def tables(e):
    def block(tag, headers, rows):
        return '\n'.join(['<!-- BEGIN GENERATED '+tag+' -->', '| '+' | '.join(headers)+' |',
                          '| '+' | '.join(['---']*len(headers))+' |'] +
                         ['| '+' | '.join(str(c).replace('|', '\\|') for c in row)+' |' for row in rows] +
                         ['<!-- END GENERATED '+tag+' -->'])
    metrics = block('METRICS', ('Measure','Count'), sorted(e['metrics'].items()))
    locations = block('LOCATIONS', ('Slot VA','Line:column','LEA sites','FDE starts'),
                      [(x['va'], '%d:%d' % (x['line'],x['column']), ', '.join(x['lea_sites']), ', '.join(x['owning_fdes'])) for x in e['locations']])
    fdes = block('FDES', ('FDE start','End exclusive','Bytes'), [(x['start'],x['end_exclusive'],x['size']) for x in e['fdes']])
    literals = block('LITERALS', ('Candidate','Status','Occurrences','Anchors'),
                     [(x['probe'],x['status'],len(x['occurrences']),len(x['anchors'])) for x in e['diagnostics']])
    anchors = block('ANCHORS', ('Candidate','FDE','LEA','Binding','Length'),
                    [(x['probe'],a['owner'],a['lea']['va'],a['kind'],a['length']) for x in e['diagnostics'] for a in x['anchors']])
    edges = block('EDGES', ('Caller FDE','Call VA','Bytes','Callee FDE'),
                  [(x['caller'],x['instruction']['va'],x['instruction']['bytes'],x['callee']) for x in e['call_edges']])
    constants = block('CONSTANTS', ('Candidate','Status'), [(x['candidate'],x['status']) for x in e['constants']])
    return locals()


def verify_docs(here, evidence):
    derived = tables(evidence)
    for filename, tags in {'README.md': ('METRICS','LOCATIONS','FDES'),
                           'RESULT.md': ('METRICS','LITERALS','ANCHORS','EDGES','CONSTANTS')}.items():
        text = (here/filename).read_text(encoding='utf-8')
        found = re.findall(r'<!-- BEGIN GENERATED ([A-Z]+) -->.*?<!-- END GENERATED \1 -->', text, re.S)
        check(found == list(tags), 'report blocks differ: '+filename)
        for tag in tags:
            blocks = re.findall(r'<!-- BEGIN GENERATED '+tag+r' -->.*?<!-- END GENERATED '+tag+r' -->', text, re.S)
            check(blocks == [derived[tag.lower()]], 'report facts differ: '+filename+'/'+tag)


def verify_facts(e):
    check(e['target']['sha256'] == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f', 'target differs')
    check(e['scope_rule'] == 'node/src/gossip_rpc_client.rs', 'scope differs')
    check(all(e['metrics'].get(k) == v for k,v in EXPECTED.items()), 'pinned metrics differ')
    check(tuple((x['va'],x['line'],x['column']) for x in e['locations']) == EXPECTED_LOCS, 'Location census differs')
    check(e['method']['all_fde_records_checked'] == 121299, 'FDE census differs')
    starts = {f['start'] for f in e['fdes']}
    check(all(x['caller'] in starts and x['callee'] in starts for x in e['call_edges']), 'edge endpoint differs')


def verify_outputs(here, tool, result):
    for name in tool.OUTPUTS:
        check(tool.render(result[name]) == (here/name).read_bytes(), 'regeneration differs: '+name)
    verify_facts(result['inventory.json'])
    verify_docs(here, result['inventory.json'])


def main():
    verify_manifest(HERE)
    tool = load_tool()
    with (ROOT/tool.TARGET).open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        result = tool.build(data)
    verify_outputs(HERE, tool, result)
    print('PASS: whitelist, manifest, target digest, byte-identical regeneration and derived reports')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit('FAIL: '+str(exc))
