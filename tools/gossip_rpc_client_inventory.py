#!/usr/bin/env python3
"""Static node #94 exact gossip_rpc_client.rs inventory; stdlib only, MIT."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import mmap
import re
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
# Isolate the reusable MIT decoder's configuration from other importers.
spec = importlib.util.spec_from_file_location('_gossip_client_decoder', TOOLS/'node_inventory.py')
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)
n.SCOPE = b'node/src/gossip_rpc_client.rs'
TARGET, SHA256 = n.TARGET, n.SHA256
OUTPUTS = ('inventory.json', 'instructions.json')
SEEDS = (0x1fd4570, 0x2039060, 0x22615b0, 0x22689f0, 0x226bb20, 0x4356c90, 0x435cb20, 0x4387f40, 0x4389070, 0x4b29760)
REFERENCE = 'references/can1357-hl/node/gossip_rpc_client.rs'
REFERENCE_SHA256 = 'eff1f93ae2097f242ad12c9157f46a20ef24f4d07f88ffdb63dac96ca398a244'
PROBES = ('rpc connect', 'gossip response', 'request err:', 'querying client blocks',
          'send gossip rpc request', 'gossip_rpc_request', 'verify_rpc', 'verified gossip rpc',
          'starting bootstrap', 'finished bootstrap')
CONSTANTS = ('request timeout', 'verification timeout', 'connect timeout', 'bootstrap block limit',
             'response wait threshold', 'status retry delay', 'peer retry delay', 'per-block retry delay', 'retry delay cap')


def probes():
    n.require(n.sha((ROOT/REFERENCE).read_bytes()) == REFERENCE_SHA256, 'reference digest mismatch')
    probes = [{'id': 'lead-%d' % (i+1), 'probe': s, 'needle': s.encode('ascii'),
               'origin': 'binary literal checked using reference search leads'} for i, s in enumerate(PROBES)]
    # Keep the unlicensed, absent reference phrase out of committed evidence.
    # Extract a single quoted lead by digest, without embedding its text here.
    candidates = re.findall(rb'"([^"\\\n]+)"', (ROOT/REFERENCE).read_bytes())
    missing = [v for v in candidates if hashlib.sha256(v).hexdigest() == '874cfd5b0fede813d41c8e4cdddc7fb0e6a3837aca2a8aea293aca51eafb6808']
    n.require(len(missing) == 1, 'absent lead identity or count differs')
    probes.append({'id': 'absent-bootstrap-log-lead', 'probe': missing[0].decode('ascii'),
                   'needle': missing[0], 'origin': 'reference lead identified by digest'})
    return probes

n.diagnostic_probes = probes


def build(data):
    n.authenticate(data)
    image = n.Image(data)
    relocs = n.relative_relocations(image)
    locs = n.locations(image, relocs)
    n.require(locs, 'no exact-path Locations')
    del relocs
    fdes = n.Fdes(image)
    leas = n.scan_leas(image, locs)
    scoped, pending = {}, []
    for slot in locs:
        n.require(leas.get(slot), 'Location lacks a RIP LEA')
        for site in leas[slot]:
            owner = fdes.owner(site, 7)
            n.require(owner is not None, 'Location LEA lacks FDE')
            scoped[owner['start']] = owner
            pending.append((site, slot, owner['start']))
    decoded = {s: n.decode_fde(image, f) for s, f in sorted(scoped.items())}
    accepted = []
    for site, slot, start in sorted(pending):
        insn, reg = n.verified_lea(image, decoded[start], site, slot)
        i = next(i for i, x in enumerate(decoded[start]) if x['site'] == site)
        context = []
        for x in decoded[start][i+1:i+5]:
            context.append(n.instruction_evidence(image, x))
            if x['kind'] in ('call_rel32', 'jmp_rel32', 'call_indirect', 'jmp_indirect', 'branch'):
                break
        accepted.append({'location': hex(slot), 'owner': hex(start), 'destination_register_index': reg,
                         'instruction': n.instruction_evidence(image, insn), 'following_context': context})
    for slot, loc in locs.items():
        loc['lea_sites'] = [x['instruction']['va'] for x in accepted if x['location'] == hex(slot)]
        loc['owning_fdes'] = sorted({x['owner'] for x in accepted if x['location'] == hex(slot)})
    diagnostics = n.diagnostic_inventory(image, decoded)
    for d in diagnostics:
        if d['id'] == 'absent-bootstrap-log-lead':
            n.require(d['status'] == 'absent', 'absent lead changed')
            d['probe'] = 'bootstrap log lead (text withheld; see hash)'
    constants = [{'candidate': name, 'status': 'unresolved', 'reason': 'No unique decoded role and dataflow established in this scoped inventory.'} for name in CONSTANTS]
    edges = n.scoped_edges(image, decoded)
    counts = Counter()
    transfers = []
    for start, insns in sorted(decoded.items()):
        for insn in insns:
            kind = insn['kind']
            if kind in ('call_rel32', 'jmp_rel32'):
                target = n.decode_rel32_transfer(insn['raw'], insn['site'])
                disposition = 'scoped_fde_entry' if target in scoped else ('internal_instruction' if start <= target < scoped[start]['end'] else 'outside_scoped_entries_unresolved')
                counts[disposition+'_'+kind] += 1
                transfers.append({'caller': hex(start), 'disposition': disposition, 'instruction': n.instruction_evidence(image, insn)})
            elif kind in ('call_indirect', 'jmp_indirect'):
                counts[kind] += 1
    metrics = {'locations': len(locs), 'location_leas': len(accepted), 'scoped_fdes': len(scoped),
               'unique_line_column': len({(x['line'],x['column']) for x in locs.values()}),
               'scoped_fde_bytes': sum(f['end']-f['start'] for f in scoped.values()),
               'decoded_instructions': sum(map(len, decoded.values())), 'diagnostics_probed': len(diagnostics),
               'diagnostics_bound': sum(x['status']=='bound' for x in diagnostics),
               'diagnostics_unresolved': sum(x['status']=='present-but-unbound' for x in diagnostics),
               'diagnostics_absent': sum(x['status']=='absent' for x in diagnostics),
               'pointer_length_anchors': sum(a['kind'] != 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'counted_fragment_anchors': sum(a['kind'] == 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'constants_bound': 0, 'constants_unresolved': len(constants),
               'scoped_rel32_calls': sum(e['instruction']['kind']=='call_rel32' for e in edges),
               'scoped_rel32_jumps': sum(e['instruction']['kind']=='jmp_rel32' for e in edges),
               'unresolved_external_rel32_calls': counts['outside_scoped_entries_unresolved_call_rel32'],
               'unresolved_external_rel32_jumps': counts['outside_scoped_entries_unresolved_jmp_rel32'],
               'internal_rel32_calls': counts['internal_instruction_call_rel32'],
               'internal_rel32_jumps': counts['internal_instruction_jmp_rel32'],
               'indirect_calls_unresolved': counts['call_indirect'], 'indirect_jumps_unresolved': counts['jmp_indirect']}
    ev = {'schema_version': 1, 'work_item': 'gossip-rpc-client-inventory-94', 'task': 'RE-012 / node-runtime exact-file bounded inventory',
          'component': 'node-runtime', 'target': {'path': TARGET, 'sha256': SHA256, 'release': 94},
          'scope_rule': n.SCOPE.decode(), 'metrics': metrics,
          'coordinates': 'ELF link-time VA; file offsets explicit; FDE end exclusive',
          'source_commit': '3324e50333042b391312515e542279ca21f63dc8',
          'reference_leads': {'path': REFERENCE, 'sha256': REFERENCE_SHA256, 'commit': n.REFERENCE_COMMIT, 'text_or_code_copied': False},
          'producer_sources_sha256': {'tools/'+p: n.sha((TOOLS/p).read_bytes()) for p in ('gossip_rpc_client_inventory.py', 'node_inventory.py', 'elf_index.py', 'fde_extents.py')},
          'method': {'decoder': 'node_inventory restricted x86-64 linear byte decoder; no objdump',
                     'dependency': 'Python 3.10+ stdlib', 'all_fde_records_checked': len(fdes.rows),
                     'boundary_check': 'linear decode from FDE start plus internal direct branch alignment; not reachability',
                     'literal_binding': 'scoped LEA and adjacent pointer/length fields or register pair to call, or bounded counted ASCII chunk',
                     'absent_probe_rule': 'whole-file exact byte search', 'path_prefix_hex': n.PREFIX.hex(),
                     'normalization_masks': [], 'captured_binary_executed': False, 'network_used': False},
          'seed_checks': [{'address': hex(a), 'fde_start': bool(fdes.owner(a) and fdes.owner(a)['start']==a), 'references_scoped_location': a in scoped} for a in SEEDS],
          'locations': list(locs.values()), 'location_leas': accepted, 'fdes': [n.Fdes.record(image, f) for _, f in sorted(scoped.items())],
          'diagnostics': diagnostics, 'constants': constants, 'call_edges': edges, 'rel32_transfers': transfers,
          'non_claims': ['No runtime behavior, network activity, protocol semantics or source reconstruction.',
                         'No function ownership, reachability, complete call graph, build, binary equivalence or progress gate.',
                         'No claims for gossip_rpc.rs, gossip_config.rs, net_utils, consensus, startup.rs, node.rs, abci/state.rs or generic helpers.',
                         'FDEs are unwind extents, not proven function boundaries; inlining and code without FDEs remain gaps.',
                         'No indirect-call, helper, relocation, vtable/data or whole-ELF closure; no #115 or visor claim.']}
    transcript = {'target_sha256': SHA256, 'columns': ['offset_from_fde_start','raw_hex','decoded_kind'],
                  'fdes': [{'start': hex(s), 'end_exclusive': hex(scoped[s]['end']),
                            'instructions': [[hex(x['site']-s), x['raw'].hex(), x['kind']] for x in insns]} for s, insns in sorted(decoded.items())]}
    return {'inventory.json': ev, 'instructions.json': transcript}


def render(value):
    return n.render(value)


def generate(binary, out):
    with Path(binary).open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = build(data)
    Path(out).mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:
        Path(out, name).write_bytes(render(result[name]))
    return result['inventory.json']['metrics']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT/TARGET)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    try:
        print(json.dumps(generate(args.binary, args.out), sort_keys=True))
    except (ValueError, OSError) as exc:
        p.exit(1, 'FAIL: %s\n' % exc)

if __name__ == '__main__':
    main()
