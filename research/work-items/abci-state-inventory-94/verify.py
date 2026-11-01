#!/usr/bin/env python3
"""Stdlib-only whitelist, manifest, target facts and regeneration (MIT)."""
import hashlib
import importlib.util
import mmap
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'instructions.json', 'verify.py'})
EXPECTED_LOCATIONS = (('0x569db28', 398, 78),
 ('0x569db50', 196, 9),
 ('0x569db68', 196, 32),
 ('0x569db80', 203, 9),
 ('0x569db98', 209, 13),
 ('0x56c4e48', 145, 17),
 ('0x56c4e60', 145, 35),
 ('0x56c4e78', 154, 83),
 ('0x56c4e90', 188, 56),
 ('0x56c4ea8', 190, 17),
 ('0x56c4ec0', 190, 64),
 ('0x56dfba0', 60, 77),
 ('0x56dfbc8', 63, 100),
 ('0x56dfbe0', 66, 21),
 ('0x56dfbf8', 107, 37),
 ('0x56dfc10', 97, 9),
 ('0x56dfc28', 86, 40),
 ('0x571fda8', 398, 78),
 ('0x571fdd0', 196, 9),
 ('0x571fde8', 196, 32),
 ('0x571fe00', 203, 9),
 ('0x571fe18', 209, 13),
 ('0x572e3e8', 145, 17),
 ('0x572e400', 145, 35),
 ('0x572e418', 154, 83),
 ('0x572e430', 188, 56),
 ('0x572e448', 190, 17),
 ('0x572e460', 190, 64))
EXPECTED_FDES = (('0x2208580', '0x2208e5c'),
 ('0x2208e60', '0x220944c'),
 ('0x2209450', '0x22095bd'),
 ('0x22ae8a0', '0x22b107c'),
 ('0x2811e40', '0x2812291'),
 ('0x28122a0', '0x2812794'),
 ('0x28127a0', '0x2812adb'),
 ('0x32725d0', '0x3272b3a'),
 ('0x3273810', '0x327396c'),
 ('0x444b430', '0x444c305'),
 ('0x444c310', '0x444d1e5'),
 ('0x446da60', '0x446e04c'),
 ('0x446e050', '0x446e63c'),
 ('0x446e640', '0x446e7ad'),
 ('0x4546ba0', '0x4546c51'),
 ('0x46cea60', '0x46cf026'),
 ('0x46cf030', '0x46cf481'),
 ('0x46cf490', '0x46cf984'),
 ('0x46cf990', '0x46cfe84'),
 ('0x46cfe90', '0x46d0456'))
EXPECTED_EDGES = (('0x22aefea', '0x22ae8a0', '0x3c155a0'),
 ('0x3273862', '0x3273810', '0x3c155a0'),
 ('0x4546bca', '0x4546ba0', '0x3c155a0'))
EXPECTED_METRICS = {'call_edges': 3,
 'constant_operand_anchors': 18,
 'constants_bound': 3,
 'constants_unresolved': 9,
 'counted_fragment_anchors': 12,
 'decoded_instructions': 7052,
 'diagnostics_absent': 3,
 'diagnostics_bound': 4,
 'diagnostics_probed': 10,
 'diagnostics_unresolved': 3,
 'indirect_calls_unresolved': 409,
 'indirect_jumps_unresolved': 4,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 169,
 'location_leas': 38,
 'locations': 28,
 'named_callee_rel32_calls': 3,
 'pointer_length_anchors': 4,
 'scoped_fde_bytes': 37052,
 'scoped_fdes': 20,
 'scoped_rel32_calls': 0,
 'scoped_rel32_jumps': 0,
 'shared_first_party_fdes': 2,
 'source_setup_triplets': 5,
 'unique_line_column': 17,
 'unresolved_external_rel32_calls': 213,
 'unresolved_external_rel32_jumps': 0}
EXPECTED_SEEDS = (('0x2208580', True, True),
 ('0x2208e60', True, True),
 ('0x2209450', True, True),
 ('0x22ae8a0', True, True),
 ('0x32725d0', True, True),
 ('0x3273810', True, True),
 ('0x444b430', True, True),
 ('0x444c310', True, True),
 ('0x446da60', True, True),
 ('0x446e050', True, True),
 ('0x446e640', True, True),
 ('0x4546ba0', True, True),
 ('0x46cea60', True, True),
 ('0x46cf030', True, True),
 ('0x46cf490', True, True),
 ('0x46cf990', True, True),
 ('0x46cfe90', True, True))
EXPECTED_DIAGNOSTICS = (('rmp', 'bound', ('0x2208eeb', '0x32726c1', '0x446daeb', '0x446e0db')),
 ('@@ linked abci state @@', 'bound', ('0x22091bb', '0x446ddbb', '0x446e3ab')),
 ('@@ serialized abci state @@',
  'bound',
  ('0x28120ce', '0x2812591', '0x28129b0', '0x46cee22', '0x46cf2be', '0x46cf781', '0x46cfc81', '0x46d0252')),
 ('@@ successfully translated abci state', 'bound', ('0x22af155',)),
 ('exchange', 'present-but-unbound', ()),
 ('/dev/null', 'present-but-unbound', ()),
 ('assertion failed: freeze_height >= self.locus.context.height()', 'present-but-unbound', ()),
 ('reference-line-119 (hash only)', 'absent', ()),
 ('reference-line-165 (hash only)', 'absent', ()),
 ('reference-line-497 (hash only)', 'absent', ()))
EXPECTED_CONSTANTS = (('EDX operand 0x810',
  'bound',
  2064,
  ('0x2209209',
   '0x2209223',
   '0x2209239',
   '0x22094d2',
   '0x22094e9',
   '0x2209500',
   '0x446de09',
   '0x446de23',
   '0x446de39',
   '0x446e3f9',
   '0x446e413',
   '0x446e429',
   '0x446e6c2',
   '0x446e6d9',
   '0x446e6f0')),
 ('EDX operand 0x3ae8', 'bound', 15080, ('0x32727a6', '0x3272945')),
 ('EDX operand 0x1fb8', 'bound', 8120, ('0x32738c5',)),
 ('candidate response tag', 'unresolved', None, ()),
 ('success tag', 'unresolved', None, ()),
 ('missing-state tag', 'unresolved', None, ()),
 ('mismatch tag', 'unresolved', None, ()),
 ('freeze option tag offset', 'unresolved', None, ()),
 ('freeze option value offset', 'unresolved', None, ()),
 ('height offset', 'unresolved', None, ()),
 ('first serialized field offset', 'unresolved', None, ()),
 ('second serialized field offset', 'unresolved', None, ()))
EXPECTED_TRIPLETS = (('0x2208e60', ('0xcb8', '0x15c0', '0x1ec8')),
 ('0x2209450', ('0xcb8', '0x15c0', '0x1ec8')),
 ('0x446da60', ('0x1738', '0x2040', '0x2948')),
 ('0x446e050', ('0xcb8', '0x15c0', '0x1ec8')),
 ('0x446e640', ('0xcb8', '0x15c0', '0x1ec8')))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_manifest(here):
    actual = set()
    for path in here.iterdir():
        check(not path.is_symlink(), f'symlink in packet: {path.name}')
        # Python import cache is transient and contains no packet evidence.
        if path.name == '__pycache__' and path.is_dir():
            check(all(p.is_file() and not p.is_symlink() and p.suffix == '.pyc' for p in path.iterdir()),
                  'unexpected import cache contents')
            continue
        check(path.is_file(), f'unexpected directory: {path.name}')
        actual.add(path.name)
    check(actual == MANIFEST | {'MANIFEST.sha256'}, 'packet file whitelist differs')
    raw = (here/'MANIFEST.sha256').read_text(encoding='ascii')
    check(raw.endswith('\n'), 'manifest lacks final newline')
    entries = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(match is not None, 'malformed manifest entry')
        digest, name = match.groups()
        check(name in MANIFEST and name not in entries, 'unexpected or duplicate manifest member')
        entries[name] = digest
    check(set(entries) == MANIFEST, 'manifest omits required file')
    for name, digest in entries.items():
        check(hashlib.sha256((here/name).read_bytes()).hexdigest() == digest, f'manifest mismatch: {name}')


def load_tool():
    spec = importlib.util.spec_from_file_location('abci_state_inventory', ROOT/'tools/abci_state_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_docs(here, tool, evidence):
    tables = tool.evidence_tables(evidence)
    expected = {'README.md': ('METRICS', 'LOCATIONS', 'FDES', 'ATTRIBUTION'),
                'RESULT.md': ('METRICS', 'LITERALS', 'ANCHORS', 'EDGES', 'CONSTANTS', 'TRIPLETS')}
    for name, tags in expected.items():
        text = (here/name).read_text(encoding='utf-8')
        blocks = re.findall(r'<!-- BEGIN GENERATED ([A-Z]+) -->.*?<!-- END GENERATED \1 -->', text, re.S)
        check(blocks == list(tags), f'derived report blocks differ: {name}')
        for tag in tags:
            blocks = re.findall(f'<!-- BEGIN GENERATED {tag} -->.*?<!-- END GENERATED {tag} -->', text, re.S)
            check(blocks == [tables[tag]], f'derived metrics/facts differ: {name}/{tag}')


def tool_seeds():
    return load_tool().SEEDS


def verify_facts(evidence):
    actual = tuple((x['va'], x['line'], x['column']) for x in evidence['locations'])
    check(actual == EXPECTED_LOCATIONS, 'pinned Location layout differs')
    check(evidence['scope_rule'] == 'l1/src/abci/state.rs', 'scope differs')
    check(evidence['metrics'] == EXPECTED_METRICS, 'pinned counts differ')
    check(tuple((f['start'], f['end_exclusive']) for f in evidence['fdes']) == EXPECTED_FDES,
          'pinned FDE ranges differ')
    check(tuple((e['instruction']['va'], e['caller'], e['callee']) for e in evidence['call_edges']) == EXPECTED_EDGES,
          'pinned call edges differ')
    check(tuple((x['address'], x['fde_start'], x['references_scoped_location'])
                for x in evidence['seed_checks']) == EXPECTED_SEEDS, 'seed checks differ')
    check(tuple((x['probe'], x['status'], tuple(a['lea']['va'] for a in x['anchors']))
                for x in evidence['diagnostics']) == EXPECTED_DIAGNOSTICS, 'diagnostic anchors differ')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    check(tuple((x['candidate'], x['status'], x['value'], tuple(a['instruction']['va'] for a in x['anchors']))
                for x in evidence['constants']) == EXPECTED_CONSTANTS, 'constant operands differ')
    check(tuple((x['owner'], tuple(x['source_displacements'])) for x in evidence['source_setup_triplets'])
          == EXPECTED_TRIPLETS, 'source setup triplets differ')
    for edge in evidence['call_edges']:
        check(edge['caller'] in {f['start'] for f in evidence['fdes']} and
              edge['callee'] in {f['start'] for f in evidence['fdes'] + evidence['named_callees']}, 'edge endpoint differs')


def verify_outputs(here, tool, result):
    for name in tool.OUTPUTS:
        check(tool.render(result[name]) == (here/name).read_bytes(), f'regeneration differs: {name}')
    verify_facts(result['inventory.json'])
    verify_docs(here, tool, result['inventory.json'])


def main():
    verify_manifest(HERE)
    tool = load_tool()
    with (ROOT/tool.TARGET).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = tool.build(data)
    verify_outputs(HERE, tool, result)
    print('PASS: whitelist, manifest, node #94 digest, exact regeneration, target facts and derived report counts')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(f'FAIL: {exc}')
