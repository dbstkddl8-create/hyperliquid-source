#!/usr/bin/env python3
"""Independent static readers and actual raw-output review; never compiles/runs."""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent / 'arithmetic'
RUN = REPO / 'work/u128-remainder-qualified'
PACKET = REPO / 'research/work-items/RE-004-u128-remainder-94'
CRATE = 'node94_u128_remainder'
BODY = '12f5828bd833666b6023e761036da32c29aeb7d1e7eedbb93d734f730f391e26'
sha = lambda data: hashlib.sha256(data).hexdigest()
jread = lambda path: json.loads(path.read_bytes())

def ar_members(raw):
    assert raw[:8] == b'!<arch>\n'
    position, longnames, members = 8, b'', []
    while position < len(raw):
        header = raw[position:position+60]
        assert len(header) == 60 and header[-2:] == b'`\n'
        label, size = header[:16].decode().strip(), int(header[48:58])
        offset = position + 60
        body = raw[offset:offset+size]
        assert len(body) == size
        if label == '//':
            longnames = body
        elif label not in ('/', '/SYM64/'):
            if label.startswith('/') and label[1:].isdigit():
                index = int(label[1:])
                label = longnames[index:longnames.index(b'/\n', index)].decode()
            else:
                label = label.removesuffix('/')
            members.append((label, body))
        position = offset + size + size % 2
    assert position == len(raw)
    return members

class Elf:
    def __init__(self, raw):
        self.raw = raw
        self.header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
        assert self.header[0][:6] == b'\x7fELF\x02\x01' and self.header[2] == 62
        assert self.header[11] == 64
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', raw, self.header[6] + i*64)
                         for i in range(self.header[12])]
        self.names = self.section_data(self.header[13])
    def cstr(self, raw, offset):
        return raw[offset:raw.index(b'\x00', offset)].decode()
    def section_data(self, index):
        section = self.sections[index]
        return self.raw[section[4]:section[4]+section[5]]
    def section_name(self, index):
        return self.cstr(self.names, self.sections[index][0])
    def named(self, name):
        choices = [index for index in range(len(self.sections)) if self.section_name(index) == name]
        assert len(choices) == 1
        return self.sections[choices[0]]
    def symbols(self):
        result = []
        for table_index, table in enumerate(self.sections):
            if table[1] != 2:
                continue
            names = self.section_data(table[6])
            assert table[9] == 24
            for ordinal, offset in enumerate(range(table[4], table[4]+table[5], 24)):
                name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', self.raw, offset)
                result.append({'index': ordinal, 'symtab': table_index, 'name': self.cstr(names, name),
                               'info': info, 'other': other, 'section': section, 'value': value, 'size': size})
        return result
    def function(self, symbol):
        section = self.sections[symbol['section']]
        assert section[1] == 1 and section[2] & 4
        assert symbol['value'] == 0 and symbol['size'] == section[5]
        return self.section_data(symbol['section'])
    def code_relocation_refs(self, section_index):
        by_table = {}
        for symbol in self.symbols():
            by_table[symbol['symtab'], symbol['index']] = symbol
        result = []
        for table in self.sections:
            assert not (table[1] == 9 and table[7] == section_index)
            if table[1] == 4 and table[7] == section_index:
                assert table[9] == 24
                for position in range(table[4], table[4]+table[5], 24):
                    offset, info, addend = struct.unpack_from('<QQq', self.raw, position)
                    result.append((offset, info & 0xffffffff, addend, by_table[table[6], info >> 32]['name']))
        return result
    def at_va(self, va, size, executable=False):
        assert self.header[9] == 56
        programs = [struct.unpack_from('<IIQQQQQQ', self.raw, self.header[5]+i*56)
                    for i in range(self.header[10])]
        matches = [row for row in programs if row[0] == 1 and row[3] <= va < va+size <= row[3]+row[5]]
        assert len(matches) == 1
        load = matches[0]
        assert not executable or load[1] & 1
        offset = load[2] + va - load[3]
        sections = [row for row in self.sections if row[1] != 8 and row[2] & 2
                    and row[3] <= va < va+size <= row[3]+row[5]]
        assert len(sections) == 1 and (not executable or sections[0][2] & 4)
        assert offset == sections[0][4] + va - sections[0][3]
        return offset, self.raw[offset:offset+size]

result = jread(RUN / 'RESULT.json')
calls = jread(RUN / 'CALLS.json')
assert sha((RUN/'RESULT.json').read_bytes()) == '15014479508c5b32a539523acd2fedcd449baafaf9725571e6b3276c2f069ebe'
assert calls == result['calls'] and len(calls) == 37
raw = {}
for call in calls:
    expected_exit = 101 if call['label'].startswith('mutant-') and call['label'].endswith('-ordinary-run') else 0
    assert call['exit_code'] == expected_exit
    for kind, record in call['logs'].items():
        data = (RUN / record['file']).read_bytes()
        assert len(data) == record['bytes'] and sha(data) == record['sha256']
        raw[call['label'], kind] = data
assert result['git_before'] == result['git_after']
assert result['git_before']['head'] == '7184a190e9f3107e40946ff4d93389ccc62d606b'
assert result['git_before']['status'] == ' M research/byte-windows.json\n'
assert result['physical_inputs_before'] == result['physical_inputs_after']
assert len(result['physical_inputs_before']) == result['physical_input_count'] == 9485
assert result['source_before'] == result['source_after']
for path, expected in result['source_before'].items():
    assert sha(Path(path).read_bytes()) == expected, path
assert (RUN/'comparison-main.rs').read_bytes() == (REPO/'src/node94-u128-remainder/input_only_driver.rs').read_bytes()
assert (RUN/'inputs.txt').read_bytes() == (HERE/'umod197-input.txt').read_bytes()
assert (RUN/'expected.txt').read_bytes() == (HERE/'umod197-expected.txt').read_bytes()
authority = jread(HERE/'umod197-authority.json')
cases = authority['cases']
expected_lines = (HERE/'umod197-expected.txt').read_bytes().splitlines()
assert len(cases) == len(expected_lines) == 53366
profiles = []
for profile in result['profiles']:
    name = profile['name']
    data = raw[name+'-production-run', 'stdout']
    assert data == (HERE/'umod197-expected.txt').read_bytes()
    assert sha(Path(profile['production']).read_bytes()) == profile['production_sha256']
    assert b'1 passed; 0 failed' in raw[name+'-ordinary-run', 'stdout']
    profiles.append({'name': name, 'cases': len(data.splitlines()), 'exact_output_sha256': sha(data),
                     'production_sha256': profile['production_sha256'], 'ordinary_methods': 1,
                     'unit_fixture_vectors_in_method': 13})

mutants = []
for mutant in result['semantic_mutants']:
    name = mutant['name']
    actual = raw['mutant-'+name+'-production-run', 'stdout'].splitlines()
    assert len(actual) == 53366 and mutant['production_exit'] == 0
    assert sha((RUN/('mutant-'+name)/'lib.rs').read_bytes()) == mutant['source_sha256']
    mismatches = []
    witness = None
    for row, expected, case in zip(actual, expected_lines, cases):
        identifier, number = row.split(b'|')
        assert identifier.decode() == case['id'] and re.fullmatch(rb'[0-9a-f]{32}', number)
        n, d = int(case['n'], 16), int(case['d'], 16)
        # Closed forms for these two controls provide a separate check of all
        # actual wrong values. Strict > can compound an equality error over
        # later bits, so retain its complete normal values and exact witness
        # rather than inventing a closed-form remainder rule for that mutant.
        if name == 'skip-top-input-bit':
            assert int(number, 16) == (n % (1 << 127)) % d
        elif name == 'omit-residue-subtraction':
            assert int(number, 16) == n
        if row != expected:
            mismatches.append(identifier.decode())
            if witness is None:
                witness = {'id':case['id'],'n':case['n'],'d':case['d'],
                           'actual':number.decode(),'expected':case['remainder']}
    assert len(mismatches) == mutant['different_transcripts']
    assert mismatches[:8] == mutant['sample_mismatch_ids']
    failure = raw['mutant-'+name+'-ordinary-run', 'stdout'] + raw['mutant-'+name+'-ordinary-run', 'stderr']
    assert b'FAILED' in failure and b'panicked at' in failure
    mutants.append({'name': name, 'normal_exit': 0, 'normal_rows': 53366,
                    'all_values_match_separate_closed_form': name != 'strict-subtraction-boundary',
                    'explicit_wrong_value_witness':witness,'mismatches': len(mismatches),
                    'mismatch_ids_sha256': sha(('\n'.join(mismatches)+'\n').encode()),
                    'ordinary_semantic_assertion_failure_exit': 101})
assert [row['mismatches'] for row in mutants] == [5341, 10847, 27945]

own_libraries = []
for check in result['own_library_static_checks']:
    label = check['label']
    directory = {'build-only-delegation-wrapper':'delegation-wrapper', 'debug-library':'debug',
                 'optimized-library':'optimized', 'repro-b':'repro-b'}.get(label)
    if directory is None:
        directory = label.removesuffix('-library') + '/library'
    directory = RUN / directory
    for filename, record in check['files'].items():
        data = (directory/filename).read_bytes()
        assert len(data) == record['bytes'] and sha(data) == record['sha256']
    undefined, definitions = set(), []
    for member, data in ar_members((directory/('lib'+CRATE+'.rlib')).read_bytes()):
        if data[:4] != b'\x7fELF':
            continue
        image = Elf(data)
        for symbol in image.symbols():
            if symbol['section'] == 0 and symbol['name']:
                undefined.add(symbol['name'])
            if symbol['section'] and symbol['info'] & 15 == 2 and CRATE in symbol['name'] and 'remainder' in symbol['name']:
                body = image.function(symbol)
                definitions.append({'symbol':symbol,'body_bytes':len(body),'body_sha256':sha(body),
                                    'code_refs':image.code_relocation_refs(symbol['section'])})
    assert sorted(undefined) == check['undefined_symbols'] and len(definitions) == 1
    observed = definitions[0]
    recorded = check['remainder_definitions'][0]
    assert observed['symbol'] == recorded['symbol']
    assert observed['body_bytes'] == recorded['body_bytes'] and observed['body_sha256'] == recorded['body_sha256']
    assert observed['code_refs'] == [(r['offset'],r['kind'],r['addend'],r['symbol']['name']) for r in recorded['code_relocations']]
    ir = (directory/(CRATE+'.ll')).read_text()
    operations = sorted(set(re.findall(r'\b(?:udiv|urem|sdiv|srem)\b', ir)))
    forbidden = sorted(name for name in undefined if re.search(r'__(?:u?div|u?mod|u?rem|sdiv|smod)',name))
    assert operations == check['IR_division_operations'] and forbidden == check['forbidden_symbols']
    if label == 'build-only-delegation-wrapper':
        assert operations == ['urem'] and forbidden == ['__umodti3']
        assert check['verdict'] == 'REJECTED_BEFORE_CLIENT_LINK_OR_EXECUTION'
        assert not any('delegation' in call['label'] and ('production' in call['label'] or 'ordinary' in call['label']) for call in calls)
    else:
        assert not operations and not forbidden
        disassembly = raw[label+'-own-object-disassembly', 'stdout'].decode()
        machine = []
        for line in disassembly.splitlines():
            fields = line.split('\t')
            if len(fields) >= 3 and fields[-1].strip().split():
                if fields[-1].strip().split()[0] in ('div','idiv'):
                    machine.append(line)
        assert not machine and not check['machine_division_instructions']
    own_libraries.append({'label':label,'files_checked':3,'actual_function_bytes':observed['body_bytes'],
                          'actual_function_sha256':observed['body_sha256'],'undefined_symbols':sorted(undefined),
                          'IR_division_operations':operations,'forbidden_symbols':forbidden,'verdict':check['verdict']})
assert len(own_libraries) == 7
a = (RUN/'optimized'/('lib'+CRATE+'.rlib')).read_bytes()
b = (RUN/'repro-b'/('lib'+CRATE+'.rlib')).read_bytes()
assert a == b and len(a) == 6926 and sha(a) == '353c7287dc0056467b3d192a6bb040049a213352e06a375df5fc0d08bfbe98c4'

audit = jread(PACKET/'preparation/PROVIDER-AUDIT.json')
prefix = HERE.parent/'toolchain/prefix'
assert len(audit['payloads']) == 103 and result['provider_before'] == result['provider_after']
for row in audit['payloads']:
    data = (prefix/row['path']).read_bytes()
    assert len(data) == row['bytes'] and sha(data) == row['sha256'] == result['provider_before'][row['path']]
for filename, expected in audit['installed_manifest_sha256'].items():
    assert sha((prefix/'lib/rustlib'/filename).read_bytes()) == expected
for path, expected in [(result['compiler']['path'],result['compiler']['sha256']),
                       (result['linker']['path'],result['linker']['sha256']),
                       (result['linker']['actual_ld'],result['linker']['actual_ld_sha256']),
                       (result['analysis_provider']['path'],result['analysis_provider']['sha256'])]:
    assert sha(Path(path).resolve().read_bytes()) == expected
pins = subprocess.check_output(['git','submodule','status','--recursive'],cwd=REPO,text=True)
assert pins == result['git_before']['actual_submodule_pins'] and len(pins.splitlines()) == 7

target = (REPO/'artifacts/node/94/hl-node').read_bytes()
assert sha(target) == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
image = Elf(target)
start,size,slot = 0x565f7f0,197,0x576e518
file_offset,body = image.at_va(start,size,True)
assert sha(body) == BODY and body == (PACKET/'native/target-197.bin').read_bytes()
ehh = image.named('.eh_frame_hdr')
assert target[ehh[4]:ehh[4]+4] == bytes.fromhex('011b033b')
count = struct.unpack_from('<I',target,ehh[4]+8)[0]
fdes = []
for ordinal in range(count):
    initial,frame = struct.unpack_from('<ii',target,ehh[4]+12+ordinal*8)
    if ehh[3]+initial == start:
        fdes.append(ehh[3]+frame)
assert len(fdes) == 1
frame_offset,_ = image.at_va(fdes[0],4)
length = struct.unpack_from('<I',target,frame_offset)[0]
frame = target[frame_offset:frame_offset+length+4]
delta,extent = struct.unpack_from('<iI',frame,8)
assert fdes[0]+8+delta == start and extent == size and len(frame) == 24
writes = []
for section in image.sections:
    if section[1] == 4:
        for position in range(section[4],section[4]+section[5],24):
            offset,info,addend = struct.unpack_from('<QQq',target,position)
            assert not (offset < start+size and offset+8 > start)
            if offset < slot+8 and offset+8 > slot:
                writes.append((offset,info,addend))
assert writes == [(slot,8,start)]
archive = (prefix/'lib/rustlib/x86_64-unknown-linux-gnu/lib/libcompiler_builtins-58c8d4715a55733a.rlib').read_bytes()
assert len(archive) == 4400606 and sha(archive) == 'f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6'
official = []
for member,data in ar_members(archive):
    if data[:4] != b'\x7fELF':
        continue
    elf = Elf(data)
    for symbol in elf.symbols():
        if symbol['section'] and symbol['info'] & 15 == 2 and '__umodti3' in symbol['name']:
            candidate = elf.function(symbol)
            assert candidate == body and not elf.code_relocation_refs(symbol['section'])
            official.append({'member':member,'member_sha256':sha(data),'symbol':symbol['name'],
                             'bytes':len(candidate),'sha256':sha(candidate)})
assert len(official) == 2
registry = jread(REPO/'research/byte-windows.json')
matches = [row for row in registry['windows'] if row['target']=='node94' and row['start']<start+size and row['end']>start]
assert len(matches) == 1 and matches[0]['id'] == 'node94-u128-remainder'
assert (matches[0]['start'],matches[0]['end']) == (start,start+size)
assert matches[0]['source']['path'].endswith('native/official-unmangled-197.bin')
assert not matches[0]['relocations'] and matches[0]['target_body_sha256'] == BODY
receipt = {'schema':'umod197-independent-actual-artifact-native-review-v1','status':'PASS',
           'result_sha256':sha((RUN/'RESULT.json').read_bytes()),'calls_sha256':sha((RUN/'CALLS.json').read_bytes()),
           'commands':len(calls),'raw_streams':2*len(calls),'source_head':result['git_before']['head'],
           'declared_run_status':result['git_before']['status'],'physical_inputs_stable_during_run':9485,
           'all_current_executable_input_hashes_match':True,'provider_payloads_independently_checked':103,
           'current_installed_manifest_hashes_checked':True,'actual_pins_independently_checked':7,
           'profiles':profiles,'semantic_mutants':mutants,'own_library_checks':own_libraries,
           'raw_rlib_rebuild':{'bytes':len(a),'sha256':sha(a),'equal':True,'new_compiler_runs_by_reviewer':0},
           'native':{'start':start,'end':start+size,'body_file_offset':file_offset,'bytes':size,'body_sha256':sha(body),
                     'fde_file_offset':frame_offset,'fde_bytes':len(frame),'fde_sha256':sha(frame),'slot':slot,
                     'slot_unique_RELATIVE':writes,'official_definitions':official,'registered_target_interval_count':1},
           'rights_review_sha256':sha((HERE/'UMOD-RIGHTS-REVIEW.json').read_bytes()),
           'limits':['This independent review inspects retained real outputs, IR/objects and authenticated bytes; no compiler, captured target or instruction evaluator runs.',
                     'C1 intentionally retained a dirty byte-window registry; only actual source/pin/physical identities were stable during that experiment.',
                     'Native197 published-artifact raw identity is separate from numerical semantics and own-source reproducibility.',
                     'Zero divisor, original ABI/register-clobbers/runtime-unwind/caller-wide/whole-node equivalence and component gates remain open.']}
output = HERE/'UMOD-ACTUAL-ARTIFACT-REVIEW.json'
output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({'receipt_sha256':sha(output.read_bytes()),'commands':len(calls),'raw_streams':len(calls)*2,
                  'profiles':profiles,'semantic_mutants':mutants,'native_bytes':197,'own_libraries':len(own_libraries)},sort_keys=True))
