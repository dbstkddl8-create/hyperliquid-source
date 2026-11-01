#!/usr/bin/env python3
"""Independent stdlib ELF metadata reader; static GNU disassembly, no evaluator."""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent / 'main'
path = REPO / 'artifacts/node/94/hl-node'
target = path.read_bytes()
digest = lambda raw: hashlib.sha256(raw).hexdigest()
assert digest(target) == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
assert target[:6] == b'\x7fELF\x02\x01'
header = struct.unpack_from('<16sHHIQQQIHHHHHH', target)
_, etype, machine, _, entry, phoff, shoff, _, _, phsize, phcount, shsize, shcount, shstrindex = header
assert machine == 62 and phsize == 56 and shsize == 64
sections = [struct.unpack_from('<IIQQQQIIQQ', target, shoff + index * shsize) for index in range(shcount)]
namesrec = sections[shstrindex]
names = target[namesrec[4]:namesrec[4] + namesrec[5]]
def name(offset):
    return names[offset:names.index(b'\x00', offset)].decode()
sectionmap = {name(record[0]): record for record in sections}
programs = [struct.unpack_from('<IIQQQQQQ', target, phoff + index * phsize) for index in range(phcount)]
def at_va(va, size, executable=False):
    loads = [record for record in programs if record[0] == 1 and record[3] <= va and va + size <= record[3] + record[5]]
    assert len(loads) == 1
    record = loads[0]
    assert not executable or record[1] & 1
    offset = record[2] + va - record[3]
    return offset, target[offset:offset + size]

start, end = 0x1571D90, 0x1571F50
offset, body = at_va(start, end-start, True)
textsec = sectionmap['.text']
assert textsec[2] & 4 and textsec[3] <= start < end <= textsec[3] + textsec[5]
assert offset == textsec[4] + start - textsec[3]
assert digest(body) == '1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561'

ehh = sectionmap['.eh_frame_hdr']
assert target[ehh[4]:ehh[4] + 4] == bytes.fromhex('011b033b')
entries = struct.unpack_from('<I', target, ehh[4] + 8)[0]
selected = []
for index in range(entries):
    location = ehh[4] + 12 + index * 8
    initial, frame = struct.unpack_from('<ii', target, location)
    if ehh[3] + initial == start:
        selected.append((location, ehh[3] + frame))
assert len(selected) == 1
index_offset, frame_va = selected[0]
frame_offset, _ = at_va(frame_va, 4)
length = struct.unpack_from('<I', target, frame_offset)[0]
frame = target[frame_offset:frame_offset + length + 4]
cie_offset = frame_offset + 4 - struct.unpack_from('<I', frame, 4)[0]
cie_length = struct.unpack_from('<I', target, cie_offset)[0]
cie = target[cie_offset:cie_offset + cie_length + 4]
assert digest(cie) == '78b6da08ece7423d48f0be866ea3d8c0b62f6b7053852a71a7672b490842354f'
assert cie[16] == 0x1b
initial_delta, size = struct.unpack_from('<iI', frame, 8)
assert frame_va + 8 + initial_delta == start and size == len(body)
assert digest(frame) == 'a1971d0fd2ab367c1a62e45248e80340387202ba7ab5a1e566cb840b25d754fd'

caller_offset, caller = at_va(0x1571150, 19, True)
assert caller.hex() == '4889d14889f2488d35b3301004ff25a5ce1f04'
displacement = struct.unpack_from('<i', caller, 15)[0]
slot = 0x1571150 + 19 + displacement
assert slot == 0x576E008
slot_offset, slotraw = at_va(slot, 8)
assert slotraw == bytes(8)
relocations = []
all_in_body = []
for record in sections:
    if record[1] != 4:
        continue
    assert record[9] == 24 and record[5] % 24 == 0
    for record_offset in range(record[4], record[4] + record[5], 24):
        relocation_offset, info, addend = struct.unpack_from('<QQq', target, record_offset)
        if relocation_offset == slot:
            relocations.append({'section': name(record[0]), 'record_file_offset': record_offset,
                                'offset': relocation_offset, 'symbol': info >> 32,
                                'type': info & 0xffffffff, 'addend': addend})
        if start <= relocation_offset < end:
            all_in_body.append(record_offset)
assert len(relocations) == 1 and relocations[0]['symbol'] == 0
assert relocations[0]['type'] == 8 and relocations[0]['addend'] == start
assert not all_in_body

published = bytes.fromhex((REPO / 'research/work-items/RE-002-libcore-write-fmt448/fixtures/official.hex').read_text())
assert published == body
licenses = {}
for filename in ('LICENSE-MIT', 'NOTICE.txt'):
    original = REPO / 'research/work-items/RE-002-libcore-write-fmt448/fixtures' / filename
    licenses[filename] = {'sha256': digest(original.read_bytes()), 'bytes': original.stat().st_size}
assert b'THE SOFTWARE IS PROVIDED' in (REPO / 'research/work-items/RE-002-libcore-write-fmt448/fixtures/LICENSE-MIT').read_bytes()

(ROOT / 'body.bin').write_bytes(body)
provider = Path('/usr/bin/objdump').resolve()
version = subprocess.run([str(provider), '--version'], capture_output=True, check=True).stdout.decode().splitlines()[0]
argv = [str(provider), '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
        '--insn-width=16', '--adjust-vma=' + str(start), 'body.bin']
observed = subprocess.run(argv, cwd=ROOT, capture_output=True, check=True)
(ROOT / 'formatter-native.stdout').write_bytes(observed.stdout)
(ROOT / 'formatter-native.stderr').write_bytes(observed.stderr)
rows = []
for line in observed.stdout.decode().splitlines():
    match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)', line)
    if match:
        rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
assert len(rows) == 138 and sum(len(row[1]) for row in rows) == 448
assert b''.join(row[1] for row in rows) == body
indirect_calls = [hex(row[0]) for row in rows if row[2].startswith('call')]
indirect_tails = [hex(row[0]) for row in rows if row[2].startswith('jmp') and row[2].split()[-1] == 'rax']
branches = [row for row in rows if re.match(r'j\w+\s+0x[0-9a-f]+$', row[2])]
assert len(indirect_calls) == 3 and len(indirect_tails) == 1 and len(branches) == 26
assert all(start <= int(row[2].split()[-1], 16) < end for row in branches)
receipt = {'schema': 'independent-formatter448-native-review-v1',
           'target': {'sha256': digest(target), 'bytes': len(target)},
           'range': {'start': start, 'end': end, 'bytes': len(body), 'file_offset': offset, 'sha256': digest(body)},
           'eh_frame': {'index_entry_file_offset': index_offset, 'fde_va': frame_va,
                        'fde_file_offset': frame_offset, 'fde_bytes': len(frame), 'fde_sha256': digest(frame),
                        'cie_file_offset': cie_offset, 'cie_sha256': digest(cie)},
           'caller': {'va': 0x1571150, 'file_offset': caller_offset, 'bytes': caller.hex(),
                      'slot': slot, 'slot_file_offset': slot_offset, 'relocations': relocations},
           'body_relocation_fields': all_in_body, 'official_published_excerpt_raw_equal': True,
           'rights': licenses, 'provider': {'path': str(provider), 'sha256': digest(provider.read_bytes()),
                                          'version': version, 'argv': argv, 'exit': observed.returncode,
                                          'stdout_sha256': digest(observed.stdout), 'stderr_sha256': digest(observed.stderr)},
           'rows': len(rows), 'local_direct_branches': len(branches),
           'indirect_calls': indirect_calls, 'indirect_tail_jumps': indirect_tails,
           'limitations': ['Static raw bytes and GNU disassembly only; no captured code or instruction evaluator.',
                           'No global function census, native renderer/private ABI, unwind execution or whole-node claim.',
                           'Official excerpt rights reviewed; complete source archive not reauthenticated in this receipt.']}
(ROOT / 'FORMATTER-NATIVE-REVIEW.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({'receipt_sha256': digest((ROOT / 'FORMATTER-NATIVE-REVIEW.json').read_bytes()),
                  'script_sha256': digest(Path(__file__).read_bytes()), 'range': receipt['range'],
                  'provider': receipt['provider'], 'rows': len(rows), 'branches': len(branches)}, sort_keys=True))
