#!/usr/bin/env python3
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
archive_path = ROOT.parent / 'toolchain/prefix/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'
archive = archive_path.read_bytes()
sha = lambda data: hashlib.sha256(data).hexdigest()
assert sha(archive) == 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256'
assert archive[:8] == b'!<arch>\n'
position = 8
longnames = b''
chosen = []
while position < len(archive):
    header = archive[position:position+60]
    assert len(header) == 60 and header[-2:] == b'`\n'
    size = int(header[48:58])
    label = header[:16].decode().strip()
    body_position = position + 60
    payload = archive[body_position:body_position+size]
    assert len(payload) == size
    if label == '//':
        longnames = payload
    elif label not in ('/', '/SYM64/'):
        if label.startswith('/') and label[1:].isdigit():
            offset = int(label[1:])
            label = longnames[offset:longnames.index(b'/\n', offset)].decode()
        else:
            label = label.removesuffix('/')
        if label == 'core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o':
            chosen.append((label, body_position, payload))
    position = body_position + size + (size % 2)
assert len(chosen) == 1 and position == len(archive)
label, member_position, member = chosen[0]
assert member_position == 46334 and len(member) == 2871296
assert sha(member) == '57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13'
header = struct.unpack_from('<16sHHIQQQIHHHHHH', member)
assert header[0][:6] == b'\x7fELF\x02\x01' and header[1:3] == (1, 62)
sections = [struct.unpack_from('<IIQQQQIIQQ', member, header[6] + index * header[11]) for index in range(header[12])]
string_section = sections[header[13]]
strings = member[string_section[4]:string_section[4] + string_section[5]]
cstr = lambda data, offset: data[offset:data.index(b'\x00', offset)].decode()
function_name = '_ZN4core3fmt5write17h469843d235cc4241E'
matching_sections = [(index, section) for index, section in enumerate(sections)
                     if cstr(strings, section[0]) == '.text.' + function_name]
assert len(matching_sections) == 1
index, section = matching_sections[0]
body = member[section[4]:section[4] + section[5]]
assert index == 370 and section[4] == 1302560 and section[5] == 448 and section[2] & 4
symbols = []
relocations = []
for record in sections:
    if record[1] == 2:
        names_section = sections[record[6]]
        names = member[names_section[4]:names_section[4] + names_section[5]]
        assert record[9] == 24
        for offset in range(record[4], record[4] + record[5], 24):
            symbol = struct.unpack_from('<IBBHQQ', member, offset)
            if cstr(names, symbol[0]) == function_name:
                symbols.append({'member_file_offset': offset, 'info': symbol[1], 'other': symbol[2],
                                'section': symbol[3], 'value': symbol[4], 'size': symbol[5]})
    if record[1] in (4, 9) and record[7] == index and record[5]:
        relocations.append(record)
assert len(symbols) == 1 and symbols[0]['section'] == index
assert symbols[0]['value'] == 0 and symbols[0]['size'] == 448 and not relocations
assert body == (ROOT / 'body.bin').read_bytes()
receipt = {'schema': 'independent-formatter448-official-archive-review-v1',
           'archive_sha256': sha(archive), 'archive_bytes': len(archive),
           'member_name': label, 'member_archive_offset': member_position,
           'member_bytes': len(member), 'member_sha256': sha(member),
           'function': function_name, 'section_index': index, 'member_file_offset': section[4],
           'body_bytes': len(body), 'body_sha256': sha(body), 'symbols': symbols,
           'source_REL_RELA_fields': [], 'raw_equal_to_current_target448': True,
           'rights': 'Complete Rust Project Contributors MIT-option license/notice retained in accepted1216 fixtures; no source Rust or whole object copied.',
           'limitations': ['This is static authentication of existing official archive; no compiler or object is run.',
                           'No original compiler uniqueness, renderer/private ABI, unwind or whole-build equivalence claim.']}
(ROOT / 'FORMATTER-OFFICIAL-REVIEW.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({'receipt_sha256': sha((ROOT / 'FORMATTER-OFFICIAL-REVIEW.json').read_bytes()),
                  'script_sha256': sha(Path(__file__).read_bytes()), 'body_sha256': sha(body)}, sort_keys=True))
