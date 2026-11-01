#!/usr/bin/env python3
"""Model and independent checker for node #94's string construction
from a C string (RE-001 work item, function at 0x514b6d0).

The model implements the behaviour pinned by
research/work-items/RE-001-string-ctor-cstr-94/records.json:
a null input throws, otherwise the content is the bytes up to the
first NUL (strlen semantics); lengths up to 15 use the object's own
16-byte buffer at +0x10, longer lengths use a heap buffer obtained
from _M_create with old-capacity 0, for which the capacity slot is
left equal to the requested length; a NUL terminator is stored at
buffer+length in both cases.

The checker re-verifies the packet against a node #94 binary
without trusting the packet's own verify script: it checks the
target digest, the function carve SHA, the int3 padding, the
branch/call targets re-derived from raw encodings, the PLT stubs
with their GOT relocations, the throw string bytes, the full
caller census, and every excerpt line's bytes against the binary.
It never lists instruction mnemonics: those live only in the raw
objdump excerpts.

Stdlib only. Run from the repository root:

    python3 tools/foundation_string_ctor_cstr.py --binary work/hl-node-94.bin
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    REPO_ROOT, "research", "work-items", "RE-001-string-ctor-cstr-94")
DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNC_START = 0x514B6D0
FUNC_END = 0x514B7B3
NEXT_FDE = 0x514B7B4
THROW_MESSAGE = "basic_string: construction from null is not valid"
SSO_MAX_LENGTH = 15


class LogicError(Exception):
    """The logic_error thrown for a null input."""


class StringObject:
    """Observable post-construction state of one string object."""

    def __init__(self, pointer, length, capacity_or_buffer, content):
        # pointer: "sso" for the object's own buffer, else a heap id.
        self.pointer = pointer
        self.length = length
        # For SSO this is the buffer bytes (content + terminator);
        # for heap it is the capacity number.
        self.capacity_or_buffer = capacity_or_buffer
        self.content = content

    @property
    def is_heap(self):
        return self.pointer != "sso"


def construct(cstr, heap_id="heap-buffer"):
    """Construct a string from a C string.

    ``cstr`` is None for a null pointer, else the raw memory bytes
    starting at the pointer; only bytes up to the first NUL are
    read, matching the strlen in the target function. Returns a
    StringObject, or raises LogicError for a null input.
    """
    if cstr is None:
        raise LogicError(THROW_MESSAGE)
    end = cstr.find(b"\x00")
    content = cstr if end < 0 else cstr[:end]
    length = len(content)
    if length <= SSO_MAX_LENGTH:
        return StringObject("sso", length, content + b"\x00", content)
    return StringObject(heap_id, length, length, content)


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping and section lookup."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        (self.e_shentsize, self.e_shnum) = struct.unpack_from("<HH", data, 0x3A)
        (self.e_shstrndx,) = struct.unpack_from("<H", data, 0x3E)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:  # PT_LOAD
                self.loads.append((p_vaddr, p_offset, p_filesz))
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            self.sections.append(struct.unpack_from("<IIQQQQIIQQ", data, off))
        shstr_off = self.sections[self.e_shstrndx][4]
        self.names = {}
        for idx, sec in enumerate(self.sections):
            end = data.index(b"\x00", shstr_off + sec[0])
            self.names[idx] = data[shstr_off + sec[0]:end].decode()

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x is not in any PT_LOAD segment" % va)

    def read_at(self, va, length):
        off = self.va_to_offset(va)
        return self.data[off:off + length]

    def section(self, name):
        for idx, sec in enumerate(self.sections):
            if self.names.get(idx) == name:
                return sec
        raise ValueError("no %s section" % name)

    def plt_symbol(self, got_slot):
        rela = self.section(".rela.plt")
        dynsym = self.section(".dynsym")
        dynstr = self.section(".dynstr")
        symtab = self.data[dynsym[4]:dynsym[4] + dynsym[5]]
        strtab = self.data[dynstr[4]:dynstr[4] + dynstr[5]]
        for i in range(rela[5] // 24):
            r_offset, r_info, _add = struct.unpack_from(
                "<QQq", self.data, rela[4] + i * 24)
            if r_offset != got_slot:
                continue
            sym = r_info >> 32
            st_name, = struct.unpack_from("<I", symtab, sym * 24)
            end = strtab.index(b"\x00", st_name)
            return (r_info & 0xFFFFFFFF, strtab[st_name:end].decode())
        raise ValueError("no .rela.plt entry for %#x" % got_slot)


def e8_callers(text, text_addr, target):
    hits = []
    pos = 0
    while True:
        pos = text.find(b"\xe8", pos)
        if pos < 0 or pos + 5 > len(text):
            break
        (rel,) = struct.unpack_from("<i", text, pos + 1)
        if text_addr + pos + 5 + rel == target:
            hits.append(text_addr + pos)
        pos += 1
    return hits


_EXCERPT_LINE = re.compile(
    r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)")


def check_excerpt_bytes(path, elf):
    """Every (address, bytes) line of an objdump excerpt vs the binary."""
    failures = []
    with open(path) as f:
        for line in f:
            m = _EXCERPT_LINE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            byts = bytes(int(t, 16) for t in m.group(2).split())
            try:
                actual = elf.read_at(addr, len(byts))
            except ValueError as exc:
                failures.append("%s: %s" % (path, exc))
                continue
            if actual != byts:
                failures.append(
                    "%s: byte mismatch at %#x" % (path, addr))
    return failures


def check(packet_dir, binary_path):
    failures = []

    def need(cond, msg):
        if not cond:
            failures.append(msg)

    with open(os.path.join(packet_dir, "records.json")) as f:
        rec = json.load(f)
    with open(binary_path, "rb") as f:
        data = f.read()
    elf = Elf(data)

    need(hashlib.sha256(data).hexdigest() == rec["target"]["sha256"],
         "target digest mismatch")
    need(len(data) == rec["target"]["size"], "target size mismatch")

    func = rec["function"]
    need(int(func["start_va"], 16) == FUNC_START, "function start mismatch")
    need(int(func["end_va_exclusive"], 16) == FUNC_END,
         "function end mismatch")
    body = elf.read_at(FUNC_START, FUNC_END - FUNC_START)
    need(len(body) == func["bytes"], "function byte count mismatch")
    need(hashlib.sha256(body).hexdigest() == func["sha256"],
         "function SHA mismatch")
    need(int(func["next_fde_start"], 16) == NEXT_FDE,
         "next FDE start mismatch")
    need(all(b == 0xCC for b in elf.read_at(FUNC_END, NEXT_FDE - FUNC_END)),
         "function padding is not all int3")
    need(NEXT_FDE - FUNC_END == func["padding_bytes"],
         "padding byte count mismatch")

    for br in rec["branches"]:
        site = int(br["site"], 16)
        if br["encoding"] == "rel8":
            raw = elf.read_at(site, 2)
            (rel,) = struct.unpack_from("<b", raw, 1)
            need(site + 2 + rel == int(br["target"], 16),
                 "branch target mismatch at %#x" % site)
        else:
            raw = elf.read_at(site, 6)
            (rel,) = struct.unpack_from("<i", raw, 2)
            need(site + 6 + rel == int(br["target"], 16),
                 "branch target mismatch at %#x" % site)
    for call in rec["calls"]:
        site = int(call["site"], 16)
        raw = elf.read_at(site, 5)
        need(raw[0] == 0xE8, "call opcode mismatch at %#x" % site)
        (rel,) = struct.unpack_from("<i", raw, 1)
        need(site + 5 + rel == int(call["target"], 16),
             "call target mismatch at %#x" % site)

    for plt in rec["plt"]:
        addr = int(plt["address"], 16)
        stub = elf.read_at(addr, 6)
        need(stub.hex() == plt["stub_bytes"], "PLT stub mismatch: %s"
             % plt["name"])
        (disp,) = struct.unpack_from("<i", stub, 2)
        need(addr + 6 + disp == int(plt["got_slot"], 16),
             "PLT GOT slot mismatch: %s" % plt["name"])
        try:
            r_type, sym = elf.plt_symbol(int(plt["got_slot"], 16))
        except ValueError as exc:
            failures.append(str(exc))
            continue
        need(r_type == 7, "PLT relocation is not JUMP_SLOT: %s" % plt["name"])
        need(sym == plt["symbol"], "PLT symbol mismatch: %s" % plt["name"])
        need(elf.read_at(int(plt["got_slot"], 16), 8).hex()
             == plt["got_slot_file_bytes"],
             "PLT GOT file bytes mismatch: %s" % plt["name"])

    ts = rec["throw_string"]
    raw = elf.read_at(int(ts["address"], 16), len(ts["text"]) + 1)
    need(raw.decode() == ts["text"] + "\x00", "throw string mismatch")
    need(raw.hex() == ts["bytes_hex"], "throw string bytes mismatch")

    text_addr, text_off, text_size = (
        lambda s: (s[3], s[4], s[5]))(elf.section(".text"))
    text = data[text_off:text_off + text_size]
    found = ["%#x" % a for a in e8_callers(text, text_addr, FUNC_START)]
    need(found == rec["callers_e8"], "caller census mismatch")

    for name in ("window.objdump.txt", "plt.objdump.txt",
                 "callers.objdump.txt"):
        failures.extend(check_excerpt_bytes(
            os.path.join(packet_dir, name), elf))

    with open(os.path.join(packet_dir, "frames.txt")) as f:
        frames = f.read()
    need("pc=%016x..%016x" % (FUNC_START, FUNC_END) in frames,
         "function FDE missing")
    need("pc=%016x..%016x" % (NEXT_FDE,
                              int(func["next_fde_end"], 16)) in frames,
         "next FDE missing")
    for fn in rec["caller_functions"]:
        rng = "pc=%016x..%016x" % (
            int(fn["enclosing_start"], 16), int(fn["enclosing_end"], 16))
        need(rng in frames, "caller FDE missing: %s" % rng)

    manifest = os.path.join(packet_dir, "MANIFEST.sha256")
    if os.path.exists(manifest):
        with open(manifest) as f:
            for line in f:
                parts = line.split()
                if len(parts) != 2:
                    continue
                digest, name = parts
                path = os.path.join(packet_dir, name)
                if not os.path.exists(path):
                    failures.append("manifest file missing: %s" % name)
                    continue
                with open(path, "rb") as pf:
                    need(hashlib.sha256(pf.read()).hexdigest() == digest,
                         "manifest hash mismatch: %s" % name)
    else:
        failures.append("MANIFEST.sha256 missing")
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--packet", default=PACKET_DIR)
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    failures = check(args.packet, args.binary)
    if failures:
        print("CHECK FAILED")
        for failure in failures:
            print(" -", failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
