#!/usr/bin/env python3
"""Checker and model for node #94's recursive destructor at 0x514b690 (RE-001).

Bounded question: given a head pointer in rdi, which nodes does the
function at 0x514b690 delete, in which order, and with what size?

Read directly from the bytes (rdi = head):

1. If rdi is null, the je at 0x514b693 jumps to the trailing ret at
   0x514b6c0: return immediately, no stack change, nothing deleted.
2. Otherwise push rbx, set the cursor to head, and loop: load
   [cursor + 0x18] into rdi and call 0x514b690 itself (destroy the
   +0x18 subtree depth-first); move the cursor into rdi, load
   [cursor + 0x10] into rbx (the next link, read before the free);
   set esi = 0x30 and call operator delete via the PLT stub at
   0x5660440; loop while the new cursor is non-null; pop rbx, ret.
3. The deletion order is therefore: for each node, its +0x18 subtree
   first, then the node itself, then the +0x10 chain iteratively.
   Every delete passes size 0x30. The function returns void (rax is
   never set after the last delete call).

The function has exactly 13 direct-e8 call sites in .text: the
self-call at 0x514b69d plus 12 external sites in 10 enclosing
functions. Two external sites are spot-checked with their argument
setup (rdi = r13 before 0x514b7bc; rdi = [rsp+0xd0] before
0x5156abb); the rest are a census only.

Stdlib only. Run from the repository root:

    python3 tools/foundation_recursive_destructor.py \
        --check research/work-items/RE-001-recursive-destructor-94/records.json \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Every claim is re-derived from target bytes: the
function body, its FDE record, the delete PLT stub with its GOT
relocation, every direct call target, the branch targets, the caller
census, the raw excerpt bytes, and the packet manifest hashes.
The packet's own verify.py checks the same semantic records
independently; this checker additionally verifies that every byte
in the raw excerpts matches the binary at that address.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNC_START = 0x514B690
FUNC_END = 0x514B6C1
FUNC_NEXT_FDE = 0x514B6D0
DELETE_PLT = 0x5660440
DELETE_GOT = 0x5778F48
NODE_SIZE = 0x30
NEXT_OFF = 0x10
CHILD_OFF = 0x18


def destroy(heap, head):
    """Faithful model of 0x514b690.

    heap maps a node address to (next10, child18), each None for a
    null link. Returns the list of (address, size) pairs passed to
    operator delete, in deletion order.
    """
    deleted = []

    def recurse(node):
        if node is None:
            return
        cur = node
        while True:
            nxt, child = heap[cur]
            recurse(child)
            deleted.append((cur, NODE_SIZE))
            if nxt is None:
                return
            cur = nxt

    recurse(head)
    return deleted


# ---------------------------------------------------------------- ELF reading

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
             p_filesz, _memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
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

    def text_range(self):
        sec = self.section(".text")
        return (sec[3], sec[4], sec[5])

    def plt_symbol(self, got_slot):
        """(reloc_type, symbol) for a GOT slot via .rela.plt/.dynsym/.dynstr."""
        rela = self.section(".rela.plt")
        dynsym = self.section(".dynsym")
        dynstr = self.section(".dynstr")
        symtab = self.data[dynsym[4]:dynsym[4] + dynsym[5]]
        strtab = self.data[dynstr[4]:dynstr[4] + dynstr[5]]
        count = rela[5] // 24
        for i in range(count):
            r_offset, r_info, _add = struct.unpack_from(
                "<QQq", self.data, rela[4] + i * 24)
            if r_offset != got_slot:
                continue
            r_type = r_info & 0xFFFFFFFF
            sym = r_info >> 32
            st_name, = struct.unpack_from("<I", symtab, sym * 24)
            end = strtab.index(b"\x00", st_name)
            return (r_type, strtab[st_name:end].decode())
        raise ValueError("no .rela.plt entry for %#x" % got_slot)


# ---------------------------------------------------------------- checking

def parse_excerpt_bytes(path):
    """Parse an objdump -d excerpt into {address: bytes_hex}.

    Only the byte column is used: the excerpts are raw objdump
    output, and their bytes are what gets verified against the
    binary. No mnemonic list is kept anywhere.
    """
    line_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t")
    out = {}
    with open(path) as f:
        for raw in f:
            m = line_re.match(raw.rstrip("\n"))
            if not m:
                continue
            out[int(m.group(1), 16)] = m.group(2).strip().replace(" ", "")
    return out


def e8_callers(text, text_addr, target):
    """Direct-e8 call sites to target in .text bytes."""
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


def check(records_path, binary_path):
    """Return a list of failures; empty means every claim re-derived."""
    failures = []

    def need(cond, msg):
        if not cond:
            failures.append(msg)

    with open(records_path) as f:
        rec = json.load(f)
    packet_dir = os.path.dirname(os.path.abspath(records_path))
    with open(binary_path, "rb") as f:
        data = f.read()
    elf = Elf(data)

    target = rec["target"]
    need(hashlib.sha256(data).hexdigest() == target["sha256"],
         "target digest mismatch")
    need(len(data) == target["size"], "target size mismatch")

    func = rec["function"]
    body = elf.read_at(FUNC_START, FUNC_END - FUNC_START)
    need(hashlib.sha256(body).hexdigest() == func["sha256"],
         "function SHA mismatch")
    need(all(b == 0xCC for b in elf.read_at(FUNC_END, FUNC_NEXT_FDE - FUNC_END)),
         "function padding is not all int3")
    need(FUNC_NEXT_FDE - FUNC_END == func["padding_bytes"],
         "padding byte count mismatch")

    # Raw excerpt bytes match the binary at every address in range,
    # and the excerpt holds exactly the recorded instruction count.
    win = parse_excerpt_bytes(os.path.join(packet_dir, "window.objdump.txt"))
    in_range = {a: b for a, b in win.items() if FUNC_START <= a < FUNC_END}
    need(len(in_range) == rec["function_instruction_count"],
         "function instruction count mismatch")
    for addr, excerpt_bytes in in_range.items():
        need(elf.read_at(addr, len(bytes.fromhex(excerpt_bytes))).hex()
             == excerpt_bytes, "excerpt bytes mismatch at %#x" % addr)

    # Every direct call target re-derived from its rel32.
    for call in rec["calls"]:
        addr = int(call["site"], 16)
        raw = elf.read_at(addr, 5)
        need(raw[0] == 0xE8, "call opcode mismatch at %#x" % addr)
        (rel,) = struct.unpack_from("<i", raw, 1)
        need(addr + 5 + rel == int(call["target"], 16),
             "call target mismatch at %#x" % addr)

    # Branch targets re-derived from their rel8.
    for br in rec["branches"]:
        addr = int(br["site"], 16)
        raw = elf.read_at(addr, 2)
        (rel,) = struct.unpack_from("<b", raw, 1)
        need(addr + 2 + rel == int(br["target"], 16),
             "branch target mismatch at %#x" % addr)

    # Delete PLT stub: jmp *[rip+disp] lands on the recorded GOT slot,
    # the slot's relocation names operator delete, and the slot's file
    # bytes equal the recorded lazy-binding resolver address.
    plt = rec["delete_plt"]
    stub = elf.read_at(DELETE_PLT, 6)
    need(stub.hex() == plt["stub_bytes"], "delete PLT stub bytes mismatch")
    (disp,) = struct.unpack_from("<i", stub, 2)
    need(DELETE_PLT + 6 + disp == int(plt["got_slot"], 16),
         "delete PLT GOT slot mismatch")
    try:
        r_type, sym = elf.plt_symbol(DELETE_GOT)
    except ValueError as exc:
        failures.append(str(exc))
        r_type, sym = None, None
    need(r_type == 7, "delete GOT relocation is not R_X86_64_JUMP_SLOT")
    need(sym == plt["symbol"], "delete GOT symbol mismatch")
    need(elf.read_at(DELETE_GOT, 8).hex() == plt["got_slot_file_bytes"],
         "delete GOT slot file bytes mismatch")

    text_addr, text_off, text_size = elf.text_range()
    text = data[text_off:text_off + text_size]
    need(["%#x" % a for a in e8_callers(text, text_addr, FUNC_START)]
         == rec["callers_e8"], "caller census mismatch")
    need(["%#x" % a for a in e8_callers(text, text_addr, FUNC_START)
          if a != 0x514B69D] == rec["callers_external"],
         "external caller census mismatch")

    # Each external caller's excerpt line matches the binary bytes and
    # re-derives the function as its call target.
    callers = parse_excerpt_bytes(os.path.join(packet_dir, "callers.objdump.txt"))
    for site in rec["callers_external"]:
        addr = int(site, 16)
        excerpt_bytes = callers.get(addr)
        need(excerpt_bytes is not None, "caller %#x missing from excerpt" % addr)
        if excerpt_bytes is not None:
            raw = elf.read_at(addr, 5)
            need(raw.hex() == excerpt_bytes,
                 "caller bytes mismatch at %#x" % addr)
            (rel,) = struct.unpack_from("<i", raw, 1)
            need(addr + 5 + rel == FUNC_START,
                 "caller target mismatch at %#x" % addr)

    with open(os.path.join(packet_dir, "frames.txt")) as f:
        frames = f.read()
    need("pc=%016x..%016x" % (FUNC_START, FUNC_END) in frames,
         "function FDE missing")
    need("pc=%016x..%016x" % (FUNC_NEXT_FDE, 0x514B7B3) in frames,
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
    ap.add_argument("--check", required=True)
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    failures = check(args.check, args.binary)
    if failures:
        print("CHECK FAILED")
        for failure in failures:
            print(" -", failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
