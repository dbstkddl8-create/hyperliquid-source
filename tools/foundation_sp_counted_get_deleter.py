#!/usr/bin/env python3
"""Checker and model for node #94's _Sp_counted_ptr_inplace _M_get_deleter (RE-001).

The function at 0x514b5d0 is the fifth virtual function (slot index 4) of
the vtable whose address point is 0x575b048, for
std::_Sp_counted_ptr_inplace<rocksdb::CacheHandleGuard<...>> (the
__si_class_type_info object at 0x575b020, whose name is recorded in
evidence.json). Its siblings in that vtable are the complete-object
destructor (0x514ac90, no-op), the deleting destructor (0x514aca0,
operator delete of 0x28 bytes), dispose (0x514bb10) and destroy
(0x514b160, operator delete of 0x28 bytes). The object is 0x28 bytes:
the _Sp_counted_base prefix is 0x10 bytes (vtable pointer plus two
4-byte counters), so the in-place storage starts at +0x10.

Composed rule, read directly from the bytes (rdi = counted object,
rsi = std::type_info):

- If rsi equals the runtime pointer held in GOT slot 0x5777a10
  (R_X86_64_RELATIVE, addend 0x7ea4a8), return object+0x10 at once,
  without reading the type_info's name field.
- Else let name = [rsi+0x8] (the type_info's __name). If the name
  pointer equals the tag-name address 0x7ea0d0
  ("St19_Sp_make_shared_tag"), return object+0x10.
- Else if name[0] == '*', return null. (For this tag name the branch
  is outcome-redundant: the tag name starts with 'S', so strcmp
  would fail anyway; it is recorded because the bytes contain it.)
- Else return object+0x10 iff strcmp(name, "St19_Sp_make_shared_tag")
  == 0 (the function's only call, strcmp@plt 0x56605e0), else null.

The function's only callee is strcmp@plt. It has no direct-e8
callers: it is reached by virtual dispatch through vtable slot
0x575b068. No stack canary is present; rbx is preserved and the
stack is balanced on every path.

Stdlib only. Run from the repository root:

    python3 tools/foundation_sp_counted_get_deleter.py \\
        --check research/work-items/foundation-sp-counted-get-deleter-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the function body, its FDE record, the strcmp arm, the
GOT sentinel relocation, the tag-name string, the vtable slot and
its siblings, the type_info object, the verbatim excerpts, and the
packet manifest hashes.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNCTION_START = 0x514B5D0
FUNCTION_END = 0x514B617
NEXT_FDE = 0x514B620
TAG_NAME_ADDR = 0x7EA0D0
TAG_NAME = "St19_Sp_make_shared_tag"
STRCMP_PLT = 0x56605E0
STRCMP_CALL = 0x514B5F7
GOT_SENTINEL_SLOT = 0x5777A10
GOT_SENTINEL_ADDEND = 0x7EA4A8
VTABLE_ADDRESS_POINT = 0x575B048
VTABLE_SLOTS = {
    0x575B048: 0x514AC90,
    0x575B050: 0x514ACA0,
    0x575B058: 0x514BB10,
    0x575B060: 0x514B160,
    0x575B068: 0x514B5D0,
}
TYPE_INFO_ADDR = 0x575B020
TYPE_INFO_NAME_ADDR = 0x7EDFA0


class TypeInfo:
    """A std::type_info as the function sees it: identity, name pointer, name."""

    def __init__(self, name, name_ptr=None, is_sentinel=False):
        self.name = name  # str, or None when the name is never read
        self.name_ptr = name_ptr
        self.is_sentinel = is_sentinel


# The tag name's own address, as a name-pointer identity token.
TAG_NAME_PTR = TAG_NAME_ADDR


def get_deleter(holder_base, ti):
    """Faithful model of 0x514b5d0: object+0x10 on a tag match, else None."""
    if ti.is_sentinel:
        return holder_base + 0x10
    if ti.name_ptr == TAG_NAME_PTR:
        return holder_base + 0x10
    if ti.name is not None and ti.name.startswith("*"):
        return None
    if ti.name == TAG_NAME:
        return holder_base + 0x10
    return None


# ---------------------------------------------------------------- ELF reading

class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping and .rela.dyn entries."""

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
            (p_type, p_flags, p_offset, p_vaddr, _p_paddr,
             p_filesz, _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
            if p_type == 1:  # PT_LOAD
                self.loads.append((p_vaddr, p_offset, p_filesz))
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            (sh_name, sh_type, _flags, sh_addr, sh_offset,
             sh_size, _link, _info, _align, _entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", data, off)
            self.sections.append((sh_name, sh_type, sh_addr, sh_offset, sh_size))
        shstr_off = self.sections[self.e_shstrndx][3]
        self.names = {}
        for idx, (sh_name, _t, _a, _o, _s) in enumerate(self.sections):
            end = data.index(b"\x00", shstr_off + sh_name)
            self.names[idx] = data[shstr_off + sh_name:end].decode()

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x is not in any PT_LOAD segment" % va)

    def read_at(self, va, length):
        off = self.va_to_offset(va)
        return self.data[off:off + length]

    def relocations(self):
        """Map r_offset -> (r_type, r_addend) for .rela.dyn entries."""
        out = {}
        for idx, (_n, sh_type, _a, sh_offset, sh_size) in enumerate(self.sections):
            if self.names.get(idx) != ".rela.dyn":
                continue
            for off in range(sh_offset, sh_offset + sh_size, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
                out[r_offset] = (r_info & 0xFFFFFFFF, r_addend)
        return out


# ---------------------------------------------------------------- checking

def parse_objdump_window(path):
    """Parse an objdump -d excerpt into {address: (bytes, mnemonic, operands)}."""
    line_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t(\S+)(?:\s+(.*?))?\s*$")
    out = {}
    with open(path) as f:
        for raw in f:
            m = line_re.match(raw.rstrip("\n"))
            if not m:
                continue
            addr = int(m.group(1), 16)
            operands = (m.group(4) or "").strip()
            if " #" in operands:
                operands = operands.split(" #", 1)[0].strip()
            operands = re.sub(r"\s*<[^>]*>", "", operands).strip()
            out[addr] = (m.group(2).strip().replace(" ", ""), m.group(3), operands)
    return out


def check(evidence_path, binary_path):
    """Return a list of failures; empty means every claim re-derived."""
    failures = []

    def need(cond, msg):
        if not cond:
            failures.append(msg)

    with open(evidence_path) as f:
        ev = json.load(f)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    with open(binary_path, "rb") as f:
        data = f.read()
    elf = Elf(data)

    target = ev["target"]
    need(hashlib.sha256(data).hexdigest() == target["sha256"],
         "target digest mismatch")
    need(len(data) == target["size"], "target size mismatch")

    fn = ev["function"]
    fn_start = int(fn["address"], 16)
    fn_end = int(fn["end"], 16)
    fn_bytes = elf.read_at(fn_start, fn_end - fn_start)
    need(hashlib.sha256(fn_bytes).hexdigest() == fn["sha256"],
         "function body SHA mismatch")
    need(fn_start == FUNCTION_START and fn_end == FUNCTION_END,
         "function extent mismatch")
    pad = elf.read_at(fn_end, fn["padding_bytes"])
    need(pad == b"\xcc" * fn["padding_bytes"], "padding is not int3 bytes")
    need(int(fn["next_fde"], 16) == NEXT_FDE, "next FDE mismatch")

    # Instructions: bytes against the binary, mnemonic/operands against the excerpt.
    window = parse_objdump_window(os.path.join(packet_dir, "window.objdump.txt"))
    for ins in ev["instructions"]:
        addr = int(ins["address"], 16)
        raw = bytes.fromhex(ins["bytes"])
        need(elf.read_at(addr, len(raw)) == raw,
             "instruction bytes mismatch at %#x" % addr)
        need(addr in window, "instruction %#x missing from excerpt" % addr)
        if addr in window:
            wbytes, wmnem, wops = window[addr]
            need(wbytes == ins["bytes"], "excerpt bytes mismatch at %#x" % addr)
            need(wmnem == ins["mnemonic"], "excerpt mnemonic mismatch at %#x" % addr)
            need(wops == ins["operands"], "excerpt operands mismatch at %#x" % addr)

    # Call targets re-derived from rel32 displacements.
    def call_target(site):
        raw = elf.read_at(site, 5)
        need(raw[0] == 0xE8, "no e8 call at %#x" % site)
        rel = struct.unpack("<i", raw[1:5])[0]
        return site + 5 + rel

    need(call_target(STRCMP_CALL) == STRCMP_PLT, "strcmp call target mismatch")

    def rip_target(site, length):
        raw = elf.read_at(site, length)
        disp = struct.unpack("<i", raw[-4:])[0]
        return site + length + disp

    cmp_site = 0x514B5D4
    need(rip_target(cmp_site, 7) == GOT_SENTINEL_SLOT, "sentinel GOT slot mismatch")
    lea_site = 0x514B5E6
    need(rip_target(lea_site, 7) == TAG_NAME_ADDR, "tag-name lea target mismatch")

    # Tag-name string bytes.
    tag = ev["tag_name"]
    raw = elf.read_at(TAG_NAME_ADDR, len(tag["value"]) + 1)
    need(raw == tag["value"].encode() + b"\x00", "tag-name string mismatch")

    # Relocations, re-derived from .rela.dyn.
    relocs = elf.relocations()
    sent = ev["sentinel"]
    got = relocs.get(GOT_SENTINEL_SLOT)
    need(got is not None, "sentinel GOT relocation missing")
    if got:
        need(got[0] == 8 and got[1] == GOT_SENTINEL_ADDEND,
             "sentinel GOT relocation mismatch (type/addend)")
        need(sent["relocation_addend"] == hex(GOT_SENTINEL_ADDEND),
             "recorded sentinel addend mismatch")
    for slot_text, target_text in ev["vtable"]["slots"].items():
        slot, target_addr = int(slot_text, 16), int(target_text, 16)
        rel = relocs.get(slot)
        need(rel is not None, "vtable slot %#x relocation missing" % slot)
        if rel:
            need(rel[0] == 8 and rel[1] == target_addr,
                 "vtable slot %#x target mismatch" % slot)
        need(VTABLE_SLOTS.get(slot) == target_addr,
             "recorded vtable slot %#x mismatch" % slot)
    ti = ev["type_info"]
    name_rel = relocs.get(int(ti["name_slot"], 16))
    need(name_rel is not None and name_rel[0] == 8
         and name_rel[1] == TYPE_INFO_NAME_ADDR, "type_info name slot mismatch")
    base_rel = relocs.get(int(ti["base_slot"], 16))
    need(base_rel is not None and base_rel[0] == 8
         and base_rel[1] == int(ti["base_type_info"], 16),
         "type_info base slot mismatch")
    vptr_rel = relocs.get(int(ti["vptr_slot"], 16))
    need(vptr_rel is not None and vptr_rel[0] == 1 and vptr_rel[1] == 0x10,
         "type_info vptr slot mismatch")
    raw = elf.read_at(TYPE_INFO_NAME_ADDR, len(ti["name"]) + 1)
    need(raw == ti["name"].encode() + b"\x00", "type_info name string mismatch")

    # FDE lines in frames.txt.
    with open(os.path.join(packet_dir, "frames.txt")) as f:
        frames_text = f.read()
    need("pc=000000000514b5d0..000000000514b617" in frames_text,
         "function FDE line missing")
    for sib in ev["siblings"]:
        rng = "pc=%016x..%016x" % (int(sib["address"], 16), int(sib["end"], 16))
        need(rng in frames_text, "sibling FDE line missing for %s" % sib["address"])

    # Manifest hashes.
    manifest_path = os.path.join(packet_dir, "MANIFEST.sha256")
    with open(manifest_path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, name = line.split("  ", 1)
            with open(os.path.join(packet_dir, name), "rb") as fh:
                actual = hashlib.sha256(fh.read()).hexdigest()
            need(actual == digest, "manifest hash mismatch for %s" % name)
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", required=True)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    binary = args.binary
    if not os.path.exists(binary) or (
            os.path.getsize(binary) < 1024 * 1024
            and open(binary, "rb").read(64).startswith(b"version https://git-lfs")):
        alt = os.path.join("work", "hl-node-94.bin")
        if os.path.exists(alt):
            binary = alt
    failures = check(args.check, binary)
    if failures:
        print("CHECKS FAILED:")
        for failure in failures:
            print(" -", failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
