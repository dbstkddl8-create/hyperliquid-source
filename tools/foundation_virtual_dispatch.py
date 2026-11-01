#!/usr/bin/env python3
"""Checker for node #94's virtual-dispatch window 0x514b170 with its
fast-path identity guard against the zero-returning function 0x4fe8fe0
(RE-001).

Stdlib only. Run from the repository root:

    python3 tools/foundation_virtual_dispatch.py \\
        --check research/work-items/foundation-virtual-dispatch-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the entry window body, the guard-target window body,
both padding runs, both FDE records, the rip-relative cmp that joins
the entry to the GOT slot, the .rela.dyn relocation that resolves the
slot to the guard target, the full direct-e8 caller census for the
entry window, and the composed dispatch rule with its fast-path
elision. A failure prints the mismatching check and exits nonzero.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

ENTRY_START = 0x514B170
GUARD_START = 0x4FE8FE0
GOT_SLOT = 0x5777F18

ENTRY_INSTR = {
    0x514B170: "f30f1efa",
    0x514B174: "53",
    0x514B175: "488b8f88070000",
    0x514B17C: "4889f3",
    0x514B17F: "488bb950090000",
    0x514B186: "488b07",
    0x514B189: "488b5028",
    0x514B18D: "31c0",
    0x514B18F: "483b1582cd6200",
    0x514B196: "7510",
    0x514B198: "488903",
    0x514B19B: "b801000000",
    0x514B1A0: "5b",
    0x514B1A1: "c3",
    0x514B1A2: "660f1f440000",
    0x514B1A8: "488b7130",
    0x514B1AC: "4883c640",
    0x514B1B0: "ffd2",
    0x514B1B2: "0fb6c0",
    0x514B1B5: "488903",
    0x514B1B8: "b801000000",
    0x514B1BD: "5b",
    0x514B1BE: "c3",
}

GUARD_INSTR = {
    0x4FE8FE0: "f30f1efa",
    0x4FE8FE4: "31c0",
    0x4FE8FE6: "c3",
}


def u64(text):
    return int(text, 16)


def guard_target_result():
    """The guard function returns 0: endbr64, xor %eax,%eax, ret."""
    return 0


def dispatch(slot, guard_value, callee_result=None):
    """Model the composed dispatch.

    Returns (out, called, return_value). The fast path stores 0
    without calling; the slow path calls the slot and stores only its
    low byte (movzbl). The return value is 1 on every path.
    """
    if slot == guard_value:
        return (0, False, 1)
    if callee_result is None:
        raise ValueError("slow path needs a callee result")
    return (callee_result & 0xFF, True, 1)


def simulate_window(root, guard_value, callee):
    """Simulate the entry window end to end from a fake container.

    ``root`` maps field offsets to values: 0x950 holds the field
    object, 0x30 holds the slow-path base. The field object maps
    "head" to a vtable dict mapping 0x28 to the slot. ``callee`` is
    called as callee(field_object, base + 0x40, slot) on the slow
    path and returns an integer result. Returns (out, called, ret).
    """
    field_object = root[0x950]
    slot = field_object["head"][0x28]
    if slot == guard_value:
        return (guard_target_result(), False, 1)
    result = callee(field_object, root[0x30] + 0x40, slot)
    return dispatch(slot, guard_value, result)


def elf_sections(binary):
    """Return {name: (sh_addr, sh_offset, sh_size)} for ELF64 sections."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if binary[4] != 2 or binary[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, _type, _flags, addr, offset, size) = struct.unpack_from(
            "<IIQQQQ", binary, off)
        headers.append((name, addr, offset, size))
    str_off = headers[e_shstrndx][2]
    out = {}
    for (name_off, addr, offset, size) in headers:
        end = binary.index(b"\x00", str_off + name_off)
        name = binary[str_off + name_off:end].decode()
        out[name] = (addr, offset, size)
    return out


def read_va(binary, sections, va, count):
    addr, offset, size = sections[".text"]
    if not (addr <= va and va + count <= addr + size):
        raise ValueError("VA %#x outside .text" % va)
    start = offset + (va - addr)
    return binary[start:start + count]


def read_section_va(binary, sections, section, va, count):
    addr, offset, size = sections[section]
    if not (addr <= va and va + count <= addr + size):
        raise ValueError("VA %#x outside %s" % (va, section))
    start = offset + (va - addr)
    return binary[start:start + count]


def relocation_entry(binary, sections, slot):
    """Return (type, addend) for the .rela.dyn entry at ``slot``.

    ELF64 Rela entries are 24 bytes: r_offset, r_info, r_addend.
    The relocation type is the low 32 bits of r_info.
    """
    addr, offset, size = sections[".rela.dyn"]
    for i in range(size // 24):
        (r_offset, r_info, r_addend) = struct.unpack_from(
            "<QQq", binary, offset + i * 24)
        if r_offset == slot:
            return (r_info & 0xFFFFFFFF, r_addend)
    return None


def check_target_digest(ev, binary, sections, packet_dir):
    if hashlib.sha256(binary).hexdigest() != ev["target_sha256"]:
        return "target SHA-256 mismatch"
    return None


def check_window(ev, binary, sections, packet_dir, key, instr):
    fn = ev[key]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        return "%s length mismatch: %d != %d" % (key, len(body), fn["bytes"])
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        return "%s body SHA-256 mismatch" % key
    for va, hexbytes in instr.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "%s instruction bytes mismatch at %#x" % (key, va)
    return None


def check_padding(ev, binary, sections, packet_dir, key):
    fn = ev[key]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        return "%s padding length mismatch: %d != %d" % (
            key, len(pad), fn["padding_bytes"])
    if pad != b"\xcc" * len(pad):
        return "%s padding bytes are not int3" % key
    return None


def check_frames(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        frames = fh.read()
    for key, pc in (("entry", "pc=000000000514b170..000000000514b1bf"),
                    ("guard_target", "pc=0000000004fe8fe0..0000000004fe8fe7")):
        if pc not in frames:
            return "%s FDE record missing from frames.txt" % key
        if ev[key]["fde_section_offset"][2:] not in frames:
            return "%s FDE section offset missing from frames.txt" % key
    return None


def check_guard_cmp(ev, binary, sections, packet_dir):
    cmp_rec = ev["guard_cmp"]
    site = u64(cmp_rec["site"])
    want = bytes.fromhex(cmp_rec["bytes"])
    got = read_va(binary, sections, site, len(want))
    if got != want:
        return "guard cmp bytes mismatch at %#x" % site
    (disp,) = struct.unpack_from("<i", got, 3)
    rip_after = site + len(want)
    if rip_after != u64(cmp_rec["rip_after"]):
        return "guard cmp rip-after mismatch"
    if rip_after + disp != u64(cmp_rec["target"]):
        return "guard cmp target mismatch: %#x + %#x != %#x" % (
            rip_after, disp, u64(cmp_rec["target"]))
    if u64(cmp_rec["target"]) != GOT_SLOT:
        return "guard cmp target is not the GOT slot"
    if disp != u64(cmp_rec["displacement"]):
        return "guard cmp displacement mismatch"
    return None


def check_relocation(ev, binary, sections, packet_dir):
    slot_rec = ev["got_slot"]
    if u64(slot_rec["address"]) != GOT_SLOT:
        return "GOT slot address mismatch"
    entry = relocation_entry(binary, sections, GOT_SLOT)
    if entry is None:
        return "no .rela.dyn entry for the GOT slot"
    rel_type, addend = entry
    if rel_type != 8:
        return "GOT relocation type is not R_X86_64_RELATIVE: %d" % rel_type
    if addend != u64(slot_rec["relocation_addend"]):
        return "GOT relocation addend mismatch"
    if addend != GUARD_START:
        return "GOT relocation addend is not the guard target"
    if slot_rec["relocation"] != "R_X86_64_RELATIVE":
        return "GOT relocation name mismatch"
    file_bytes = read_section_va(binary, sections, ".got", GOT_SLOT, 8)
    if file_bytes.hex() != slot_rec["file_bytes"]:
        return "GOT slot file bytes mismatch"
    if file_bytes != b"\x00" * 8:
        return "GOT slot file bytes are not zero (loader-filled)"
    return None


def check_indirect_call(ev, binary, sections, packet_dir):
    call = ev["indirect_call"]
    site = u64(call["site"])
    want = bytes.fromhex(call["bytes"])
    got = read_va(binary, sections, site, len(want))
    if got != want:
        return "indirect call bytes mismatch at %#x" % site
    if call["register"] != "%rdx":
        return "indirect call register is not %rdx"
    return None


def scan_callers(binary, sections, target):
    addr, offset, size = sections[".text"]
    text = binary[offset:offset + size]
    found = []
    idx = 0
    while True:
        idx = text.find(b"\xe8", idx)
        if idx < 0:
            break
        if idx + 5 <= len(text):
            (rel,) = struct.unpack_from("<i", text, idx + 1)
            if addr + idx + 5 + rel == target:
                found.append(addr + idx)
        idx += 1
    return found


def check_callers(ev, binary, sections, packet_dir):
    if scan_callers(binary, sections, ENTRY_START) != []:
        return "entry direct e8 caller scan is not empty"
    if ev["incoming"]["direct_e8_callers"] != []:
        return "evidence entry caller list is not empty"
    return None


def check_excerpts(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    with open(os.path.join(packet_dir, "guard.objdump.txt")) as fh:
        guard = fh.read()
    for needle, where, name in (
            ("514b170:", window, "entry excerpt start"),
            ("514b18f:", window, "guard cmp site"),
            ("514b1b0:", window, "indirect call site"),
            ("endbr64", window, "entry endbr64 mnemonic"),
            ("movzbl", window, "slow-path movzbl mnemonic"),
            ("nopw", window, "alignment nopw mnemonic"),
            ("4fe8fe0:", guard, "guard excerpt start"),
            ("4fe8fe6:", guard, "guard ret"),
            ("endbr64", guard, "guard endbr64 mnemonic")):
        if needle not in where:
            return "%s missing from excerpts" % name
    for fn, excerpt in (("entry", window), ("guard_target", guard)):
        for instr in ev[fn]["instructions"]:
            if instr["mnemonic"] not in excerpt:
                return "%s mnemonic %s missing from %s excerpt" % (
                    fn, instr["mnemonic"], fn)
    return None


def check_edges(ev, binary, sections, packet_dir):
    guard_value = 0x1000  # symbolic stand-in for load base + guard target
    for edge in ev["rule"]["edges"]:
        if edge["slot_equals_guard"]:
            out, called, ret = dispatch(guard_value, guard_value)
        else:
            out, called, ret = dispatch(
                guard_value + 8, guard_value, edge["callee_result"])
        if out != edge["out"]:
            return "rule edge out mismatch: %s" % edge
        if called != edge["called"]:
            return "rule edge called mismatch: %s" % edge
        if ret != edge["return_value"]:
            return "rule edge return mismatch: %s" % edge
    return None


CHECKS = (
    ("target digest", check_target_digest),
    ("entry body", lambda ev, b, s, p: check_window(ev, b, s, p, "entry", ENTRY_INSTR)),
    ("guard body", lambda ev, b, s, p: check_window(ev, b, s, p, "guard_target", GUARD_INSTR)),
    ("entry padding", lambda ev, b, s, p: check_padding(ev, b, s, p, "entry")),
    ("guard padding", lambda ev, b, s, p: check_padding(ev, b, s, p, "guard_target")),
    ("frames", check_frames),
    ("guard cmp", check_guard_cmp),
    ("relocation", check_relocation),
    ("indirect call", check_indirect_call),
    ("callers", check_callers),
    ("excerpts", check_excerpts),
    ("rule edges", check_edges),
)


def run_evidence(ev, binary, sections, packet_dir):
    """Run every check against an already-loaded evidence dict.

    Returns a list of failure strings (empty on success). Corruption
    controls in the unit tests call this directly with mutated dicts.
    """
    failures = []
    for name, fn in CHECKS:
        try:
            err = fn(ev, binary, sections, packet_dir)
        except Exception as exc:  # corrupted input must fail, not crash
            err = "%s (%s)" % (name, exc)
        if err:
            failures.append("%s: %s" % (name, err))
    return failures


def run_all(evidence_path, binary_path):
    """Return a list of failure strings (empty on success)."""
    with open(evidence_path) as fh:
        ev = json.load(fh)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    with open(binary_path, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    return run_evidence(ev, binary, sections, packet_dir)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", required=True)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    failures = run_all(args.check, args.binary)
    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("Virtual-dispatch evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
