#!/usr/bin/env python3
"""Checker for the foundation span-count window (node #94, 0x53c7490).

Stdlib only. Run from the repository root:

    python3 tools/foundation_span_count.py \
        --check research/work-items/foundation-span-count-94/evidence.json

The bounded checks re-derive from target bytes: the 43-byte window body, its
five int3 padding bytes, the retained FDE records (window, next, the
1514-byte callee, the FDE after the callee, and the tail-jump target, each
locked under its own CIE read from the cie= field, never from the
third-column CIE-pointer delta), the callee body (locked by length, SHA-256
and padding; its behavior is excluded, so its instructions are not locked
one by one) and its six int3 padding bytes, the direct call encoding to
the callee, the tail-jump encoding to 0x53c4ec0, the span-count rule on
its edges including the empty-span wraparound and the negative-span edge,
and the full direct-caller scan (exactly zero sites). A failure prints the
mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elf_index
import fde_extents

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x53C7490: "f30f1efa",
    0x53C7494: "53",
    0x53C7495: "4889fb",
    0x53C7498: "e8e3f9ffff",
    0x53C749D: "488b4370",
    0x53C74A1: "482b4368",
    0x53C74A5: "4889df",
    0x53C74A8: "48c1f802",
    0x53C74AC: "83e801",
    0x53C74AF: "898380000000",
    0x53C74B5: "5b",
    0x53C74B6: "e905daffff",
}

WINDOW_START = 0x53C7490
CALLEE_START = 0x53C6E80
JUMP_TARGET = 0x53C4EC0


def u64(text):
    return int(text, 16)


def elf_sections(binary):
    """Return {name: (sh_addr, sh_offset, sh_size)} for ELF64 sections."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    strtab_off = e_shoff + e_shstrndx * e_shentsize
    (st_name, st_type, st_flags, st_addr, st_off, st_size) = struct.unpack_from(
        "<IIQQQQ", binary, strtab_off)
    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (nm, tp, fl, addr, o, sz) = struct.unpack_from("<IIQQQQ", binary, off)
        end = binary.index(b"\x00", st_off + nm)
        name = binary[st_off + nm:end].decode()
        sections[name] = (addr, o, sz)
    return sections


def read_va(binary, sections, va, count):
    """Read count bytes at virtual address va via its section mapping."""
    for name, (addr, off, size) in sections.items():
        if addr <= va < addr + size and va + count <= addr + size:
            return binary[off + (va - addr):off + (va - addr) + count]
    raise ValueError(f"VA {hex(va)} not covered by any section")


def check_target_digest(ev, binary):
    digest = hashlib.sha256(binary).hexdigest()
    if digest != ev["target_sha256"]:
        raise ValueError(
            f"target digest mismatch: {digest} != {ev['target_sha256']}")


def check_window(ev, binary, sections):
    fn = ev["function"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        raise ValueError(f"body length {len(body)} != {fn['bytes']}")
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        raise ValueError("body sha256 mismatch")
    for va, hexbytes in INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"instruction bytes at {hex(va)}: {got.hex()} != {hexbytes}")
    # The call must target the callee: rel32 from the end of the call.
    enc = read_va(binary, sections, 0x53C7498, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x53C7498 + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The tail jump must target 0x53c4ec0: rel32 from the end of the jump.
    enc = read_va(binary, sections, 0x53C74B6, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x53C74B6 + 5 + rel != JUMP_TARGET:
        raise ValueError("tail-jump target is not 0x53c4ec0")
    # The object pointer must be restored to rdi before the jump.
    if read_va(binary, sections, 0x53C74A5, 3) != bytes.fromhex("4889df"):
        raise ValueError("rdi restore site is not mov rdi, rbx")
    # The store must be mov [rbx+0x80], eax.
    if read_va(binary, sections, 0x53C74AF, 6) != bytes.fromhex("898380000000"):
        raise ValueError("store site is not mov [rbx+0x80], eax")


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        raise ValueError(f"padding length {len(pad)} != {fn['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"padding not all int3: {pad.hex()}")


def check_frames(ev, packet_dir, binary):
    fn = ev["function"]
    cal = ev["callee"]
    jt = ev["jump_target"]
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        text = fh.read()
    # A single retained row must bind the offset, CIE and PC range.
    retained = {
        tuple(int(value, 16) for value in match)
        for match in re.findall(
            r"^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+FDE\s+"
            r"cie=([0-9a-f]+)\s+pc=([0-9a-f]+)\.\.([0-9a-f]+)$",
            text, re.MULTILINE)
    }
    # Derive those associations independently from the authenticated ELF;
    # another valid retained row cannot stand in for the declared function.
    sections = elf_index.sections(binary)
    frame = next(s for s in sections if s["name"] == ".eh_frame")
    _, parsed = fde_extents.eh_frame_records(binary, sections)
    actual = {
        row["fde"] - frame["address"]:
        (row["fde"] - frame["address"], row["cie"] - frame["address"],
         row["start"], row["end"])
        for row in parsed
    }
    records = [
        (fn["fde_section_offset"], fn["start_va"], fn["end_va_exclusive"],
         fn["fde_cie"], "window"),
        (fn["next_fde_section_offset"], fn["next_fde_start"], None,
         fn["next_fde_cie"], "window-next"),
        (cal["fde_section_offset"], cal["start_va"], cal["end_va_exclusive"],
         cal["fde_cie"], "callee"),
        (cal["next_fde_section_offset"], cal["next_fde_start"], None,
         cal["next_fde_cie"], "callee-next"),
        (jt["fde_section_offset"], jt["start_va"], jt["end_va_exclusive"],
         jt["fde_cie"], "jump-target"),
    ]
    for off, start, end, cie, label in records:
        native = actual.get(u64(off))
        if (native is None or native[1] != u64(cie)
                or native[2] != u64(start)
                or (end is not None and native[3] != u64(end))):
            raise ValueError(f"{label} FDE association does not match binary")
        if native not in retained:
            raise ValueError(f"{label} FDE association missing from frames.txt")


def check_callee(ev, binary, sections):
    cal = ev["callee"]
    start = u64(cal["start_va"])
    end = u64(cal["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != cal["bytes"]:
        raise ValueError(f"callee length {len(body)} != {cal['bytes']}")
    if hashlib.sha256(body).hexdigest() != cal["sha256"]:
        raise ValueError("callee sha256 mismatch")
    if not cal["is_fde_start"]:
        raise ValueError("callee must be an FDE start")
    # Entry instruction must be endbr64; the rest of the callee body is
    # locked by SHA-256 above, not per instruction, because its behavior
    # is excluded from the rule.
    if read_va(binary, sections, start, 4) != bytes.fromhex("f30f1efa"):
        raise ValueError("callee entry is not endbr64")
    nxt = u64(cal["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != cal["padding_bytes"]:
        raise ValueError(f"callee padding length {len(pad)} != {cal['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"callee padding not all int3: {pad.hex()}")


def check_callers(ev, binary, sections):
    """Byte-pattern scan of .text for direct e8 calls to the window."""
    addr, off, size = sections[".text"]
    text = binary[off:off + size]
    found = []
    idx = 0
    while True:
        idx = text.find(b"\xe8", idx)
        if idx < 0:
            break
        if idx + 5 <= len(text):
            (rel,) = struct.unpack_from("<i", text, idx + 1)
            site_va = addr + idx
            if site_va + 5 + rel == WINDOW_START:
                found.append(site_va)
        idx += 1
    want = [u64(c) for c in ev["incoming"]["direct_e8_callers"]]
    if found != want:
        raise ValueError(
            f"direct caller scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")


def evaluate_edge(edge):
    """Check one edge against the span-count model."""
    start = u64(edge["start"])
    end = u64(edge["end"])
    diff = (end - start) & 0xFFFFFFFFFFFFFFFF
    signed = diff - (1 << 64) if diff >= (1 << 63) else diff
    shifted = signed >> 2
    stored = ((shifted & 0xFFFFFFFF) - 1) & 0xFFFFFFFF
    if stored != u64(edge["stored"]):
        raise ValueError(
            f"edge {edge['note']}: model stored {hex(stored)} "
            f"!= {edge['stored']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if rule["tail_jump"] != "0x53c4ec0":
        raise ValueError("tail jump must be 0x53c4ec0")
    if rule["store"] != "dword at [obj+0x80]":
        raise ValueError("store must be dword at [obj+0x80]")
    if ev["incoming"]["direct_e8_callers"] != []:
        raise ValueError("this packet claims exactly zero direct callers")


def run_all(evidence_path):
    with open(evidence_path) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir, binary)
    check_callee(ev, binary, sections)
    check_callers(ev, binary, sections)
    check_edges(ev)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_span_count.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation span-count evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
