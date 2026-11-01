#!/usr/bin/env python3
"""Checker for the foundation modulo-index-byte window (node #94, 0x538c820).

Stdlib only. Run from the repository root:

    python3 tools/foundation_modulo_index_byte.py \\
        --check research/work-items/foundation-modulo-index-byte-94/evidence.json

Every claim is re-derived from target bytes: the 57-byte window body, its
seven int3 padding bytes, the retained FDE records (window, next, the
133-byte callee, the FDE after the callee, and the single caller FDE, each
locked under its own CIE read from the cie= field, never from the
third-column CIE-pointer delta), the callee body and its eleven int3
padding bytes, the direct call encoding to the callee, the constant
0x18d seed argument, the modulo-index rule on its edges including the
divisor-zero fault limit, and the full direct-caller scan (exactly one
site, verified as an instruction start inside its containing FDE). A
failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import re
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x538C820: "f30f1efa",
    0x538C824: "4154",
    0x538C826: "4989fc",
    0x538C829: "55",
    0x538C82A: "4889f5",
    0x538C82D: "53",
    0x538C82E: "488b7108",
    0x538C832: "89d3",
    0x538C834: "ba8d010000",
    0x538C839: "488b39",
    0x538C83C: "e82f660900",
    0x538C841: "410fb70c24",
    0x538C846: "31d2",
    0x538C848: "f7f1",
    0x538C84A: "89d2",
    0x538C84C: "4801d5",
    0x538C84F: "0fb6441d00",
    0x538C854: "5b",
    0x538C855: "5d",
    0x538C856: "415c",
    0x538C858: "c3",
}

CALLEE_INSTR = {
    0x5422E70: "f30f1efa",
    0x5422E74: "69c693a7a4c6",
    0x5422E7A: "4c8d0437",
    0x5422E7E: "4c8d4f04",
    0x5422E82: "31d0",
    0x5422E84: "4d39c8",
    0x5422E87: "722c",
    0x5422E89: "4c89ca",
    0x5422E8C: "0f1f4000",
    0x5422E90: "0342fc",
    0x5422E93: "4883c204",
    0x5422E97: "69c893a7a4c6",
    0x5422E9D: "89c8",
    0x5422E9F: "c1e810",
    0x5422EA2: "31c8",
    0x5422EA4: "4939d0",
    0x5422EA7: "73e7",
    0x5422EA9: "4883ee04",
    0x5422EAD: "4883e6fc",
    0x5422EB1: "498d3c31",
    0x5422EB5: "4929f8",
    0x5422EB8: "4983f802",
    0x5422EBC: "741b",
    0x5422EBE: "4983f803",
    0x5422EC2: "740c",
    0x5422EC4: "4983f801",
    0x5422EC8: "7418",
    0x5422ECA: "c3",
    0x5422ECB: "0f1f440000",
    0x5422ED0: "0fbe5702",
    0x5422ED4: "c1e210",
    0x5422ED7: "01d0",
    0x5422ED9: "0fbe5701",
    0x5422EDD: "c1e208",
    0x5422EE0: "01d0",
    0x5422EE2: "0fbe17",
    0x5422EE5: "01c2",
    0x5422EE7: "69d293a7a4c6",
    0x5422EED: "89d0",
    0x5422EEF: "c1e818",
    0x5422EF2: "31d0",
    0x5422EF4: "c3",
}

WINDOW_START = 0x538C820
CALLEE_START = 0x5422E70
CALLER_SITE = 0x535BEA9


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
    enc = read_va(binary, sections, 0x538C83C, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x538C83C + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The third call argument must be the constant 0x18d seed.
    if read_va(binary, sections, 0x538C834, 5) != bytes.fromhex("ba8d010000"):
        raise ValueError("seed argument site is not mov edx, 0x18d")
    # The divisor must come from a word load at [r12] (movzx ecx, word [r12]).
    if read_va(binary, sections, 0x538C841, 5) != bytes.fromhex("410fb70c24"):
        raise ValueError("divisor site is not movzx ecx, word ptr [r12]")
    # The division must be div ecx with edx zeroed first.
    if read_va(binary, sections, 0x538C846, 2) != bytes.fromhex("31d2"):
        raise ValueError("high dividend half is not zeroed (xor edx, edx)")
    if read_va(binary, sections, 0x538C848, 2) != bytes.fromhex("f7f1"):
        raise ValueError("division site is not div ecx")


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        raise ValueError(f"padding length {len(pad)} != {fn['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"padding not all int3: {pad.hex()}")


def check_frames(ev, packet_dir):
    fn = ev["function"]
    cal = ev["callee"]
    inc = ev["incoming"]
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        text = fh.read()
    # Each record is locked by its own section offset, PC range, and the
    # cie= value -- never by the third column, which is the CIE-pointer
    # delta, not the CIE.
    records = [
        (fn["fde_section_offset"], fn["start_va"], fn["end_va_exclusive"],
         fn["fde_cie"], "window"),
        (fn["next_fde_section_offset"], fn["next_fde_start"], None,
         fn["next_fde_cie"], "window-next"),
        (cal["fde_section_offset"], cal["start_va"], cal["end_va_exclusive"],
         cal["fde_cie"], "callee"),
        (cal["next_fde_section_offset"], cal["next_fde_start"], None,
         cal["next_fde_cie"], "callee-next"),
        (inc["caller_fde_section_offset"], inc["caller_fde_start"],
         inc["caller_fde_end"], inc["caller_fde_cie"], "caller"),
    ]
    for off, start, end, cie, label in records:
        if off[2:] not in text:
            raise ValueError(f"{label} FDE section offset not in frames.txt")
        if end is not None:
            if f"pc={u64(start):016x}..{u64(end):016x}" not in text:
                raise ValueError(f"{label} FDE PC range not in frames.txt")
        else:
            if f"pc={u64(start):016x}" not in text:
                raise ValueError(f"{label} FDE start not in frames.txt")
        if f"cie={cie[2:]}" not in text:
            raise ValueError(f"{label} FDE CIE not in frames.txt")


def check_callee(ev, binary, sections):
    cal = ev["callee"]
    start = u64(cal["start_va"])
    end = u64(cal["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != cal["bytes"]:
        raise ValueError(f"callee length {len(body)} != {cal['bytes']}")
    if hashlib.sha256(body).hexdigest() != cal["sha256"]:
        raise ValueError("callee sha256 mismatch")
    for va, hexbytes in CALLEE_INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"callee bytes at {hex(va)}: {got.hex()} != {hexbytes}")
    if not cal["is_fde_start"]:
        raise ValueError("callee must be an FDE start")
    nxt = u64(cal["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != cal["padding_bytes"]:
        raise ValueError(f"callee padding length {len(pad)} != {cal['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"callee padding not all int3: {pad.hex()}")


def check_callers(ev, binary, sections, packet_dir):
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
    # The single site must be an instruction start inside its containing
    # FDE, as retained in caller.objdump.txt.
    inc = ev["incoming"]
    if not (u64(inc["caller_fde_start"]) <= CALLER_SITE < u64(inc["caller_fde_end"])):
        raise ValueError("caller site is not inside the caller FDE")
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller_text = fh.read()
    if not re.search(rf"^\s*{CALLER_SITE:x}:\s+e8\s+[0-9a-f ]+\s+call\s+538c820\b",
                     caller_text, re.MULTILINE):
        raise ValueError("caller.objdump.txt lacks the call-site instruction")


def evaluate_edge(edge):
    """Check one edge against the modulo-index-byte model."""
    d = u64(edge["divisor"])
    h = u64(edge["callee_result"])
    if d == 0:
        raise ValueError(f"edge {edge['note']}: divisor zero is a fault edge")
    r = h % d
    if r != u64(edge["remainder"]):
        raise ValueError(
            f"edge {edge['note']}: model remainder {hex(r)} "
            f"!= {edge['remainder']}")
    addr = (u64(edge["base"]) + r + u64(edge["idx"])) & 0xFFFFFFFFFFFFFFFF
    if addr != u64(edge["read_addr"]):
        raise ValueError(
            f"edge {edge['note']}: model read addr {hex(addr)} "
            f"!= {edge['read_addr']}")
    mem = {u64(k): v for k, v in edge["mem"].items()}
    if mem.get(addr) != u64(edge["ret"]):
        raise ValueError(
            f"edge {edge['note']}: mem[{hex(addr)}] != ret {edge['ret']}")
    if edge["call_rdx"] != "0x18d":
        raise ValueError(
            f"edge {edge['note']}: call rdx must be the 0x18d seed")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if rule["call_args"] != {"rdi": "[rcx]", "rsi": "[rcx + 8]",
                             "rdx": "0x18d"}:
        raise ValueError("call args must be [rcx], [rcx + 8], 0x18d")
    if rule["divisor"] != "word at [rdi], zero-extended to 32 bits":
        raise ValueError("divisor must be the word at [rdi]")
    if rule["return_register"] != "rax":
        raise ValueError("return register must be rax")
    fault = rule["fault_edge"]
    if fault["divisor"] != "0x0" or fault["fault"] != "#DE":
        raise ValueError("fault edge must be divisor 0 -> #DE")
    if ev["incoming"]["direct_e8_callers"] != ["0x535bea9"]:
        raise ValueError("this packet claims exactly one direct caller")


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
    check_frames(ev, packet_dir)
    check_callee(ev, binary, sections)
    check_callers(ev, binary, sections, packet_dir)
    check_edges(ev)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_modulo_index_byte.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation modulo-index-byte evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
