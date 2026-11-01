#!/usr/bin/env python3
"""Checker for the foundation sentinel-checked field-reader window
(node #94, 0x514abb0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_sentinel_field_read.py \\
        --check research/work-items/foundation-sentinel-field-read-94/evidence.json
    python3 tools/foundation_sentinel_field_read.py \\
        --check research/work-items/foundation-sentinel-field-read-94/evidence.json \\
        --binary work/hl-node-94.bin

Without --binary, every claim is re-derived from the retained packet files:
the window.objdump.txt instruction bytes, their SHA-256, the thirteen
int3 padding bytes, the retained FDE records, and the sentinel rule on
its edges. With --binary, the checker additionally verifies the target
digest, the window bytes and padding, and the full direct-caller scan
against that binary. A failure prints the mismatching check and exits
nonzero.
"""

import hashlib
import json
import os
import re
import struct
import sys

WINDOW_START = 0x514ABB0

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x514ABB0: "f30f1efa",
    0x514ABB4: "488b8200120000",
    0x514ABBB: "4881c2e0110000",
    0x514ABC2: "4839d0",
    0x514ABC5: "7411",
    0x514ABC7: "488b4030",
    0x514ABCB: "488906",
    0x514ABCE: "b801000000",
    0x514ABD3: "c3",
    0x514ABD4: "0f1f4000",
    0x514ABD8: "31c0",
    0x514ABDA: "488906",
    0x514ABDD: "b801000000",
    0x514ABE2: "c3",
}

OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f]{2}(?: [0-9a-f]{2})*)")


def u64(text):
    return int(text, 16)


def sentinel_field_read(elem, sentinel, field30):
    """Pure model of the window: (stored value, return value)."""
    if elem == sentinel:
        return 0, 1
    return field30, 1


def parse_objdump(path):
    """Return {va: bytes} parsed from a GNU objdump -d text file."""
    parsed = {}
    with open(path) as fh:
        for line in fh:
            match = OBJDUMP_LINE.match(line)
            if match:
                va = int(match.group(1), 16)
                parsed[va] = bytes.fromhex(match.group(2).replace(" ", ""))
    if not parsed:
        raise ValueError(f"no disassembly lines parsed from {path}")
    return parsed


def bytes_in_range(parsed, start, end):
    """Concatenate parsed bytes over [start, end); fail on any gap."""
    out = bytearray()
    va = start
    while va < end:
        chunk = parsed.get(va)
        if chunk is None:
            raise ValueError(f"missing disassembly at {hex(va)}")
        out.extend(chunk)
        va += len(chunk)
    if va != end:
        raise ValueError(f"disassembly overruns range end {hex(end)}")
    return bytes(out)


def check_packet(ev, packet_dir):
    fn = ev["function"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    parsed = parse_objdump(os.path.join(packet_dir, "window.objdump.txt"))
    body = bytes_in_range(parsed, start, end)
    if len(body) != fn["bytes"]:
        raise ValueError(f"body length {len(body)} != {fn['bytes']}")
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        raise ValueError("body sha256 mismatch")
    for va, hexbytes in INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = parsed.get(va)
        if got != want:
            raise ValueError(
                f"instruction bytes at {hex(va)}: "
                f"{got.hex() if got else None} != {hexbytes}")
    # Branch target: je lands on the zero path.
    if 0x514ABC7 + 0x11 != 0x514ABD8:
        raise ValueError("je target is not the zero path")
    pad = bytes_in_range(parsed, end, nxt)
    if len(pad) != fn["padding_bytes"]:
        raise ValueError(f"padding length {len(pad)} != {fn['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"padding not all int3: {pad.hex()}")
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        text = fh.read()
    if fn["fde_section_offset"][2:] not in text:
        raise ValueError("window FDE section offset not in frames.txt")
    if f"pc={start:016x}..{end:016x}" not in text:
        raise ValueError("window FDE PC range not in frames.txt")
    if f"cie={fn['fde_cie'][2:]}" not in text:
        raise ValueError("window FDE CIE not in frames.txt")
    if f"pc={nxt:016x}" not in text:
        raise ValueError("next FDE start not in frames.txt")
    if fn["next_fde_section_offset"][2:] not in text:
        raise ValueError("next FDE section offset not in frames.txt")
    if f"cie={fn['next_fde_cie'][2:]}" not in text:
        raise ValueError("next FDE CIE not in frames.txt")
    return body


def evaluate_edge(edge):
    """Check one edge against the sentinel-field-read model."""
    elem = u64(edge["elem"])
    sentinel = u64(edge["sentinel"])
    if "base" in edge:
        if sentinel != (u64(edge["base"]) + 0x11E0):
            raise ValueError(
                f"edge {edge['note']}: sentinel is not base + 0x11e0")
    out, ret = sentinel_field_read(elem, sentinel, u64(edge["field30"]))
    if out != u64(edge["out"]):
        raise ValueError(
            f"edge {edge['note']}: model out {hex(out)} != {edge['out']}")
    if ret != edge["ret"]:
        raise ValueError(f"edge {edge['note']}: return must be 1")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if u64(rule["elem_offset"]) != 0x1200:
        raise ValueError("elem offset must be 0x1200")
    if u64(rule["sentinel_delta"]) != 0x11E0:
        raise ValueError("sentinel delta must be 0x11e0")
    if u64(rule["field_offset"]) != 0x30:
        raise ValueError("field offset must be 0x30")
    if rule["return_value"] != 1:
        raise ValueError("return value must be 1")


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


def check_binary(ev, binary_path, packet_body):
    fn = ev["function"]
    with open(binary_path, "rb") as fh:
        binary = fh.read()
    if hashlib.sha256(binary).hexdigest() != ev["target_sha256"]:
        raise ValueError("target digest mismatch")
    if len(binary) != ev["target_bytes"]:
        raise ValueError("target size mismatch")
    sections = elf_sections(binary)
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    body = read_va(binary, sections, start, end - start)
    if body != packet_body:
        raise ValueError("binary window bytes differ from packet bytes")
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        raise ValueError("binary body sha256 mismatch")
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"] or any(b != 0xCC for b in pad):
        raise ValueError("binary padding mismatch")
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
            if addr + idx + 5 + rel == WINDOW_START:
                found.append(addr + idx)
        idx += 1
    want = [u64(c["site"]) for c in ev["incoming"]["direct_e8_callers"]]
    if found != want:
        raise ValueError(
            f"direct caller scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")


def run_all(evidence_path, binary_path=None):
    with open(evidence_path) as fh:
        ev = json.load(fh)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    packet_body = check_packet(ev, packet_dir)
    check_edges(ev)
    if binary_path is not None:
        check_binary(ev, binary_path, packet_body)
        print("Foundation sentinel-field-read evidence reproduces exactly, "
              "including the binary cross-check.")
    else:
        print("Foundation sentinel-field-read packet evidence reproduces "
              "exactly (binary cross-check not run; pass --binary).")
    return 0


def main(argv):
    if len(argv) < 3 or argv[1] != "--check":
        print("usage: foundation_sentinel_field_read.py --check <evidence.json> "
              "[--binary <path>]", file=sys.stderr)
        return 2
    binary_path = None
    if "--binary" in argv:
        idx = argv.index("--binary")
        if idx + 1 >= len(argv):
            print("usage: --binary requires a path", file=sys.stderr)
            return 2
        binary_path = argv[idx + 1]
    try:
        return run_all(argv[2], binary_path)
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
