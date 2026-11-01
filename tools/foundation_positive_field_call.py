#!/usr/bin/env python3
"""Checker for node #94's field-positive call: entry 0x514b0f0 plus its
callee 0x5228fe0 (RE-001).

Stdlib only. Run from the repository root:

    python3 tools/foundation_positive_field_call.py \
        --check research/work-items/foundation-positive-field-call-94/evidence.json \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: both window bodies, both padding runs, both FDE records,
the call site joining entry to callee, the full direct-e8 caller
censuses for both windows, and the composed rule with its movzbl
subtlety. A failure prints the mismatching check and exits nonzero.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

ENTRY_START = 0x514B0F0
CALLEE_START = 0x5228FE0

ENTRY_INSTR = {
    0x514B0F0: "f30f1efa",
    0x514B0F4: "53",
    0x514B0F5: "488dba00110000",
    0x514B0FC: "4889f3",
    0x514B0FF: "e8dcde0d00",
    0x514B104: "0fb6c0",
    0x514B107: "488903",
    0x514B10A: "b801000000",
    0x514B10F: "5b",
    0x514B110: "c3",
}

CALLEE_INSTR = {
    0x5228FE0: "f30f1efa",
    0x5228FE4: "8b07",
    0x5228FE6: "85c0",
    0x5228FE8: "0f9fc0",
    0x5228FEB: "c3",
}

CALLEE_CALLERS = [
    0x4FEB909, 0x503594B, 0x503FA27, 0x504157F, 0x505C899, 0x505D8C0,
    0x50E6CC5, 0x50E6CFB, 0x50E7471, 0x50EE21D, 0x512BDF9, 0x514B0FF,
]


def u64(text):
    return int(text, 16)


def s32(value):
    """Interpret a 32-bit field value as signed, as the callee's test does."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def callee_low(field):
    """The callee's low byte after setg: 1 iff the field is > 0 signed."""
    return 1 if s32(field) > 0 else 0


def callee_full(field):
    """The callee's full rax: mov zero-extends, setg rewrites only %al.

    This is deliberately NOT a clean 0/1: field 0x12345678 yields
    0x12345601 and field 0xFFFFFFFF yields 0xFFFFFF00.
    """
    return (field & 0xFFFFFF00) | callee_low(field)


def entry_out(field):
    """The composed output: the entry's movzbl keeps only the low byte."""
    return callee_low(field)


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
    for key, pc in (("entry", "pc=000000000514b0f0..000000000514b111"),
                    ("callee", "pc=0000000005228fe0..0000000005228fec")):
        if pc not in frames:
            return "%s FDE record missing from frames.txt" % key
        if ev[key]["fde_section_offset"][2:] not in frames:
            return "%s FDE section offset missing from frames.txt" % key
    return None


def check_call(ev, binary, sections, packet_dir):
    call = ev["call"]
    site = u64(call["site"])
    want = bytes.fromhex(call["bytes"])
    got = read_va(binary, sections, site, len(want))
    if got != want:
        return "call site bytes mismatch at %#x" % site
    (rel,) = struct.unpack_from("<i", got, 1)
    if site + 5 + rel != u64(call["target"]):
        return "call target mismatch"
    if u64(call["target"]) != CALLEE_START:
        return "call target is not the callee start"
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
    found = scan_callers(binary, sections, CALLEE_START)
    if found != CALLEE_CALLERS:
        return "callee direct e8 caller scan mismatch: %s" % (
            [hex(f) for f in found],)
    if [u64(v) for v in ev["callee_callers"]["direct_e8_callers"]] != CALLEE_CALLERS:
        return "evidence callee caller list mismatch"
    if 0x514B0FF not in CALLEE_CALLERS:
        return "entry call site missing from callee caller census"
    return None


def check_excerpts(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "entry.objdump.txt")) as fh:
        entry = fh.read()
    with open(os.path.join(packet_dir, "callee.objdump.txt")) as fh:
        callee = fh.read()
    for needle, where, name in (
            ("514b0f0:", entry, "entry excerpt start"),
            ("514b0ff:", entry, "entry call site"),
            ("5228fe0", entry, "entry call target"),
            ("endbr64", entry, "entry endbr64 mnemonic"),
            ("5228fe0:", callee, "callee excerpt start"),
            ("5228feb:", callee, "callee ret"),
            ("endbr64", callee, "callee endbr64 mnemonic"),
            ("setg", callee, "callee setg mnemonic")):
        if needle not in where:
            return "%s missing from excerpts" % name
    for fn, excerpt in (("entry", entry), ("callee", callee)):
        for instr in ev[fn]["instructions"]:
            if instr["mnemonic"] not in excerpt:
                return "%s mnemonic %s missing from %s excerpt" % (
                    fn, instr["mnemonic"], fn)
    return None


def check_edges(ev, binary, sections, packet_dir):
    for edge in ev["rule"]["edges"]:
        field = edge["field"] & 0xFFFFFFFF
        if entry_out(field) != edge["out"]:
            return "rule edge out mismatch: field %#x -> %d, expected %d" % (
                field, entry_out(field), edge["out"])
        if edge["return_value"] != 1:
            return "rule edge return mismatch: field %#x" % field
    return None


CHECKS = (
    ("target digest", check_target_digest),
    ("entry body", lambda ev, b, s, p: check_window(ev, b, s, p, "entry", ENTRY_INSTR)),
    ("callee body", lambda ev, b, s, p: check_window(ev, b, s, p, "callee", CALLEE_INSTR)),
    ("entry padding", lambda ev, b, s, p: check_padding(ev, b, s, p, "entry")),
    ("callee padding", lambda ev, b, s, p: check_padding(ev, b, s, p, "callee")),
    ("frames", check_frames),
    ("call", check_call),
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
    print("Field-positive call evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
