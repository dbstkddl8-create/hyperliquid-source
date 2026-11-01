#!/usr/bin/env python3
"""Checker for node #94's keyed lookup window 0x514b1c0 (RE-001).

The window is a whole function, not a fragment: a binary-tree search
over the map object at 0x578bf20, with an out_of_range("map::at")
throw arm for every miss and a mapped-value address on every hit,
plus 13 direct e8 call sites that actually call it.

Stdlib only. Run from the repository root:

    python3 tools/foundation_map_at.py \\
        --check research/work-items/foundation-map-at-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the window body, its FDE record, the table lea, the
throw-path lea and its "map::at" string, the PLT throw call, the full
direct-e8 caller census, and the composed search rule.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

ENTRY_START = 0x514B1C0
TABLE_ADDR = 0x578BF20
SENTINEL_ADDR = 0x578BF28
THROW_TARGET = 0x5660710
MESSAGE_ADDR = 0x1EFEEE

ENTRY_INSTR = {
    0x514B1C0: "4c8d05590d6400",
    0x514B1C7: "498b5010",
    0x514B1CB: "4885d2",
    0x514B1CE: "7443",
    0x514B1D0: "498d4008",
    0x514B1D4: "eb12",
    0x514B1D6: "662e0f1f840000000000",
    0x514B1E0: "4889f2",
    0x514B1E3: "4885d2",
    0x514B1E6: "7418",
    0x514B1E8: "488b4a10",
    0x514B1EC: "488b7218",
    0x514B1F0: "397a20",
    0x514B1F3: "7ceb",
    0x514B1F5: "4889d0",
    0x514B1F8: "4889ca",
    0x514B1FB: "4885d2",
    0x514B1FE: "75e8",
    0x514B200: "498d5008",
    0x514B204: "4839d0",
    0x514B207: "740a",
    0x514B209: "397820",
    0x514B20C: "7f05",
    0x514B20E: "4883c028",
    0x514B212: "c3",
    0x514B213: "50",
    0x514B214: "488d3dd34c0afb",
    0x514B21B: "e8f0545100",
}

EXPECTED_CALLERS = [
    0x514D7CB, 0x514D7DD, 0x514D8CE, 0x514D94E, 0x514D961, 0x514D974,
    0x514D987, 0x514D99A, 0x514D9AD, 0x514D9C0, 0x514DAA1, 0x514DB62,
    0x514DB75,
]

_SENTINEL = object()


def u64(text):
    return int(text, 16)


def map_at(table, sought):
    """Faithful model of the 0x514b1c0 window.

    ``table`` is {"root": node id or None, "nodes": {id: {"left",
    "right", "key"}}}. Node ids stand in for node addresses; the
    returned value is the node id, standing in for the address
    node+0x28 that the window actually returns. A miss raises
    LookupError, standing in for the out_of_range("map::at") throw.
    Signed 32-bit comparison is used throughout, matching jl/jg.
    """
    nodes = table["nodes"]
    node = table["root"]
    if node is None:
        raise LookupError("map::at")
    candidate = _SENTINEL
    # Enter at 0x514b1e8 with rdx = current node.
    while True:
        left = nodes[node]["left"]
        right = nodes[node]["right"]
        key = nodes[node]["key"]
        if key < sought:  # jl at 0x514b1f3: advance via +0x18
            node = right
            if node is None:
                break
            continue
        # Otherwise record the candidate and go via +0x10.
        candidate = node
        node = left
        if node is None:
            break
    if candidate is _SENTINEL:
        raise LookupError("map::at")
    if nodes[candidate]["key"] > sought:  # jg at 0x514b20c
        raise LookupError("map::at")
    return candidate


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


def check_target_digest(ev, binary, sections, packet_dir):
    if hashlib.sha256(binary).hexdigest() != ev["target_sha256"]:
        return "target SHA-256 mismatch"
    return None


def check_window(ev, binary, sections, packet_dir):
    fn = ev["entry"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        return "entry length mismatch: %d != %d" % (len(body), fn["bytes"])
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        return "entry body SHA-256 mismatch"
    for va, hexbytes in ENTRY_INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "entry instruction bytes mismatch at %#x" % va
    return None


def check_evidence_instructions(ev, binary, sections, packet_dir):
    """The evidence instruction table must itself match the binary.

    The tool's hardcoded table guards the checker; this check guards
    the packet, so a hand-edited evidence.json cannot drift from the
    bytes it claims to record.
    """
    fn = ev["entry"]
    pos = u64(fn["start_va"])
    for instr in fn["instructions"]:
        va = u64(instr["va"])
        if va != pos:
            return "evidence instructions do not tile the body at %#x" % va
        want = bytes.fromhex(instr["bytes"])
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "evidence instruction bytes mismatch at %#x" % va
        pos += len(want)
    if pos != u64(fn["end_va_exclusive"]):
        return "evidence instructions do not end at the FDE end"
    return None


def check_padding(ev, binary, sections, packet_dir):
    fn = ev["entry"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        return "padding length mismatch: %d != %d" % (
            len(pad), fn["padding_bytes"])
    if pad != b"\xcc" * len(pad):
        return "padding bytes are not int3"
    return None


def check_frames(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        frames = fh.read()
    if "pc=000000000514b1c0..000000000514b220" not in frames:
        return "entry FDE record missing from frames.txt"
    if ev["entry"]["fde_section_offset"][2:] not in frames:
        return "entry FDE section offset missing from frames.txt"
    return None


def check_table_lea(ev, binary, sections, packet_dir):
    rec = ev["table"]
    site = u64(rec["site"])
    want = bytes.fromhex(rec["bytes"])
    got = read_va(binary, sections, site, len(want))
    if got != want:
        return "table lea bytes mismatch at %#x" % site
    (disp,) = struct.unpack_from("<i", got, 3)
    rip_after = site + len(want)
    if rip_after != u64(rec["rip_after"]):
        return "table lea rip-after mismatch"
    if rip_after + disp != u64(rec["address"]):
        return "table lea target mismatch"
    if disp != u64(rec["displacement"]):
        return "table lea displacement mismatch"
    if u64(rec["address"]) != TABLE_ADDR:
        return "table address mismatch"
    if u64(rec["sentinel"]) != SENTINEL_ADDR:
        return "sentinel address is not table+0x8"
    return None


def check_throw(ev, binary, sections, packet_dir):
    rec = ev["throw_call"]
    lea_site = u64(rec["message_lea_site"])
    want = bytes.fromhex(rec["message_lea_bytes"])
    got = read_va(binary, sections, lea_site, len(want))
    if got != want:
        return "message lea bytes mismatch at %#x" % lea_site
    (disp,) = struct.unpack_from("<i", got, 3)
    rip_after = lea_site + len(want)
    if rip_after != u64(rec["message_lea_rip_after"]):
        return "message lea rip-after mismatch"
    if rip_after + disp != u64(rec["message_address"]):
        return "message lea target mismatch"
    if disp != -0x4F5B32D:
        return "message lea displacement mismatch"
    if u64(rec["message_address"]) != MESSAGE_ADDR:
        return "message address mismatch"
    msg = read_section_va(binary, sections, ".rodata",
                          MESSAGE_ADDR, 8)
    if msg != b"map::at\x00":
        return "throw message bytes are not 'map::at'"
    if bytes.fromhex(rec["message_bytes"]) != b"map::at\x00":
        return "evidence message bytes mismatch"
    if rec["message"] != "map::at":
        return "evidence message text mismatch"
    call_site = u64(rec["site"])
    want = bytes.fromhex(rec["bytes"])
    got = read_va(binary, sections, call_site, len(want))
    if got != want:
        return "throw call bytes mismatch at %#x" % call_site
    (rel,) = struct.unpack_from("<i", got, 1)
    if call_site + len(want) + rel != u64(rec["target"]):
        return "throw call target mismatch"
    if u64(rec["target"]) != THROW_TARGET:
        return "throw call target is not the PLT stub"
    if rec["symbol"] != "_ZSt20__throw_out_of_rangePKc@plt":
        return "throw call symbol mismatch"
    return None


def check_callers(ev, binary, sections, packet_dir):
    found = scan_callers(binary, sections, ENTRY_START)
    if found != EXPECTED_CALLERS:
        return "entry direct e8 caller scan mismatch: %s" % (
            [hex(x) for x in found])
    listed = [u64(x) for x in ev["incoming"]["direct_e8_callers"]]
    if listed != EXPECTED_CALLERS:
        return "evidence caller list mismatch"
    return None


def check_excerpts(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    for needle, name in (
            ("514b1c0:", "entry excerpt start"),
            ("514b21b:", "throw call site"),
            ("514b214:", "message lea site"),
            ("cs nopw", "alignment nop mnemonic")):
        if needle not in window:
            return "%s missing from excerpts" % name
    if "_ZSt20__throw_out_of_rangePKc@plt" not in window:
        return "throw PLT label missing from excerpt"
    for instr in ev["entry"]["instructions"]:
        if instr["mnemonic"] not in window:
            return "mnemonic %s missing from excerpt" % instr["mnemonic"]
    return None


def check_edges(ev, binary, sections, packet_dir):
    for edge in ev["rule"]["edges"]:
        table = {"root": edge["root"],
                 "nodes": {k: {"left": v["left"], "right": v["right"],
                               "key": v["key"]}
                           for k, v in edge["nodes"].items()}}
        try:
            got = map_at(table, edge["sought"])
            outcome = got
        except LookupError:
            outcome = "throw"
        if outcome != edge["outcome"]:
            return "rule edge mismatch: %s (got %s)" % (edge, outcome)
    return None


CHECKS = (
    ("target digest", check_target_digest),
    ("entry body", check_window),
    ("evidence instructions", check_evidence_instructions),
    ("entry padding", check_padding),
    ("frames", check_frames),
    ("table lea", check_table_lea),
    ("throw path", check_throw),
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
    print("Map-at evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
