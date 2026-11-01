#!/usr/bin/env python3
"""Checker and model for node #94's compaction-stats consumer 0x514d770 (RE-001).

The consumer is one whole FDE function, not a fragment: it appends a
"** Compaction Stats [<name>] **" header, a 21-column %s row and a
dash separator line to the caller's buffer. The row's first column
comes from the caller's third argument ([r15]); the other twenty
columns are the value+0x20 string fields (node+0x48) of map keys
1 and 3..21 in the global map at 0x578bf20. Thirteen keys are read
through the map::at window 0x514b1c0 (exact match, throws
out_of_range("map::at") on a miss) and seven through inlined
successor searches that pin key sought+1 exactly (smallest key
strictly greater than sought, accepted only when it equals
sought+1). Key 2 is never looked up in this function. Every
failure path in the function jumps to the same throw tail that
loads the "map::at" string and calls the throw PLT stub, so any
missing key aborts the whole row.

Stdlib only. Run from the repository root:

    python3 tools/foundation_compaction_stats.py \
        --check research/work-items/foundation-compaction-stats-94/evidence.json \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the function body, its FDE record, the thirteen
map::at call sites with their key setups, the seven inlined
successor searches with their sought/required pairs, the three
format strings, the full direct-e8 caller censuses, and the
composed row rule.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNCTION_START = 0x514D770
FUNCTION_END = 0x514DCDC
MAP_AT = 0x514B1C0
MAP_BASE = 0x578BF20
THROW_PLT = 0x5660710
SNPRINTF_PLT = 0x56605F0

EXPECTED_MAP_AT_CALLERS = [
    0x514D7CB, 0x514D7DD, 0x514D8CE, 0x514D94E, 0x514D961, 0x514D974,
    0x514D987, 0x514D99A, 0x514D9AD, 0x514D9C0, 0x514DAA1, 0x514DB62,
    0x514DB75,
]
EXPECTED_CONSUMER_CALLERS = [0x515611D, 0x5156AFB]
MAP_AT_KEYS = [21, 20, 17, 15, 14, 13, 12, 11, 10, 9, 6, 3, 1]
SUCCESSOR_PAIRS = {18: 19, 17: 18, 15: 16, 7: 8, 6: 7, 4: 5, 3: 4}
KEY_DOMAIN = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
              17, 18, 19, 20, 21]


class OutOfRange(Exception):
    """Models _ZSt20__throw_out_of_rangePKc@plt with "map::at"."""


def u64(text):
    return int(text, 16)


def make_container(pairs, root_first=True):
    """Build a BST container model from [(key, value_str)] pairs.

    ``nodes`` maps an id to {"left", "right", "key", "value"}; ids
    are the keys themselves, which is enough because the model only
    exercises comparisons and child links, never addresses. The
    header sentinel id is "header".
    """
    nodes = {}
    root = None
    for key, value in pairs:
        nodes[key] = {"left": None, "right": None, "key": key,
                      "value": value}
        if root is None:
            root = key
            continue
        node = root
        while True:
            if key < nodes[node]["key"]:
                if nodes[node]["left"] is None:
                    nodes[node]["left"] = key
                    break
                node = nodes[node]["left"]
            else:
                if nodes[node]["right"] is None:
                    nodes[node]["right"] = key
                    break
                node = nodes[node]["right"]
    leftmost = None
    node = root
    while node is not None:
        leftmost = node
        node = nodes[node]["left"]
    return {"root": root, "header": "header",
            "leftmost": leftmost if leftmost is not None else "header",
            "nodes": nodes}


def _walk(container, sought, strict):
    """Shared walk; strict=True is the inlined successor search.

    Returns the candidate node id, or the header sentinel when the
    walk never records one. For map::at (strict=False) the candidate
    is the smallest key >= sought; for the inlined blocks
    (strict=True) it is the smallest key > sought, because their
    branch is jle (key <= sought goes right) where map::at uses jl
    (key < sought goes right).
    """
    nodes = container["nodes"]
    node = container["root"]
    candidate = container["header"]
    while node is not None:
        key = nodes[node]["key"]
        if (key <= sought) if strict else (key < sought):
            node = nodes[node]["right"]
        else:
            candidate = node
            node = nodes[node]["left"]
    return candidate


def map_at(container, sought):
    """Faithful model of the 0x514b1c0 window (RE-001 #1314 rule).

    Returns the mapped value's +0x20 string field (the model stores
    that field directly as "value"). Raises OutOfRange exactly when
    the window throws: empty tree, no candidate, or candidate key
    greater than sought.
    """
    candidate = _walk(container, sought, strict=False)
    if candidate == container["header"]:
        raise OutOfRange("map::at")
    if container["nodes"][candidate]["key"] > sought:
        raise OutOfRange("map::at")
    return container["nodes"][candidate]["value"]


def successor_lookup(container, sought):
    """Faithful model of one inlined successor block.

    The block finds the smallest key strictly greater than sought
    and accepts it only when it equals sought+1 (final check
    ``cmpl $sought+1; jg throw``); anything else throws.
    """
    candidate = _walk(container, sought, strict=True)
    if candidate == container["header"]:
        raise OutOfRange("map::at")
    if container["nodes"][candidate]["key"] != sought + 1:
        raise OutOfRange("map::at")
    return container["nodes"][candidate]["value"]


def collect_row(container, first_column):
    """The twenty map columns plus the caller's first column.

    Returns the 21 strings in row order: [first_column, key 1,
    key 3, ..., key 21]. Keys read through map::at use map_at;
    keys read through inlined blocks use successor_lookup with
    sought = key - 1. Raises OutOfRange if any of the twenty keys
    is missing; key 2 is never consulted.
    """
    columns = [first_column]
    for key in KEY_DOMAIN:
        if key in MAP_AT_KEYS:
            columns.append(map_at(container, key))
        else:
            columns.append(successor_lookup(container, key - 1))
    return columns


def render_row(name, first_column, container):
    """The full appended text: header, row, dash separator, newline.

    snprintf lengths are the full formatted lengths; each write is
    clamped to the 0x7d0 (2000) buffer budget exactly as the
    function does it: the header write clamps at 2000, the row
    write uses the remaining budget, and the separator write starts
    at min(header_len + row_len, 2000) with the remaining budget.
    The separator itself is row_len dashes (the _M_construct count
    is the row snprintf's full return, not the clamped length).
    """
    header = "\n** Compaction Stats [%s] **\n" % name
    row_fmt = ("%s    %s   %s     %s %s  %s %s %s %s %s %s %s %s %s "
               "%s %s %s %s %s %s %s\n")
    row = row_fmt % tuple(collect_row(container, first_column))
    separator = "-" * len(row)
    budget = 2000
    out = header[:budget]
    remaining = budget - len(out)
    out += row[:remaining]
    pos = min(len(header) + len(row), budget)
    out += (separator + "\n")[:budget - pos]
    return out


def elf_sections(binary):
    """Return [(name, sh_addr, sh_offset, sh_size)] for ELF64."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if binary[4] != 2 or binary[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH",
                                                            binary, 0x3A)
    headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, _type, _flags, addr, offset, size) = struct.unpack_from(
            "<IIQQQQ", binary, off)
        headers.append((name, addr, offset, size))
    str_off = headers[e_shstrndx][2]
    out = []
    for (name_off, addr, offset, size) in headers:
        end = binary.index(b"\x00", str_off + name_off)
        name = binary[str_off + name_off:end].decode()
        out.append((name, addr, offset, size))
    return out


def read_va(binary, sections, va, count):
    """Read bytes at a VA from whichever section contains it."""
    for (_name, addr, offset, size) in sections:
        if addr <= va and va + count <= addr + size:
            start = offset + (va - addr)
            return binary[start:start + count]
    raise ValueError("VA %#x outside every section" % va)


def text_section(binary, sections):
    """The largest section named .text (the scan surface)."""
    cands = [(addr, offset, size) for (n, addr, offset, size)
             in sections if n == ".text"]
    if not cands:
        raise ValueError("no .text section")
    return max(cands, key=lambda c: c[2])


def scan_callers(binary, sections, target):
    addr, offset, size = text_section(binary, sections)
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


def check_function(ev, binary, sections, packet_dir):
    fn = ev["function"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    if start != FUNCTION_START or end != FUNCTION_END:
        return "function range mismatch"
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        return "function length mismatch: %d != %d" % (len(body),
                                                       fn["bytes"])
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        return "function body SHA-256 mismatch"
    pad = read_va(binary, sections, end,
                  u64(fn["next_fde_start"]) - end)
    if len(pad) != fn["padding_bytes"] or pad != b"\xcc" * len(pad):
        return "padding bytes are not int3"
    return None


def check_instructions(ev, binary, sections, packet_dir):
    table = {u64(i["va"]): i for i in ev["function"]["instructions"]}
    table.update({u64(i["va"]): i for i in ev["caller_instructions"]})
    # GNU's default seven-byte display wraps these encodings onto a second
    # line. The retained instruction must include its complete displacement.
    complete = {
        0x514D7A2: "64488b042528000000",
        0x514D7AB: "48898424b8000000",
        0x514DA3D: "4889b42480000000",
        0x514DAFE: "4889b42488000000",
        0x514DC19: "4c8dac2430010000",
    }
    for va, raw in complete.items():
        if va not in table or table[va]["bytes"] != raw:
            return "incomplete instruction encoding at %#x" % va
    for va, instr in table.items():
        want = bytes.fromhex(instr["bytes"])
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "instruction bytes mismatch at %#x" % va
    return None


def check_excerpts(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "consumer.objdump.txt")) as fh:
        consumer = fh.read()
    with open(os.path.join(packet_dir, "callers.objdump.txt")) as fh:
        callers = fh.read()
    for instr in ev["function"]["instructions"]:
        va = instr["va"][2:]
        if (va + ":") not in consumer:
            return "consumer excerpt missing instruction at %s" % va
        if instr["mnemonic"] not in consumer:
            return "consumer excerpt missing mnemonic %s" % (
                instr["mnemonic"],)
    for instr in ev["caller_instructions"]:
        va = instr["va"][2:]
        if (va + ":") not in callers:
            return "caller excerpt missing instruction at %s" % va
    return None


def check_frames(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        frames = fh.read()
    for needle in ("pc=000000000514d770..000000000514dcdc",
                   "pc=00000000051560b0..0000000005157a19",
                   "0x0029aaf4"):
        if needle not in frames:
            return "FDE record missing from frames.txt: %s" % needle
    return None


def _instr_by_va(ev, va):
    for instr in ev["function"]["instructions"]:
        if instr["va"] == va:
            return instr
    return None


def _imm_of(instr):
    ops = instr["operands"]
    if not ops.startswith("$0x"):
        return None
    return int(ops[3:].split(",")[0], 16)


def check_map_at_calls(ev, binary, sections, packet_dir):
    calls = ev["map_at_calls"]
    if [c["key"] for c in calls] != MAP_AT_KEYS:
        return "map::at key sequence mismatch"
    for rec in calls:
        site = u64(rec["call_site"])
        got = read_va(binary, sections, site, 5)
        if got[0] != 0xE8:
            return "map::at call is not e8 at %s" % rec["call_site"]
        (rel,) = struct.unpack_from("<i", got, 1)
        if site + 5 + rel != MAP_AT:
            return "map::at call target mismatch at %s" % rec["call_site"]
        setup = _instr_by_va(ev, rec["key_setup_va"])
        if setup is None or _imm_of(setup) != rec["key"]:
            return "map::at key setup mismatch for key %d" % rec["key"]
        load = _instr_by_va(ev, rec["value_load_va"])
        if load is None or not load["operands"].startswith("0x20(%"):
            return "map::at value load mismatch for key %d" % rec["key"]
    return None


def check_inline_lookups(ev, binary, sections, packet_dir):
    for rec in ev["inline_successor_lookups"]:
        if SUCCESSOR_PAIRS.get(rec["sought"]) != rec["required_key"]:
            return "successor pair mismatch for sought %d" % rec["sought"]
        header = _instr_by_va(ev, rec["header_cmp_va"])
        final = _instr_by_va(ev, rec["final_check_va"])
        load = _instr_by_va(ev, rec["value_load_va"])
        if header is None or _imm_of(header) != rec["sought"]:
            return "inline header cmp mismatch for sought %d" % rec["sought"]
        if final is None or _imm_of(final) != rec["required_key"]:
            return "inline final check mismatch for sought %d" % rec["sought"]
        if load is None or not load["operands"].startswith("0x48(%"):
            return "inline value load mismatch for sought %d" % rec["sought"]
    return None


def check_key_domain(ev, binary, sections, packet_dir):
    got = sorted([c["key"] for c in ev["map_at_calls"]] +
                 [r["required_key"]
                  for r in ev["inline_successor_lookups"]])
    if got != ev["key_domain"] or got != KEY_DOMAIN:
        return "key domain mismatch: %s" % (got,)
    if ev["absent_key"] != 2 or 2 in got:
        return "absent key is not exactly 2"
    cols = ev["row_columns"]
    if len(cols) != 21:
        return "row column count is not 21"
    if [c["key"] for c in cols[1:]] != KEY_DOMAIN:
        return "row column key order mismatch"
    if cols[0]["key"] is not None:
        return "first row column must not be a map key"
    return None


def check_formats(ev, binary, sections, packet_dir):
    for rec in ev["formats"]:
        want = rec["string"].encode() + b"\x00"
        got = read_va(binary, sections, u64(rec["va"]), len(want))
        if got != want:
            return "format string mismatch at %s" % rec["va"]
    if ev["formats"][1]["string"].count("%s") != 21:
        return "row format does not have 21 %s conversions"
    return None


def check_callers(ev, binary, sections, packet_dir):
    found_map = scan_callers(binary, sections, MAP_AT)
    if found_map != EXPECTED_MAP_AT_CALLERS:
        return "map::at direct e8 caller scan mismatch: %s" % (
            [hex(x) for x in found_map],)
    found_cons = scan_callers(binary, sections, FUNCTION_START)
    if found_cons != EXPECTED_CONSUMER_CALLERS:
        return "consumer direct e8 caller scan mismatch: %s" % (
            [hex(x) for x in found_cons],)
    listed = [u64(c["call_site"]) for c in ev["consumer_callers"]]
    if listed != EXPECTED_CONSUMER_CALLERS:
        return "evidence consumer caller list mismatch"
    for rec in ev["consumer_callers"]:
        site = u64(rec["call_site"])
        got = read_va(binary, sections, site, 5)
        (rel,) = struct.unpack_from("<i", got, 1)
        if site + 5 + rel != FUNCTION_START:
            return "consumer caller target mismatch at %s" % rec["call_site"]
    return None


def check_throw(ev, binary, sections, packet_dir):
    rec = ev["throw"]
    want = rec["string"].encode() + b"\x00"
    got = read_va(binary, sections, u64(rec["string_va"]), len(want))
    if got != want:
        return "throw string mismatch"
    site = u64(rec["tail_call_va"])
    call = read_va(binary, sections, site, 5)
    (rel,) = struct.unpack_from("<i", call, 1)
    if site + 5 + rel != u64(rec["plt"]):
        return "throw PLT call target mismatch"
    return None


CHECKS = [
    ("target digest", check_target_digest),
    ("function body", check_function),
    ("instruction bytes", check_instructions),
    ("excerpts", check_excerpts),
    ("frames", check_frames),
    ("map::at calls", check_map_at_calls),
    ("inline successor lookups", check_inline_lookups),
    ("key domain and columns", check_key_domain),
    ("format strings", check_formats),
    ("caller censuses", check_callers),
    ("throw tail", check_throw),
]


def run_checks(evidence_path, binary_path):
    with open(evidence_path) as fh:
        ev = json.load(fh)
    with open(binary_path, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    packet_dir = os.path.dirname(evidence_path)
    failures = []
    for name, fn in CHECKS:
        err = fn(ev, binary, sections, packet_dir)
        print("%s: %s" % (name, "ok" if err is None else "FAIL " + err))
        if err is not None:
            failures.append(name)
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", required=True)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    failures = run_checks(args.check, args.binary)
    if failures:
        print("FAILED: %s" % ", ".join(failures))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
