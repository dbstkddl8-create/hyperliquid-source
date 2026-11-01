#!/usr/bin/env python3
"""Checker and model for node #94's decimal-index replace at 0x514b390 (RE-001).

Bounded question: what does the function at 0x514b390 do with a
decimal input, a container, and a target string?

Read directly from the bytes (rdi = container, rsi = target string,
rdx = input pointer, rcx = input length):

1. It calls the parser at 0x54307c0 on a stack parse state built
   from (rdx, rcx): the parser reads decimal digits, updates the
   state (pointer, remaining length) as it consumes them, and writes
   the parsed value to the stack slot at rsp+0x18.
2. If the parser returns 0, or any input remains unconsumed, the
   entry returns 0 and the string is untouched.
3. Otherwise it compares the low 32 bits of the parsed value, as a
   signed int32, against the dword at [container + 0x778]. If the
   value is not strictly less than that threshold, it returns 0.
4. Otherwise it formats one integer with "%d" (at 0x1f6ff2) into a
   100-byte stack buffer and replaces the whole target string with
   it (via strlen and basic_string::_M_replace at position 0 over
   the string's full length), returning 1.

The formatted integer is derived from a table: let inner =
[[container + 0x788] + 0x30]; let base = [inner + 0xad8]; the entry
at index i (the parsed value, sign-extended) occupies 24 bytes at
base + 24*i, and the formatted integer is
(signed64([base + 24*i + 8] - [base + 24*i])) >> 3 (arithmetic
shift, i.e. the qword difference divided by 8).

The parser at 0x54307c0, in full: the input is (pointer at [state],
length at [state + 8]); the parsed value is written to [out]. Empty
input returns 0 with out = 0. Digits accumulate as value =
value * 10 + digit with an exact UINT64_MAX bound: value may exceed
0x1999999999999999 only never, and at exactly that value a digit
above 5 overflows -- overflow returns 0 and leaves out untouched.
A non-digit stops the parse: it returns 1 with the value so far if
at least one digit was read, else 0 with out = 0. Reaching the end
of the input returns 1 with the value. The state pointer/length are
updated after each consumed digit, so on return the caller can tell
exactly how much input was consumed.

The entry has no direct-e8 callers in a full .text scan. The parser
has exactly 10 direct-e8 call sites, this entry's being one of them;
the other nine are recorded as a census only, not claimed here.
A negative parsed index (low32 sign-extended below zero) passes a
non-negative threshold and would read before the table; that edge
is outside the modelled domain and raises in the model rather than
being given a made-up table value. The entry is protected by a
stack canary (fs:0x28 saved at rsp+0x88 and checked before return,
__stack_chk_fail on mismatch).

Stdlib only. Run from the repository root:

    python3 tools/foundation_decimal_index_replace.py \\
        --check research/work-items/foundation-decimal-index-replace-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Every claim is re-derived from target bytes: the entry
and parser bodies, both FDE records, the "%d" format string, every
direct call target, the caller censuses, the verbatim excerpts, and
the packet manifest hashes.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

ENTRY_START = 0x514B390
ENTRY_END = 0x514B486
ENTRY_NEXT_FDE = 0x514B490
PARSER_START = 0x54307C0
PARSER_END = 0x5430857
PARSER_NEXT_FDE = 0x5430860
FORMAT_ADDR = 0x1F6FF2
UINT64_MAX = (1 << 64) - 1
PARSER_LIMIT = 0x1999999999999999  # UINT64_MAX // 10


def signed32(x):
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x >= (1 << 31) else x


def signed64(x):
    x &= UINT64_MAX
    return x - (1 << 64) if x >= (1 << 63) else x


def parse_decimal(data):
    """Faithful model of 0x54307c0.

    Returns (ok, value, consumed, out_written, out_value). ``value``
    is None on overflow (out is then untouched); ``out_value`` is the
    value written to the out slot, or None when nothing was written.
    """
    if len(data) == 0:
        return (False, 0, 0, True, 0)
    value = 0
    digits = 0
    i = 0
    while i < len(data):
        b = data[i]
        if not (48 <= b <= 57):
            if digits > 0:
                return (True, value, i, True, value)
            return (False, 0, 0, True, 0)
        digit = b - 48
        digits += 1
        if value > PARSER_LIMIT or (value == PARSER_LIMIT and digit > 5):
            # Overflow: return 0, out untouched, state not advanced
            # past this digit.
            return (False, None, i, False, None)
        value = value * 10 + digit
        i += 1
    return (True, value, len(data), True, value)


def table_count(field0, field1):
    """(signed64(field1 - field0)) >> 3, as the sar $0x3 performs it."""
    return signed64(field1 - field0) >> 3


def decimal_index_replace(threshold, table, raw):
    """Faithful model of 0x514b390 for in-range indices.

    threshold is the signed int32 at [container + 0x778]; table is a
    list of (field0, field1) pairs for the table at [inner + 0xad8].
    Returns (return_code, new_string_or_None). Raises ValueError for
    a negative parsed index, which reads before the table and is
    outside the modelled domain.
    """
    ok, value, consumed, _written, _out = parse_decimal(raw)
    if not ok or consumed != len(raw):
        return (0, None)
    idx = signed32(value)
    if idx >= threshold:
        return (0, None)
    if idx < 0:
        raise ValueError("negative parsed index reads before the table")
    count = table_count(*table[idx])
    return (1, "%d" % count)


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
            (sh_name, _type, _flags, sh_addr, sh_offset,
             sh_size, _link, _info, _align, _entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", data, off)
            self.sections.append((sh_name, sh_addr, sh_offset, sh_size))
        shstr_off = self.sections[self.e_shstrndx][2]
        self.names = {}
        for idx, (sh_name, _a, _o, _s) in enumerate(self.sections):
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

    def text_range(self):
        for idx, (_n, sh_addr, sh_offset, sh_size) in enumerate(self.sections):
            if self.names.get(idx) == ".text":
                return (sh_addr, sh_offset, sh_size)
        raise ValueError("no .text section")


# ---------------------------------------------------------------- checking

def parse_objdump_window(path):
    """Parse an objdump -d excerpt into {address: (bytes, mnemonic, operands)}."""
    line_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t(\S+)(?:\s+(.*?))?\s*$")
    continuation_re = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s*)+)\s*$")
    out = {}
    previous = None
    with open(path) as f:
        for raw in f:
            m = line_re.match(raw.rstrip("\n"))
            if not m:
                continuation = continuation_re.match(raw.rstrip("\n"))
                if continuation and previous is not None:
                    encoded, mnemonic, operands = out[previous]
                    address = int(continuation.group(1), 16)
                    suffix = "".join(continuation.group(2).split())
                    if address != previous + len(encoded) // 2:
                        raise ValueError("noncontiguous objdump continuation")
                    if (len(encoded) + len(suffix)) // 2 > 15:
                        raise ValueError("objdump instruction exceeds x86 length limit")
                    out[previous] = (encoded + suffix, mnemonic, operands)
                continue
            addr = int(m.group(1), 16)
            operands = (m.group(4) or "").strip()
            if " #" in operands:
                operands = operands.split(" #", 1)[0].strip()
            operands = re.sub(r"\s*<[^>]*>", "", operands).strip()
            out[addr] = (m.group(2).strip().replace(" ", ""), m.group(3), operands)
            previous = addr
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

    entry = ev["entry"]
    body = elf.read_at(ENTRY_START, ENTRY_END - ENTRY_START)
    need(hashlib.sha256(body).hexdigest() == entry["sha256"],
         "entry function SHA mismatch")
    need(all(b == 0xCC for b in elf.read_at(ENTRY_END, ENTRY_NEXT_FDE - ENTRY_END)),
         "entry padding is not all int3")
    need(len(entry["instructions"]) == 61, "entry instruction count mismatch")
    parser = ev["parser"]
    pbody = elf.read_at(PARSER_START, PARSER_END - PARSER_START)
    need(hashlib.sha256(pbody).hexdigest() == parser["sha256"],
         "parser function SHA mismatch")
    need(all(b == 0xCC for b in elf.read_at(PARSER_END, PARSER_NEXT_FDE - PARSER_END)),
         "parser padding is not all int3")
    need(len(parser["instructions"]) == 48, "parser instruction count mismatch")

    ewin = parse_objdump_window(os.path.join(packet_dir, "entry.objdump.txt"))
    pwin = parse_objdump_window(os.path.join(packet_dir, "parser.objdump.txt"))
    for ins in entry["instructions"] + parser["instructions"]:
        addr = int(ins["address"], 16)
        excerpt = ewin.get(addr) or pwin.get(addr)
        need(excerpt is not None, "instruction %#x missing from excerpt" % addr)
        if excerpt is not None:
            need(excerpt[0] == ins["bytes"], "bytes mismatch at %#x" % addr)
            need(excerpt[1] == ins["mnemonic"], "mnemonic mismatch at %#x" % addr)
            need(excerpt[2] == ins["operands"], "operands mismatch at %#x" % addr)
        need(elf.read_at(addr, len(bytes.fromhex(ins["bytes"]))).hex()
             == ins["bytes"], "binary bytes mismatch at %#x" % addr)

    # Every direct call target re-derived from its rel32.
    for ins in entry["instructions"] + parser["instructions"]:
        if ins["mnemonic"] != "call" or ins["operands"].startswith("*"):
            continue
        addr = int(ins["address"], 16)
        raw = bytes.fromhex(ins["bytes"])
        if raw[0] != 0xE8:
            continue
        (rel,) = struct.unpack_from("<i", raw, 1)
        need(addr + len(raw) + rel == int(ins["operands"], 16),
             "call target mismatch at %#x" % addr)

    need(elf.read_at(FORMAT_ADDR, 3) == b"%d\x00", "format string mismatch")
    need(int(ev["format"]["address"], 16) == FORMAT_ADDR, "evidence format addr mismatch")

    text_addr, text_off, text_size = elf.text_range()
    text = data[text_off:text_off + text_size]
    need(["%#x" % a for a in e8_callers(text, text_addr, ENTRY_START)]
         == ev["callers_entry_e8"], "entry caller census mismatch")
    need(["%#x" % a for a in e8_callers(text, text_addr, PARSER_START)]
         == ev["callers_parser_e8"], "parser caller census mismatch")

    with open(os.path.join(packet_dir, "frames.txt")) as f:
        frames = f.read()
    need("pc=000000000514b390..000000000514b486" in frames, "entry FDE missing")
    need("pc=00000000054307c0..0000000005430857" in frames, "parser FDE missing")

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
        for f in failures:
            print("FAIL:", f)
        print("CHECKS FAILED")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
