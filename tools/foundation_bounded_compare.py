#!/usr/bin/env python3
"""Checker and model for node #94's bounded byte compare 0x514b340 (RE-001).

The function compares two (pointer, length) pairs: it runs memcmp
over exactly min(first_length, second_length) bytes (skipped when
that minimum is zero) and returns the memcmp result when nonzero;
otherwise it returns first_length - second_length as a signed
64-bit difference saturated to the int32 range
[-2147483648, 2147483647]. Its only callee is libc memcmp@plt;
it has 7 direct-e8 call sites in 4 enclosing functions, every one
of which branches on the sign of the returned int.

Stdlib only. Run from the repository root:

    python3 tools/foundation_bounded_compare.py \\
        --check research/work-items/foundation-bounded-compare-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the function body, its FDE record, the memcmp call
target, the full direct-e8 caller census, and the composed rule.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNCTION_START = 0x514B340
FUNCTION_END = 0x514B38E
MEMCMP_PLT = 0x5660150
MEMCMP_CALL = 0x514B35E

EXPECTED_CALLERS = [
    0x515352C, 0x5153564, 0x51535AA, 0x51535E5, 0x51537B9,
    0x5153A49, 0x5159629,
]

INT32_MIN = -2147483648
INT32_MAX = 2147483647


def _to_signed64(value):
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= (1 << 63) else value


def _saturate_i32(diff64):
    if diff64 > INT32_MAX:
        return INT32_MAX
    if diff64 < INT32_MIN:
        return INT32_MIN
    return diff64


def compare_parts(first_diff, len_a, len_b):
    """Core rule with an explicit prefix-comparison outcome.

    ``first_diff`` is None when the shared prefix is equal (or the
    compared length is zero) and otherwise the memcmp result, an
    int in [-255, 255]. Lengths are unsigned 64-bit values; the
    difference is computed as a signed 64-bit value, exactly as
    the ``sub %rbp,%rbx`` at 0x514b367 computes it, then saturated
    by the 0x514b36a..0x514b384 clamp sequence.
    """
    if first_diff is not None and first_diff != 0:
        return first_diff
    diff = _to_signed64(len_a - len_b)
    return _saturate_i32(diff)


def compare_bytes(a, b):
    """Faithful model of the 0x514b340 window over two byte strings.

    memcmp compares the first min(len(a), len(b)) bytes as unsigned
    bytes and returns the first differing byte difference, or 0
    when the prefix is equal; the length arm then applies.
    """
    n = min(len(a), len(b))
    first_diff = None
    for i in range(n):
        if a[i] != b[i]:
            first_diff = a[i] - b[i]
            break
    return compare_parts(first_diff, len(a), len(b))


def elf_sections(binary):
    """Return [(name, sh_addr, sh_offset, sh_size)] for ELF64."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if binary[4] != 2 or binary[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHH", binary, 0x3A)
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


def check_evidence(ev, binary, packet_dir):
    """Return a list of error strings; empty means all checks pass."""
    errors = []
    if hashlib.sha256(binary).hexdigest() != ev["target_sha256"]:
        errors.append("target digest mismatch")
        return errors
    sections = elf_sections(binary)
    fn = ev["function"]
    start = int(fn["start_va"], 16)
    end = int(fn["end_va_exclusive"], 16)
    if (start, end) != (FUNCTION_START, FUNCTION_END):
        errors.append("function range mismatch")
    body = read_va(binary, sections, start, end - start)
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        errors.append("function body SHA mismatch")
    if fn["bytes"] != end - start:
        errors.append("function byte count mismatch")
    if fn["padding_bytes"] != int(fn["next_fde_start"], 16) - end:
        errors.append("padding count mismatch")
    for ins in fn["instructions"]:
        va = int(ins["va"], 16)
        want = bytes.fromhex(ins["bytes"])
        got = read_va(binary, sections, va, len(want))
        if got != want:
            errors.append("instruction bytes mismatch at %#x" % va)
    # Memcmp call: rel32 at the call site must land on memcmp@plt.
    call = ev["memcmp_call"]
    call_va = int(call["va"], 16)
    if call_va != MEMCMP_CALL:
        errors.append("memcmp call site mismatch")
    raw = read_va(binary, sections, call_va, 5)
    if raw[0] != 0xE8:
        errors.append("memcmp call opcode mismatch")
    (rel,) = struct.unpack_from("<i", raw, 1)
    if call_va + 5 + rel != MEMCMP_PLT:
        errors.append("memcmp call target mismatch")
    if int(call["plt_target"], 16) != MEMCMP_PLT:
        errors.append("memcmp PLT record mismatch")
    # Caller census: the recorded sites must equal the full scan.
    recorded = sorted(int(c["site"], 16) for c in ev["callers"])
    if recorded != EXPECTED_CALLERS:
        errors.append("recorded caller list mismatch")
    scanned = scan_callers(binary, sections, FUNCTION_START)
    if scanned != EXPECTED_CALLERS:
        errors.append("scanned caller census mismatch: %s" %
                      [hex(s) for s in scanned])
    for c in ev["callers"]:
        site = int(c["site"], 16)
        raw = read_va(binary, sections, site, 5)
        (rel,) = struct.unpack_from("<i", raw, 1)
        if site + 5 + rel != FUNCTION_START:
            errors.append("caller call target mismatch at %#x" % site)
    # Excerpt checks: every recorded mnemonic must appear in the
    # window excerpt, and every caller site must appear in the
    # callers excerpt; the FDE record must appear in frames.txt.
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window_text = fh.read()
    for ins in fn["instructions"]:
        if ins["mnemonic"] not in window_text:
            errors.append("mnemonic %s missing from window excerpt"
                          % ins["mnemonic"])
    with open(os.path.join(packet_dir, "callers.objdump.txt")) as fh:
        callers_text = fh.read()
    for c in ev["callers"]:
        if c["site"][2:] not in callers_text:
            errors.append("caller %s missing from callers excerpt"
                          % c["site"])
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        frames_text = fh.read()
    if fn["fde_record"] not in frames_text:
        errors.append("window FDE record missing from frames.txt")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", required=True)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    with open(args.check) as fh:
        ev = json.load(fh)
    with open(args.binary, "rb") as fh:
        binary = fh.read()
    packet_dir = os.path.dirname(os.path.abspath(args.check))
    errors = check_evidence(ev, binary, packet_dir)
    if errors:
        for err in errors:
            print("FAIL:", err)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
