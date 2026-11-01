#!/usr/bin/env python3
"""RE-001: range sum over node #94 entries (function 0x514bc60).

The target function walks a range of 16-byte entries and returns 1
with the sum written to its second argument.  Read directly from the
bytes in research/work-items/RE-001-range-sum-94/window.objdump.txt:

    container = [[rdi + 0x788] + 0x30]
    begin = [container + 0xb18], end = [container + 0xb20]
    total = 0
    for cursor in range(begin, end, 0x10):
        target = *[cursor + 0x0]     # first load: entry's qword
        # second load happens in the loop body: rdi = [target]
        total = (total + callee([target])) mod 2**64
    [rsi] = total
    return 1

The per-entry callee (0x5032f40, own FDE, 13 bytes) is:

    return [rdi + 0x10] + 0x3e       # 0x3e == 62

so each entry contributes ``target.field + 62`` where ``target`` is
the callee argument (the value loaded from ``[entry + 0x0]``'s
address) and ``field`` is the qword at ``target + 0x10``.  The second
qword of each 16-byte entry (+0x8) is never read by this function.
The sum is a plain 64-bit wrapping add: there is no saturation, no
overflow check, and the empty range stores 0.  Four callee-saved
registers (rbx, rbp, r12, r13) are pushed and popped in balance.

The model below takes the post-deref targets as its input: an entry
is represented by a ``Target`` whose ``field`` is the qword at
+0x10.  The two-load structure itself is recorded in records.json
and verified against the raw excerpts by :func:`check_packet`; it is
not re-simulated, because the model has no memory image.

Stdlib only.  ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import json
import os
import re
import struct
import sys

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FUNC_START = 0x514BC60
FUNC_END = 0x514BCC3
CALLEE_START = 0x5032F40
CALLEE_END = 0x5032F4D
CALLEE_ADDEND = 0x3E
MASK64 = (1 << 64) - 1


class Target:
    """The callee argument for one entry: the qword stored at the
    address held in entry + 0x0 (the loop loads [cursor], then loads
    again from that value, before calling the callee)."""

    __slots__ = ("field",)

    def __init__(self, field=0):
        self.field = field & MASK64


def callee(target):
    """The 0x5032f40 callee: [rdi + 0x10] + 62, modulo 2**64."""
    return (target.field + CALLEE_ADDEND) & MASK64


def range_sum(targets):
    """Sum ``callee(t)`` over ``targets``; return ``(1, total)``.

    ``targets`` is the list of post-deref callee arguments in range
    order (one per 16-byte entry, begin to end).  The empty list
    stores 0, exactly as the empty range does in the bytes.
    """
    total = 0
    for target in targets:
        total = (total + callee(target)) & MASK64
    return 1, total


# ---------------------------------------------------------------------------
# Packet checker (used by tests/test_foundation_range_sum.py)
# ---------------------------------------------------------------------------

class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping only."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def read(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]


def _rel_target(elf, site, length):
    raw = elf.read(site, length)
    if length == 2:
        (disp,) = struct.unpack_from("<b", raw, 1)
    elif length == 5:
        (disp,) = struct.unpack_from("<i", raw, 1)
    elif length == 6:
        (disp,) = struct.unpack_from("<i", raw, 2)
    else:
        raise ValueError("unsupported branch length %d" % length)
    return site + length + disp


_INSN_LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\t")


def _check_excerpt_bytes(elf, path, errors, label):
    """Every instruction line's bytes must match the binary at its VA."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError as exc:
        errors.append("cannot read %s excerpt: %s" % (label, exc))
        return
    checked = 0
    for line in lines:
        m = _INSN_LINE.match(line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes(int(tok, 16) for tok in m.group(2).split())
        try:
            actual = elf.read(va, len(raw))
        except ValueError:
            errors.append("%s excerpt VA %#x outside PT_LOAD" % (label, va))
            continue
        if actual != raw:
            errors.append("%s excerpt bytes mismatch at %#x" % (label, va))
        checked += 1
    if checked == 0:
        errors.append("%s excerpt has no instruction lines" % label)


def check_packet(packet_dir, binary_path):
    """Verify the packet's semantic records against a binary.

    Returns a list of error strings; empty means ALL CHECKS PASSED.
    The caller census is verified by the packet's own verify.py (which
    runs a full disassembly scan); this checker verifies the recorded
    branch/call encodings, the carve SHAs, the padding, the FDE lines,
    every excerpt line's bytes, and the manifest.
    """
    errors = []
    records_path = os.path.join(packet_dir, "records.json")
    try:
        with open(records_path) as f:
            rec = json.load(f)
    except (OSError, ValueError) as exc:
        return ["cannot read records.json: %s" % exc]
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return ["cannot read binary: %s" % exc]
    if hashlib.sha256(data).hexdigest() != rec["target"]["sha256"]:
        errors.append("target digest mismatch")
    if len(data) != rec["target"]["size"]:
        errors.append("target size mismatch")
    elf = Elf(data)
    func = rec["function"]
    start = int(func["start_va"], 16)
    end = int(func["end_va_exclusive"], 16)
    body = elf.read(start, end - start)
    if len(body) != func["bytes"]:
        errors.append("function byte count mismatch")
    if hashlib.sha256(body).hexdigest() != func["sha256"]:
        errors.append("function SHA mismatch")
    pad = elf.read(end, func["padding_bytes"])
    if pad != b"\xcc" * func["padding_bytes"]:
        errors.append("function padding is not int3")
    callee_rec = rec["callee"]
    cs = int(callee_rec["start_va"], 16)
    ce = int(callee_rec["end_va_exclusive"], 16)
    cbody = elf.read(cs, ce - cs)
    if len(cbody) != callee_rec["bytes"]:
        errors.append("callee byte count mismatch")
    if hashlib.sha256(cbody).hexdigest() != callee_rec["sha256"]:
        errors.append("callee SHA mismatch")
    for branch in rec["branches"]:
        site = int(branch["site"], 16)
        want = int(branch["target"], 16)
        if _rel_target(elf, site, branch["length"]) != want:
            errors.append("branch %s target mismatch" % branch["site"])
    for call in rec["calls"]:
        site = int(call["site"], 16)
        want = int(call["target"], 16)
        if _rel_target(elf, site, 5) != want:
            errors.append("call %s target mismatch" % call["site"])
    try:
        with open(os.path.join(packet_dir, "frames.txt")) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    for key in ("function", "callee"):
        part = rec[key]
        want = "pc=%016x..%016x" % (
            int(part["start_va"], 16), int(part["end_va_exclusive"], 16))
        if want not in frames:
            errors.append("%s FDE line missing from frames.txt" % key)
    for name in ("window", "callee"):
        _check_excerpt_bytes(
            elf, os.path.join(packet_dir, "%s.objdump.txt" % name),
            errors, name)
    manifest_path = os.path.join(packet_dir, "MANIFEST.sha256")
    try:
        with open(manifest_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, name = line.split(None, 1)
                path = os.path.join(packet_dir, name.strip())
                with open(path, "rb") as pf:
                    actual = hashlib.sha256(pf.read()).hexdigest()
                if actual != digest:
                    errors.append("MANIFEST mismatch for %s" % name)
    except OSError as exc:
        errors.append("cannot verify MANIFEST: %s" % exc)
    return errors


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("packet_dir")
    ap.add_argument("binary")
    args = ap.parse_args(argv)
    errors = check_packet(args.packet_dir, args.binary)
    if errors:
        for err in errors:
            print("FAIL: %s" % err)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
