#!/usr/bin/env python3
"""Model of node #94 two-piece string concat (RE-001, 0x514bbb0).

Stdlib only. The binary function builds a fresh ``std::string`` from
two (pointer, length) pieces: reserve(len1 + len2), append piece one,
append piece two, return the string. Each append is guarded by the
``basic_string`` max-size check and throws ``length_error`` with the
message ``basic_string::append`` when the piece does not fit.

``concat_two`` models that contract at the string level; the
libstdc++ callees (reserve/_M_append) are modelled only through the
contract this function relies on. ``check_binary`` independently
re-checks the packet excerpts against a node #94 binary: target
digest, function carve SHA, int3 padding, every excerpt line's bytes,
and every caller census site's call target re-derived from its rel32.
"""

import hashlib
import json
import os
import re
import struct
import sys

MAX_SIZE = 0x3FFFFFFFFFFFFFFF
TARGET_SHA256 = ("3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")
FUNCTION_START = 0x514BBB0
FUNCTION_END = 0x514BC55
FUNCTION_SHA256 = ("d3b6f21647732fc9b1fb56b0b3dab0e660160d1a880022fd14a8cd56174a7745")
PACKET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           os.pardir, "research", "work-items",
                           "RE-001-string-concat-two-94")


class LengthError_(ValueError):
    """Models std::__throw_length_error("basic_string::append")."""


def reserve_total(len1, len2):
    """The reserve argument: (len1 + len2) mod 2**64, as computed
    by the lea at 0x514bbb9. On any path that completes both
    appends, len1 + len2 <= MAX_SIZE, so no wrap occurs there."""
    return (len1 + len2) & 0xFFFFFFFFFFFFFFFF


def concat_two(piece1, len1, piece2, len2):
    """Build the concatenated string, enforcing the max-size arms.

    ``piece1``/``piece2`` are byte strings; only the first ``len1`` /
    ``len2`` bytes are appended, matching _M_append(ptr, len).
    Raises LengthError_ exactly when the binary throws.
    """
    if len1 > MAX_SIZE:
        raise LengthError_("basic_string::append")
    if len2 > MAX_SIZE - len1:
        raise LengthError_("basic_string::append")
    return piece1[:len1] + piece2[:len2]


class Elf:
    """Minimal ELF64 reader for PT_LOAD byte comparison."""

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

    def read(self, va, size):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                start = offset + (va - vaddr)
                return self.data[start:start + size]
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)


_LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t| *$)")
_HEX_RE = re.compile(r"^[0-9a-f]{2}$")


def _excerpt_bytes(path):
    """Yield (address, bytes) for every disassembly line in a file."""
    with open(path) as f:
        for line in f:
            m = _LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            addr = int(m.group(1), 16)
            raw = bytes(int(t, 16) for t in m.group(2).split()
                        if _HEX_RE.match(t))
            if raw:
                yield addr, raw


def check_binary(binary_path):
    """Re-check the packet against the binary. Returns a list of
    error strings; empty means ALL CHECKS PASSED."""
    errors = []
    with open(binary_path, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        return ["target digest mismatch"]
    elf = Elf(data)
    if hashlib.sha256(
            elf.read(FUNCTION_START,
                     FUNCTION_END - FUNCTION_START)).hexdigest() \
            != FUNCTION_SHA256:
        errors.append("function carve SHA mismatch")
    if elf.read(FUNCTION_END, 5) != b"\xcc" * 5:
        errors.append("function padding is not int3")
    for name in ("window.objdump.txt", "landing.objdump.txt",
                 "callers.objdump.txt", "plt.objdump.txt"):
        path = os.path.join(PACKET_DIR, name)
        try:
            lines = list(_excerpt_bytes(path))
        except OSError as e:
            errors.append("cannot read %s: %s" % (name, e))
            continue
        if not lines:
            errors.append("no disassembly lines in %s" % name)
        for addr, raw in lines:
            try:
                actual = elf.read(addr, len(raw))
            except ValueError as e:
                errors.append("%s: %s" % (name, e))
                continue
            if actual != raw:
                errors.append("%s: byte mismatch at %#x" % (name, addr))
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        records = json.load(f)
    for site in records["censuses"]["concat_direct_callers"]:
        addr = int(site, 16)
        raw = elf.read(addr, 5)
        if raw[0] != 0xE8:
            errors.append("census site %s is not a call" % site)
            continue
        (rel,) = struct.unpack_from("<i", raw, 1)
        if addr + 5 + rel != FUNCTION_START:
            errors.append("census site %s targets %#x"
                          % (site, addr + 5 + rel))
    return errors


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    binary = argv[0] if argv else os.path.join("work", "hl-node-94.bin")
    errors = check_binary(binary)
    if errors:
        print("FAILED")
        for e in errors:
            print(" - %s" % e)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
