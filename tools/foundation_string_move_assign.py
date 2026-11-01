#!/usr/bin/env python3
"""Checker and model for node #94's string move-assign 0x514b4f0 (RE-001).

The function takes a destination string object in rdi and a source
string object in rsi. Each object is a libstdc++-style string: a data
pointer at +0x0, a length at +0x8, and a union at +0x10 holding either
the heap capacity or the 16-byte small-string (SSO) character buffer.
An object is SSO exactly when its pointer equals its own +0x10 address.

Composed rule, read directly from the bytes:

- Source SSO: copy the source bytes into the destination's existing
  buffer (memcpy for length >= 2, a single movzbl store for length 1,
  nothing for length 0), set the destination length to the source
  length, write the terminator at destination[length], then empty the
  source (length 0, first byte 0). The destination pointer and, for a
  heap destination, its capacity are unchanged.
- Source heap: the destination takes over the source buffer, length
  and capacity. The source takes the destination's old buffer and old
  capacity and is emptied (length 0, first byte 0 at the old buffer).
  Two old-buffer special cases: when the destination was SSO, the
  source's new buffer is the destination's internal (+0x10) buffer;
  when the destination's old pointer was null, the source's new buffer
  is its own internal buffer. In every case the source ends empty.
- Self move-assign (destination is the source object) empties the
  string: every path writes length 0 and a terminator byte to the
  object's own buffer.

The function's only callee is memcpy@plt (0x5660100), used only on
the SSO-source copy arm. Its 20 direct-e8 call sites live in 13
distinct enclosing functions. No stack canary is present.

Stdlib only. Run from the repository root:

    python3 tools/foundation_string_move_assign.py \\
        --check research/work-items/foundation-string-move-assign-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the function body, its FDE record, the memcpy arm, the
full direct-e8 caller census, the caller FDE records, the verbatim
excerpts, and the packet manifest hashes.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNCTION_START = 0x514B4F0
FUNCTION_END = 0x514B5C8
MEMCPY_PLT = 0x5660100
MEMCPY_CALL = 0x514B580
EXPECTED_CALLERS = [
    0x514BE33, 0x514CCAA, 0x514DDAB, 0x514EAF6, 0x514ECC4, 0x514EDC1,
    0x514EFA9, 0x514FF33, 0x51546D6, 0x51549B2, 0x51559A6, 0x5155A3C,
    0x5155A73, 0x5155AB4, 0x5155AF5, 0x5155E30, 0x5157DDF, 0x5157E4E,
    0x5157EAA, 0x515963D,
]
EXPECTED_ENCLOSING = [
    (0x514BDF0, 0x514BE75), (0x514CC10, 0x514CCF9), (0x514DCE0, 0x514DDF1),
    (0x514E9F0, 0x514EB3A), (0x514EB90, 0x514ED1B), (0x514ED50, 0x514F223),
    (0x514FD60, 0x514FFD8), (0x5154460, 0x51547CD), (0x5154830, 0x5154AD6),
    (0x5155710, 0x5155BED), (0x5155C50, 0x5155FAE), (0x5157D30, 0x5158EBE),
    (0x5159180, 0x515994F),
]


class Buffer:
    """One string character buffer; content is the live string bytes."""

    def __init__(self, content=b""):
        self.content = bytes(content)


class Str:
    """A string object: pointer, length, capacity, internal buffer."""

    def __init__(self, ptr, size, cap, internal):
        self.ptr = ptr  # a Buffer, or None for a null pointer
        self.size = size
        self.cap = cap  # meaningful only when ptr is a heap buffer
        self.internal = internal  # this object's own SSO buffer

    def is_sso(self):
        return self.ptr is not None and self.ptr is self.internal

    def data(self):
        if self.ptr is None:
            return b""
        return self.ptr.content[:self.size]


def make_heap(data, cap):
    """A heap string holding data with the given capacity."""
    buf = Buffer(data)
    return Str(buf, len(data), cap, Buffer())


def make_sso(data):
    """An SSO string whose buffer is its own internal buffer."""
    internal = Buffer(data)
    return Str(internal, len(data), 15, internal)


def move_assign(dest, src):
    """Faithful model of the 0x514b4f0 move-assign over Str objects."""
    if dest is src:
        # Every path writes length 0 and a terminator to the object.
        dest.size = 0
        if dest.ptr is not None:
            dest.ptr.content = b""
        return
    if src.is_sso():
        # Copy arm: destination buffer unchanged, source emptied.
        # A null destination pointer has no copy destination in the
        # bytes (the copy arm dereferences it), so it is not modelled.
        if dest.ptr is None:
            raise ValueError("copy arm with a null destination pointer")
        data = src.data()
        dest.ptr.content = data
        dest.size = src.size
        src.size = 0
        src.ptr.content = b""
        return
    # Steal arm: destination takes the source buffer/length/capacity.
    old_ptr, old_cap = dest.ptr, dest.cap
    dest_was_sso = dest.is_sso()
    src_ptr, src_cap = src.ptr, src.cap
    dest.ptr, dest.cap, dest.size = src_ptr, src_cap, src.size
    if dest_was_sso:
        src.ptr = dest.internal
    elif old_ptr is None:
        src.ptr = src.internal
    else:
        src.ptr, src.cap = old_ptr, old_cap
    src.size = 0
    src.ptr.content = b""


def elf_sections(binary):
    """Return [(name, sh_addr, sh_offset, sh_size)] for ELF64."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if binary[4] != 2 or binary[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", binary, off)[:6])
        sections.append([sh_name, sh_addr, sh_offset, sh_size])
    str_off = sections[e_shstrndx][2]
    out = []
    for sh_name, sh_addr, sh_offset, sh_size in sections:
        end = binary.index(b"\x00", str_off + sh_name)
        name = binary[str_off + sh_name:end].decode("ascii")
        out.append((name, sh_addr, sh_offset, sh_size))
    return out


def va_to_offset(binary, va):
    """Map a virtual address to a file offset via section headers."""
    for name, sh_addr, sh_offset, sh_size in elf_sections(binary):
        if sh_addr <= va < sh_addr + sh_size:
            return sh_offset + (va - sh_addr)
    raise ValueError("address 0x%x is not in any section" % va)


def read_at(binary, va, size):
    return binary[va_to_offset(binary, va):va_to_offset(binary, va) + size]


def caller_census(binary):
    """All direct-e8 call sites in .text targeting 0x514b4f0."""
    for name, sh_addr, sh_offset, sh_size in elf_sections(binary):
        if name != ".text":
            continue
        text = binary[sh_offset:sh_offset + sh_size]
        sites = []
        for i in range(len(text) - 5):
            if text[i] != 0xE8:
                continue
            (rel,) = struct.unpack_from("<i", text, i + 1)
            if sh_addr + i + 5 + rel == FUNCTION_START:
                sites.append(sh_addr + i)
        return sites
    raise ValueError("no .text section")


def excerpt_lines(path):
    """Map instruction VA -> disassembly line for lines with asm text."""
    out = {}
    with open(path) as fh:
        for line in fh:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            addr = parts[0].strip().rstrip(":")
            if not addr or not all(c in "0123456789abcdef" for c in addr):
                continue
            out[int(addr, 16)] = line.rstrip("\n")
    return out


def check(evidence, binary, packet_dir=None):
    """Re-derive every packet claim from target bytes; raise on mismatch."""
    if hashlib.sha256(binary).hexdigest() != evidence["target_sha256"]:
        raise ValueError("target digest mismatch")
    func = evidence["function"]
    if int(func["start_va"], 16) != FUNCTION_START:
        raise ValueError("function start mismatch")
    if int(func["end_va_exclusive"], 16) != FUNCTION_END:
        raise ValueError("function end mismatch")
    body = read_at(binary, FUNCTION_START, func["bytes"])
    if hashlib.sha256(body).hexdigest() != func["sha256"]:
        raise ValueError("function bytes mismatch")
    for ins in func["instructions"]:
        va = int(ins["va"], 16)
        raw = bytes.fromhex(ins["bytes"])
        if read_at(binary, va, len(raw)) != raw:
            raise ValueError("instruction bytes mismatch at %s" % ins["va"])
    # Memcpy arm: the only call in the function, to the memcpy PLT stub.
    arm = evidence["memcpy_arm"]
    call_raw = read_at(binary, MEMCPY_CALL, 5)
    if call_raw[0] != 0xE8:
        raise ValueError("memcpy call is not a direct call")
    if call_raw.hex() != arm["memcpy_call_bytes"]:
        raise ValueError("memcpy call bytes mismatch")
    (rel,) = struct.unpack_from("<i", call_raw, 1)
    if MEMCPY_CALL + 5 + rel != MEMCPY_PLT:
        raise ValueError("memcpy call target mismatch")
    if int(arm["memcpy_plt"], 16) != MEMCPY_PLT:
        raise ValueError("memcpy PLT mismatch")
    # Full caller census plus every recorded call site.
    sites = caller_census(binary)
    if sites != EXPECTED_CALLERS:
        raise ValueError("caller census mismatch: %s" % [hex(s) for s in sites])
    recorded = [int(c["call_va"], 16) for c in evidence["callers"]]
    if sites != recorded:
        raise ValueError(
            "caller census mismatch: binary %s vs recorded %s"
            % ([hex(s) for s in sites], [hex(s) for s in recorded]))
    enclosing = []
    for caller in evidence["callers"]:
        call_va = int(caller["call_va"], 16)
        call_raw = read_at(binary, call_va, 5)
        if call_raw[0] != 0xE8:
            raise ValueError("caller is not a direct call at %s"
                             % caller["call_va"])
        if call_raw.hex() != caller["call_bytes"]:
            raise ValueError("call bytes mismatch at %s" % caller["call_va"])
        (rel,) = struct.unpack_from("<i", call_raw, 1)
        if call_va + 5 + rel != FUNCTION_START:
            raise ValueError("call target mismatch at %s" % caller["call_va"])
        pair = (int(caller["enclosing_fde_start"], 16),
                int(caller["enclosing_fde_end"], 16))
        if pair not in enclosing:
            enclosing.append(pair)
    if enclosing != EXPECTED_ENCLOSING:
        raise ValueError("enclosing functions mismatch: %s"
                         % [(hex(a), hex(b)) for a, b in enclosing])
    if packet_dir is not None:
        with open(os.path.join(packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        if func["fde_record"] not in frames:
            raise ValueError("function FDE record missing from frames.txt")
        seen_fde = set()
        for caller in evidence["callers"]:
            if caller["enclosing_fde_record"] in seen_fde:
                continue
            seen_fde.add(caller["enclosing_fde_record"])
            if caller["enclosing_fde_record"] not in frames:
                raise ValueError("caller FDE record missing from frames.txt")
        # Verbatim excerpts: every recorded mnemonic must appear on
        # its own objdump line, exactly as objdump emitted it.
        window = excerpt_lines(os.path.join(packet_dir, "window.objdump.txt"))
        for ins in func["instructions"]:
            va = int(ins["va"], 16)
            if va not in window:
                raise ValueError("instruction missing from excerpt: %s"
                                 % ins["va"])
            asm = window[va].split("\t")[-1].strip()
            if not asm or asm.split(None, 1)[0] != ins["mnemonic"]:
                raise ValueError("mnemonic mismatch in excerpt at %s: %r"
                                 % (ins["va"], asm))
        callers_ex = excerpt_lines(
            os.path.join(packet_dir, "callers.objdump.txt"))
        for caller in evidence["callers"]:
            va = int(caller["call_va"], 16)
            if va not in callers_ex:
                raise ValueError("caller missing from excerpt: %s"
                                 % caller["call_va"])
            line = callers_ex[va]
            if "call" not in line or "514b4f0" not in line:
                raise ValueError("caller excerpt mismatch at %s" % caller["call_va"])
        # Packet manifest: every listed file must hash as recorded.
        with open(os.path.join(packet_dir, "MANIFEST.sha256")) as fh:
            manifest = {}
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                digest, name = line.split(None, 1)
                manifest[name.strip()] = digest
        for name in ("window.objdump.txt", "callers.objdump.txt",
                     "frames.txt", "evidence.json", "README.md"):
            if name not in manifest:
                raise ValueError("manifest missing %s" % name)
            with open(os.path.join(packet_dir, name), "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != manifest[name]:
                    raise ValueError("manifest hash mismatch for %s" % name)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, help="evidence.json path")
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    with open(args.check) as fh:
        evidence = json.load(fh)
    with open(args.binary, "rb") as fh:
        binary = fh.read()
    check(evidence, binary, packet_dir=os.path.dirname(args.check))
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
