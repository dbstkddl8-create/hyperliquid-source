#!/usr/bin/env python3
"""Checker and model for node #94's object-keyed map::at 0x514b490 (RE-001).

The function takes a map object in rdi and a signed int32 key in esi,
walks the tree (left +0x10, right +0x18, key +0x20) to the lower bound,
and returns the hit node's value pointer (node + 0x28) on an exact key
hit; on every miss it throws out_of_range("map::at") via the PLT stub
0x5660710 with the .rodata string at 0x1efeee. Its 14 direct-e8 call
sites all live in the consumer function 0x514d0c0..0x514d76e, pass the
same object in rbx with descending small keys, and immediately read a
double from the returned pointer.

Stdlib only. Run from the repository root:

    python3 tools/foundation_map_at_object.py \\
        --check research/work-items/foundation-map-at-object-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: the function body, its FDE record, the throw arm, the
full direct-e8 caller census, and the per-site key setups.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

FUNCTION_START = 0x514B490
FUNCTION_END = 0x514B4E4
THROW_PLT = 0x5660710
THROW_CALL = 0x514B4DF
STRING_VA = 0x1EFEEE
EXPECTED_KEYS = [21, 20, 19, 18, 16, 14, 13, 10, 9, 7, 6, 5, 4, 3]


class MapAtError(Exception):
    """Raised when the modelled lookup misses, like the throw arm."""


class Node:
    """One tree node: signed int32 key, value, left/right children."""

    def __init__(self, key, value, left=None, right=None):
        self.key = key
        self.value = value
        self.left = left
        self.right = right


def map_at(root, sought):
    """Faithful model of the 0x514b490 window over a node tree.

    Lower-bound walk: when the node key is strictly less than the
    sought key, continue right; otherwise record the node as the
    candidate and continue left. A missing candidate, or a
    candidate whose key is greater than the sought key, throws —
    exactly the two miss arms at 0x514b4c8..0x514b4d0. Only an
    exact key equality returns the node's value.
    """
    candidate = None
    node = root
    while node is not None:
        if node.key < sought:
            node = node.right
        else:
            candidate = node
            node = node.left
    if candidate is None or candidate.key != sought:
        raise MapAtError("map::at")
    return candidate.value


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
    """All direct-e8 call sites in .text targeting 0x514b490."""
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
    # Throw arm: string bytes and the PLT call target.
    throw = evidence["throw_arm"]
    if read_at(binary, STRING_VA, 8) != bytes.fromhex(throw["string_bytes"]):
        raise ValueError("map::at string bytes mismatch")
    call_raw = read_at(binary, THROW_CALL, 5)
    if call_raw[0] != 0xE8:
        raise ValueError("throw call is not a direct call")
    (rel,) = struct.unpack_from("<i", call_raw, 1)
    if THROW_CALL + 5 + rel != THROW_PLT:
        raise ValueError("throw call target mismatch")
    # FDE records, as retained in frames.txt.
    if packet_dir is not None:
        with open(os.path.join(packet_dir, "frames.txt")) as fh:
            frames = fh.read()
        if func["fde_record"] not in frames:
            raise ValueError("function FDE record missing from frames.txt")
        if evidence["consumer"]["fde_record"] not in frames:
            raise ValueError("consumer FDE record missing from frames.txt")
    # Full caller census plus every per-site key setup.
    sites = caller_census(binary)
    recorded = [int(c["call_va"], 16) for c in evidence["consumer"]["callers"]]
    if sites != recorded:
        raise ValueError(
            "caller census mismatch: binary %s vs recorded %s"
            % ([hex(s) for s in sites], [hex(s) for s in recorded]))
    keys = [c["key"] for c in evidence["consumer"]["callers"]]
    if keys != EXPECTED_KEYS:
        raise ValueError("caller key list mismatch: %r" % keys)
    for caller in evidence["consumer"]["callers"]:
        call_va = int(caller["call_va"], 16)
        if read_at(binary, call_va, 5) != bytes.fromhex(caller["call_bytes"]):
            raise ValueError("call bytes mismatch at %s" % caller["call_va"])
        setup = caller["key_setup"]
        setup_va = int(setup["va"], 16)
        if read_at(binary, setup_va, len(bytes.fromhex(setup["bytes"]))) != (
            bytes.fromhex(setup["bytes"])):
            raise ValueError("key setup bytes mismatch at %s" % setup["va"])
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
