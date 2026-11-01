#!/usr/bin/env python3
"""RE-001: counted-pointer dispose at node #94 function 0x514bb10.

The function is vtable slot 2 of the ``_Sp_counted_ptr_inplace``
family (vtable address point 0x575b048; see the packet's
relocations.txt). It takes a counted object in rdi:

    value = [object + 0x18]
    if value == 0:
        return                        # the head node is never read
    node = [object + 0x10]
    walk the +0x38 chain from node, reading each node's vtable
    slot +0x38 dispose function:
      - the first node's dispose, when it differs from the runtime
        guard value (GOT slot 0x5777960, RELATIVE to 0x4f9ea60),
        is CALLED with (node, value, 0) and dispose returns;
      - otherwise the next nodes' dispose functions are compared
        against the previous node's dispose; the first one that
        differs is TAIL-CALLED with (node, value, 0);
      - if the first five nodes all carry the guard dispose, the
        fifth node's dispose is tail-called unconditionally; when
        that dispose is the guard itself, the guard continues the
        walk (see ``guard_continue``).

The guard (0x4f9ea60) is the default dispose. It takes a node in
rdi, a second argument in rsi (untouched), and a flag byte in dl
(zero-extended by movzbl). It walks from [node + 0x38] onward with
the same rule: the first node's dispose is compared against the
guard itself, later nodes against the previous node's dispose, and
the ninth node examined is tail-called unconditionally, so a
guard tail-call recurses and the walk is unbounded, not nine
steps. The comparisons against the previous node's dispose are
equivalent to guard compares on every reachable path: a node is
only reached when the previous node's dispose equalled the guard
(or, for the first node, the guard itself).

Both functions return void; the observable outcome is which node
is invoked, with which arguments, and whether the invocation is a
call (dispose returns afterwards) or a tail call. The node type,
the meaning of [object + 0x18] beyond "the second dispose
argument", and what a non-guard dispose does with its arguments
are NOT claimed here: only the dispatch rule above.

Stdlib only. ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import os
import re
import struct

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DISPOSE_START = 0x514BB10
DISPOSE_END = 0x514BB95
GUARD_START = 0x4F9EA60
GUARD_END = 0x4F9EB0A
GUARD_NEXT_FDE = 0x4F9EB10
GOT_GUARD_SLOT = 0x5777960

GUARD = "guard"  # marker: the node's dispose slot is 0x4f9ea60


class Node:
    """One chain node.

    ``dispose`` is GUARD for a default-dispose node, or any other
    hashable marker (for example a string name) for a node with its
    own dispose function. ``next_node`` is the node at +0x38, or
    None at the end of the chain. The model never reads past the
    window the bytes unroll, so a chain that ends inside a window
    raises ValueError instead of silently inventing a node.
    """

    __slots__ = ("dispose", "next_node")

    def __init__(self, dispose=GUARD, next_node=None):
        self.dispose = dispose
        self.next_node = next_node


def _walk_window(start, value, flag, window, first_is_call):
    """Transliterate one unrolled window.

    ``start`` is the first node examined. ``window`` is the number
    of nodes the bytes examine before the unconditional tail call.
    Returns ("return", None) only for the value-zero path, which
    the caller handles before calling this helper; here it returns
    ("call", node, value, flag) or ("tail", node, value, flag).
    """
    current = start
    previous = GUARD
    for i in range(window):
        if current is None:
            raise ValueError("chain ends inside the dispose window")
        fn = current.dispose
        if i == window - 1:
            return ("tail", current, value, flag)
        if fn != previous:
            if i == 0 and first_is_call:
                return ("call", current, value, flag)
            return ("tail", current, value, flag)
        previous = fn
        current = current.next_node
    raise AssertionError("unreachable")


def dispose(value, head):
    """The 0x514bb10 dispose: outcome of disposing ``head``.

    ``value`` is [object + 0x18]; ``head`` is the [object + 0x10]
    node (None is only accepted when value == 0, mirroring the
    bytes, which return before reading +0x10 on that path).
    """
    if value == 0:
        return ("return", None)
    if head is None:
        raise ValueError("nonzero value with no head node")
    return _walk_window(head, value, 0, 5, first_is_call=True)


def guard_continue(node, value, flag):
    """The 0x4f9ea60 guard: outcome of invoking it on ``node``.

    The walk starts at [node + 0x38] and examines nine nodes: the
    first node's dispose is compared against the guard itself,
    later nodes against the previous node's dispose, and the ninth
    node's dispose is tail-called unconditionally. ``flag`` is the
    zero-extended dl byte, passed through unchanged to the invoked
    dispose.
    """
    if node.next_node is None:
        raise ValueError("guard invoked on a chain-terminating node")
    return _walk_window(node.next_node, value, flag, 9,
                        first_is_call=False)


def dispose_full(value, head):
    """Follow the dispatch to the first non-guard dispose invoked.

    Tail calls into the guard recurse through ``guard_continue``;
    a "call" outcome (first node, non-guard) is terminal because
    dispose returns after that call.
    """
    outcome = dispose(value, head)
    while outcome[0] == "tail" and outcome[1].dispose == GUARD:
        node, _value, flag = outcome[1], outcome[2], outcome[3]
        outcome = guard_continue(node, outcome[2], flag)
    return outcome


class _Elf:
    """Minimal ELF64 reader: PT_LOAD mapping and RELA sections."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_shentsize, self.e_shnum) = struct.unpack_from("<HH", data, 0x3A)
        (self.e_shstrndx,) = struct.unpack_from("<H", data, 0x3E)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            (name, sh_type, _flags, _addr, sh_offset,
             sh_size, _link, _info, _align,
             _entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
            self.sections.append((name, sh_type, sh_offset, sh_size))
        shstr_off = self.sections[self.e_shstrndx][2]
        self.names = {}
        for i, (name, _t, _o, _s) in enumerate(self.sections):
            end = data.index(b"\x00", shstr_off + name)
            self.names[i] = data[shstr_off + name:end].decode()

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def read(self, va, size):
        off = self.va_to_offset(va)
        return self.data[off:off + size]

    def relocations(self):
        """Map relocation offset -> (type, addend) for RELA sections."""
        out = {}
        for i, (_name, sh_type, sh_offset, sh_size) in enumerate(
                self.sections):
            if sh_type != 4:  # SHT_RELA
                continue
            entsize = 24
            for j in range(sh_size // entsize):
                off = sh_offset + j * entsize
                (r_offset, r_info, r_addend) = struct.unpack_from(
                    "<QQq", self.data, off)
                out[r_offset] = (r_info & 0xFFFFFFFF, r_addend)
        return out


_EXCERPT_LINE = re.compile(
    r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+[0-9a-f]{2})")


def _scan_direct_calls(elf, target):
    """Byte-level scan of .text for e8 rel32 calls to ``target``.

    Returns the sorted list of call-site VAs. The sites are then
    cross-checked by the caller against the objdump excerpts where
    they fall inside a claimed function; the census itself is a
    byte scan because a full disassembly of .text takes minutes.
    """
    text_sec = None
    for i, (_name, _t, sh_offset, sh_size) in enumerate(elf.sections):
        if elf.names.get(i) == ".text":
            text_sec = (sh_offset, sh_size)
            break
    if text_sec is None:
        raise ValueError("no .text section")
    off, size = text_sec
    blob = elf.data[off:off + size]
    # .text VA: resolve via the LOAD segment containing the offset.
    base_va = None
    for vaddr, poff, filesz in elf.loads:
        if poff <= off < poff + filesz:
            base_va = vaddr + (off - poff)
            break
    if base_va is None:
        raise ValueError(".text not in any PT_LOAD segment")
    hits = []
    for j in range(len(blob) - 5):
        if blob[j] == 0xE8:
            (rel,) = struct.unpack_from("<i", blob, j + 1)
            site = base_va + j
            if site + 5 + rel == target:
                hits.append(site)
    return hits


def check_packet(packet_dir, binary_path):
    """Verify a packet directory against a node #94 binary.

    Checks the target digest, that every byte recorded in the
    packet's objdump excerpts matches the binary at the stated VA,
    the dispose/guard carve SHAs, the int3 padding, the GOT/vtable
    relocations, and the direct-call censuses. Returns a list of
    error strings (empty = pass).
    """
    errors = []
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return ["cannot read binary: %s" % e]
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        errors.append("target digest mismatch")
        return errors
    try:
        elf = _Elf(data)
    except ValueError as e:
        return [str(e)]
    import json
    try:
        with open(os.path.join(packet_dir, "records.json")) as f:
            records = json.load(f)
    except (OSError, ValueError) as e:
        return ["cannot read records.json: %s" % e]
    for key, start, end in (("dispose", DISPOSE_START, DISPOSE_END),
                            ("guard", GUARD_START, GUARD_END)):
        rec = records[key]
        actual = elf.read(start, end - start)
        if hashlib.sha256(actual).hexdigest() != rec["sha256"]:
            errors.append("%s carve SHA mismatch" % key)
    pad = elf.read(GUARD_END, GUARD_NEXT_FDE - GUARD_END)
    if pad != b"\xcc" * len(pad) or len(pad) != records["guard"]["padding_bytes"]:
        errors.append("guard padding mismatch")
    if elf.read(DISPOSE_START, DISPOSE_END - DISPOSE_START) is None:
        errors.append("dispose carve unreadable")
    relocs = elf.relocations()
    got = relocs.get(GOT_GUARD_SLOT)
    if got != (8, GUARD_START):
        errors.append("GOT guard relocation mismatch: %r" % (got,))
    for slot, want in records["vtable"]["slots"].items():
        entry = relocs.get(int(slot, 16))
        if entry is None or entry[1] != int(want, 16):
            errors.append("vtable slot %s mismatch: %r" % (slot, entry))
    for name in ("window.objdump.txt", "guard.objdump.txt"):
        path = os.path.join(packet_dir, name)
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError as e:
            errors.append("cannot read %s: %s" % (name, e))
            continue
        checked = 0
        for line in lines:
            m = _EXCERPT_LINE.match(line)
            if not m:
                continue
            va = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            try:
                actual = elf.read(va, len(raw))
            except ValueError as e:
                errors.append("%s: %s" % (name, e))
                continue
            if actual != raw:
                errors.append("%s: byte mismatch at %#x" % (name, va))
            checked += 1
        if checked == 0:
            errors.append("%s: no excerpt lines parsed" % name)
    for key, target in (("dispose_direct_callers", DISPOSE_START),
                        ("guard_direct_callers", GUARD_START)):
        want = [int(x, 16) for x in records["censuses"][key]]
        try:
            got_sites = _scan_direct_calls(elf, target)
        except ValueError as e:
            errors.append("census scan failed: %s" % e)
            continue
        if got_sites != want:
            errors.append("%s census mismatch: got %s want %s"
                          % (key, [hex(x) for x in got_sites], want))
    return errors
