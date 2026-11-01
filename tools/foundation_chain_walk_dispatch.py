#!/usr/bin/env python3
"""RE-001: chain-walk dispatch at node #94 function 0x514ba10.

The target function takes a chain head object and a key string
(pointer at +0x0, length at +0x8) and returns a word:

    node = next(head)             # vtable slot +0x88 of the head
    while node is not None:
        handler = node vtable slot +0x38
        if handler != DEFAULT:    # DEFAULT = 0x4f8da10, the value of
                                  # GOT slot 0x5777b10 at runtime
            return handler(node, key)      # tail call, same arguments
        hit = table_lookup(node, key)      # 0x52f5290
        if hit != 0:
            return hit
        node = next(node)
    return 0

``table_lookup`` scans the 48-byte records from [node+0x8] to
[node+0x10]. A record matches when its key string equals the argument
string by length then bytes; an empty key matches an empty record key
(the byte compare is skipped at length zero). On a match it returns
the record's +0x20 first qword; when no record matches it returns 0.
An empty range returns 0 immediately. The record's trailing 16-byte
field is not typed here: only its first qword is ever returned, so
the model stores it as an opaque integer result.

The default handler (0x4f8da10) is the one-step form of the same
dispatch: it tries the helper on its node, and on a miss steps exactly
one node and tail-calls that node's handler slot (or returns 0 when
the next node is null). The walker is the looping form; the two agree
on every chain (see the tests).

The walker's first three iterations are unrolled in the bytes, with
the second and third slot compares made against the previous node's
slot; each is reachable only when the previous slot equalled the
sentinel, so they are equivalent to sentinel compares, and after the
third helper miss the code jumps back to the loop head with the
current node. The model therefore loops without an iteration cap.

Stdlib only. ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import os
import re
import struct

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
WALKER_START = 0x514BA10
WALKER_END = 0x514BB05
HELPER_START = 0x52F5290
HELPER_END = 0x52F5427
SENTINEL_START = 0x4F8DA10
SENTINEL_END = 0x4F8DA5E

DEFAULT = "default"  # sentinel marker: handler == 0x4f8da10


class Record:
    """One 48-byte table record: a key string and an opaque result word."""

    __slots__ = ("key", "result")

    def __init__(self, key, result):
        self.key = bytes(key)
        self.result = result


class Node:
    """One chain node.

    ``handler`` is DEFAULT for a default-handler node, or a callable
    ``(node, key_bytes) -> int`` for a node with its own handler.
    ``table`` is the node's record list (the [node+0x8, node+0x10)
    range). ``next_node`` is the node the +0x88 virtual returns, or
    None at the end of the chain.
    """

    __slots__ = ("handler", "table", "next_node")

    def __init__(self, handler=DEFAULT, table=None, next_node=None):
        self.handler = handler
        self.table = list(table) if table is not None else []
        self.next_node = next_node


def table_lookup(node, key):
    """The 0x52f5290 helper: first matching record's result, else 0."""
    key = bytes(key)
    for record in node.table:
        if len(record.key) != len(key):
            continue
        if len(key) == 0 or record.key == key:
            return record.result
    return 0


def dispatch_from(node, key):
    """Dispatch starting at ``node`` (its handler slot is examined)."""
    current = node
    while current is not None:
        if current.handler != DEFAULT:
            return current.handler(current, key)
        hit = table_lookup(current, key)
        if hit != 0:
            return hit
        current = current.next_node
    return 0


def default_handler(node, key):
    """The 0x4f8da10 one-step form: helper, then one step and delegate."""
    hit = table_lookup(node, key)
    if hit != 0:
        return hit
    nxt = node.next_node
    if nxt is None:
        return 0
    return dispatch_from(nxt, key)


def walk(head, key):
    """The 0x514ba10 walker: step once from the head, then dispatch."""
    if head is None or head.next_node is None:
        return 0
    return dispatch_from(head.next_node, key)


class _Elf:
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


_EXCERPT_LINE = re.compile(
    r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+[0-9a-f]{2})")


def check_packet(packet_dir, binary_path):
    """Verify a packet directory against a node #94 binary.

    Checks the target digest and that every byte recorded in the
    packet's objdump excerpts matches the binary at the stated VA.
    Returns a list of error strings (empty = pass).
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
    for name in ("window.objdump.txt", "helper.objdump.txt",
                 "sentinel.objdump.txt", "caller.objdump.txt",
                 "plt.objdump.txt"):
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
                errors.append(
                    "%s: byte mismatch at %#x" % (name, va))
            checked += 1
        if checked == 0:
            errors.append("%s: no excerpt lines parsed" % name)
    return errors
