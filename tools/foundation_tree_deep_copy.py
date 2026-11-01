#!/usr/bin/env python3
"""RE-001: deep copy of a node #94 binary tree (function 0x514b7e0).

The target function copies a tree of 0x30-byte nodes.  Node layout, read
directly from the field accesses in the function body:

    +0x00  int32 value (copied verbatim; its first dword)
    +0x08  parent pointer (the caller passes the destination header as the
           parent of the new root; recursive calls pass the new node)
    +0x10  left child (copied iteratively, as a spine loop)
    +0x18  right child (copied by direct recursion)
    +0x20  16-byte payload (copied verbatim with a 16-byte vector move)

The third argument is a two-qword pool pair ``C``:

    [C+0x0]  old-root handle: cleared to 0 exactly when the pool is
             exhausted (the pop that takes the last node)
    [C+0x8]  pool head: the next recyclable node, or 0

When the head is 0 the function allocates a fresh 0x30-byte node with
operator new (PLT 0x5660490); otherwise it pops a node from the pool.
The pop is a destructive traversal of the old tree, transliterated
instruction by instruction in :meth:`Pool.pop` (see the packet README
for the branch-by-branch mapping).  The copy returns the new root.

Exception path (landing-pad stub 0x514ba00 -> shared cleanup
0x514b7b4): when a call inside the function throws, the cleanup calls
the recursive destructor (0x514b690, bound by an earlier work item) on
the node currently being built and rethrows.  The model mirrors this:
a failing frame destroys its own in-progress node and re-raises.

Stdlib only.  ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import json
import os
import struct
import sys

NODE_SIZE = 0x30
PAYLOAD_BYTES = 16

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FUNC_START = 0x514B7E0
FUNC_END = 0x514BA0C


class Node:
    """One 0x30-byte tree node."""

    __slots__ = ("value", "parent", "left", "right", "payload",
                 "destroyed", "tag")

    def __init__(self, value=0, payload=b"\x00" * PAYLOAD_BYTES, tag=None):
        self.value = value
        self.parent = None
        self.left = None
        self.right = None
        self.payload = bytes(payload)
        self.destroyed = False
        self.tag = tag

    def __repr__(self):  # pragma: no cover - debugging aid
        return "Node(%r, payload=%r, tag=%r)" % (
            self.value, self.payload, self.tag)


def destroy(node):
    """Recursive-destructor model: mark a node and its built children."""
    if node is None or node.destroyed:
        return
    node.destroyed = True
    destroy(node.left)
    destroy(node.right)


class CopyAborted(Exception):
    """Raised when the allocator (or a nested copy) fails mid-copy."""


class Pool:
    """The two-qword pool pair ``C``: (old-root handle, head)."""

    def __init__(self, root=None, head=None):
        self.root = root
        self.head = head

    def pop(self):
        """Take the next recyclable node, or None when the pool is empty.

        Transliteration of 0x514b7e0's pop (entry path; the spine loop
        uses the identical sequence):

        - head = [C+0x8]; if head is 0, the caller allocates instead.
        - next = [head+0x8] (the parent link); [C+0x8] = next.
        - if next is 0: [C+0x0] = 0 (pool exhausted); return head.
        - if [next+0x18] == head (head was a right child): detach
          [next+0x18] = 0, then redirect the head into next's left
          subtree: its rightmost descendant, or that descendant's
          left child when one exists; when there is no left subtree
          the head stays at next.  Return head.
        - otherwise: [next+0x10] = 0 (detach next's left); return head.
        """
        head = self.head
        if head is None:
            return None
        nxt = head.parent
        self.head = nxt
        if nxt is None:
            self.root = None
            return head
        if nxt.right is head:
            left = nxt.left
            nxt.right = None
            if left is not None:
                cur = left
                self.head = cur
                nxt_right = cur.right
                while nxt_right is not None:
                    cur = nxt_right
                    nxt_right = nxt_right.right
                self.head = cur
                left_child = cur.left
                if left_child is not None:
                    self.head = left_child
            return head
        nxt.left = None
        return head


def _copy_node(source, parent, pool, alloc):
    """One frame of the copy: build the copy of ``source``."""
    node = pool.pop()
    if node is None:
        node = alloc()
        node.payload = source.payload
    else:
        node.payload = source.payload
    node.value = source.value
    node.left = None
    node.right = None
    node.parent = parent
    try:
        if source.right is not None:
            node.right = deep_copy(source.right, node, pool, alloc)
        prev = node
        cur_src = source.left
        while cur_src is not None:
            nxt = pool.pop()
            if nxt is None:
                nxt = alloc()
                nxt.payload = cur_src.payload
            else:
                nxt.payload = cur_src.payload
            nxt.value = cur_src.value
            nxt.left = None
            nxt.right = None
            prev.left = nxt
            nxt.parent = prev
            if cur_src.right is not None:
                nxt.right = deep_copy(cur_src.right, nxt, pool, alloc)
            cur_src = cur_src.left
            prev = nxt
    except Exception:
        # Landing-pad behaviour: destroy this frame's in-progress node
        # (via the recursive destructor) and rethrow.
        destroy(node)
        raise
    return node


def deep_copy(source, parent, pool, alloc):
    """Deep-copy the tree rooted at ``source``; return the new root.

    ``source`` must be non-null: the only direct caller guards the call
    with a null check, and the function itself dereferences the source
    unconditionally.  ``alloc`` is a zero-argument callable returning a
    fresh node (operator new, 0x30 bytes); it may raise to model an
    allocation failure.
    """
    if source is None:
        raise ValueError("deep_copy: source must be non-null")
    return _copy_node(source, parent, pool, alloc)


# ---------------------------------------------------------------------------
# Packet checker (used by tests/test_foundation_tree_deep_copy.py)
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


def _rel_target(binary, site, length):
    """Target of a rel8/rel32 branch or call at ``site`` (raw bytes)."""
    raw = binary.read(site, length)
    if length == 2:
        (disp,) = struct.unpack_from("<b", raw, 1)
    elif length == 5:
        (disp,) = struct.unpack_from("<i", raw, 1)
    elif length == 6:
        (disp,) = struct.unpack_from("<i", raw, 2)
    else:
        raise ValueError("unsupported branch length %d" % length)
    return site + length + disp


def check_packet(packet_dir, binary_path):
    """Verify the packet's semantic records against a binary.

    Returns a list of error strings; empty means ALL CHECKS PASSED.
    The caller census is verified by the packet's own verify.py (which
    runs a full disassembly scan); this checker verifies the recorded
    call sites' encodings and every other record directly.
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
    for name in ("cleanup", "caller"):
        part = rec[name]
        s = int(part["start_va"], 16)
        e = int(part["end_va_exclusive"], 16)
        blob = elf.read(s, e - s)
        if hashlib.sha256(blob).hexdigest() != part["sha256"]:
            errors.append("%s SHA mismatch" % name)
        ppad = elf.read(e, part["padding_bytes"])
        if ppad != b"\xcc" * part["padding_bytes"]:
            errors.append("%s padding is not int3" % name)
    for branch in rec["branches"]:
        site = int(branch["site"], 16)
        want = int(branch["target"], 16)
        try:
            got = _rel_target(elf, site, branch["length"])
        except ValueError as exc:
            errors.append("branch %s: %s" % (branch["site"], exc))
            continue
        if got != want:
            errors.append("branch %s: target %#x != %#x" % (
                branch["site"], got, want))
    for call in rec["calls"]:
        site = int(call["site"], 16)
        want = int(call["target"], 16)
        got = _rel_target(elf, site, 5)
        if got != want:
            errors.append("call %s: target %#x != %#x" % (
                call["site"], got, want))
    for stub in rec["plt"]:
        sva = int(stub["stub_va"], 16)
        want = int(stub["got_va"], 16)
        raw = elf.read(sva, 6)
        if raw[0] != 0xFF or raw[1] != 0x25:
            errors.append("PLT stub %s: not an indirect jmp" % stub["stub_va"])
            continue
        (disp,) = struct.unpack_from("<i", raw, 2)
        got = sva + 6 + disp
        if got != want:
            errors.append("PLT stub %s: GOT %#x != %#x" % (
                stub["stub_va"], got, want))
    frames_path = os.path.join(packet_dir, "frames.txt")
    try:
        with open(frames_path) as f:
            frames = f.read()
    except OSError as exc:
        errors.append("cannot read frames.txt: %s" % exc)
        frames = ""
    for key in ("function", "cleanup", "caller"):
        part = rec[key]
        # FDE lines print zero-padded 16-digit addresses without 0x.
        want = "pc=%016x..%016x" % (
            int(part["start_va"], 16), int(part["end_va_exclusive"], 16))
        if want not in frames:
            errors.append("%s FDE line missing from frames.txt" % key)
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
