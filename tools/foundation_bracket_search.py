#!/usr/bin/env python3
"""Checker for node #94's bracket-search twin windows 0x514b220 and
0x514b2b0 (RE-001).

The two windows are whole functions, not fragments: a signed-key
binary-tree walk that returns an exact-hit node or a bracketing
neighbour, with the _Rb_tree_decrement PLT stub as its callee for
the predecessor step and a genuine insert routine as the consumer
of the second window. The windows are byte-identical except for
the decrement call's rel32 displacement (both calls land on the
same PLT stub).

Stdlib only. Run from the repository root:

    python3 tools/foundation_bracket_search.py \\
        --check research/work-items/foundation-bracket-search-twin-94/evidence.json \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node (the materialized
checkout path); pass the digest-verified work copy on checkouts where
that path is still an LFS pointer. Every claim is re-derived from
target bytes: both window bodies, their FDE records, the decrement
calls, the consumer call site and its post-call branch, the full
direct-e8 caller census, and the composed bracket rule.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")

ENTRY_A_START = 0x514B220
ENTRY_B_START = 0x514B2B0
DECREMENT_TARGET = 0x56604B0
CONSUMER_CALL_SITE = 0x5150F6E

ENTRY_A_INSTR = [{'va': '0x514b220', 'bytes': '55', 'mnemonic': 'push', 'operands': '%rbp'}, {'va': '0x514b221', 'bytes': '89f5', 'mnemonic': 'mov', 'operands': '%esi,%ebp'}, {'va': '0x514b223', 'bytes': '53', 'mnemonic': 'push', 'operands': '%rbx'}, {'va': '0x514b224', 'bytes': '4883ec08', 'mnemonic': 'sub', 'operands': '$0x8,%rsp'}, {'va': '0x514b228', 'bytes': '488b5f10', 'mnemonic': 'mov', 'operands': '0x10(%rdi),%rbx'}, {'va': '0x514b22c', 'bytes': '4885db', 'mnemonic': 'test', 'operands': '%rbx,%rbx'}, {'va': '0x514b22f', 'bytes': '750a', 'mnemonic': 'jne', 'operands': '514b23b'}, {'va': '0x514b231', 'bytes': 'eb45', 'mnemonic': 'jmp', 'operands': '514b278'}, {'va': '0x514b233', 'bytes': '0f1f440000', 'mnemonic': 'nopl', 'operands': '0x0(%rax,%rax,1)'}, {'va': '0x514b238', 'bytes': '4889c3', 'mnemonic': 'mov', 'operands': '%rax,%rbx'}, {'va': '0x514b23b', 'bytes': '8b5320', 'mnemonic': 'mov', 'operands': '0x20(%rbx),%edx'}, {'va': '0x514b23e', 'bytes': '488b4318', 'mnemonic': 'mov', 'operands': '0x18(%rbx),%rax'}, {'va': '0x514b242', 'bytes': '39ea', 'mnemonic': 'cmp', 'operands': '%ebp,%edx'}, {'va': '0x514b244', 'bytes': '480f4f4310', 'mnemonic': 'cmovg', 'operands': '0x10(%rbx),%rax'}, {'va': '0x514b249', 'bytes': '0f9fc1', 'mnemonic': 'setg', 'operands': '%cl'}, {'va': '0x514b24c', 'bytes': '4885c0', 'mnemonic': 'test', 'operands': '%rax,%rax'}, {'va': '0x514b24f', 'bytes': '75e7', 'mnemonic': 'jne', 'operands': '514b238'}, {'va': '0x514b251', 'bytes': '4889de', 'mnemonic': 'mov', 'operands': '%rbx,%rsi'}, {'va': '0x514b254', 'bytes': '84c9', 'mnemonic': 'test', 'operands': '%cl,%cl'}, {'va': '0x514b256', 'bytes': '7524', 'mnemonic': 'jne', 'operands': '514b27c'}, {'va': '0x514b258', 'bytes': '31c0', 'mnemonic': 'xor', 'operands': '%eax,%eax'}, {'va': '0x514b25a', 'bytes': '39ea', 'mnemonic': 'cmp', 'operands': '%ebp,%edx'}, {'va': '0x514b25c', 'bytes': '480f4df0', 'mnemonic': 'cmovge', 'operands': '%rax,%rsi'}, {'va': '0x514b260', 'bytes': '480f4cd8', 'mnemonic': 'cmovl', 'operands': '%rax,%rbx'}, {'va': '0x514b264', 'bytes': '4883c408', 'mnemonic': 'add', 'operands': '$0x8,%rsp'}, {'va': '0x514b268', 'bytes': '4889d8', 'mnemonic': 'mov', 'operands': '%rbx,%rax'}, {'va': '0x514b26b', 'bytes': '4889f2', 'mnemonic': 'mov', 'operands': '%rsi,%rdx'}, {'va': '0x514b26e', 'bytes': '5b', 'mnemonic': 'pop', 'operands': '%rbx'}, {'va': '0x514b26f', 'bytes': '5d', 'mnemonic': 'pop', 'operands': '%rbp'}, {'va': '0x514b270', 'bytes': 'c3', 'mnemonic': 'ret', 'operands': ''}, {'va': '0x514b271', 'bytes': '0f1f8000000000', 'mnemonic': 'nopl', 'operands': '0x0(%rax)'}, {'va': '0x514b278', 'bytes': '488d5f08', 'mnemonic': 'lea', 'operands': '0x8(%rdi),%rbx'}, {'va': '0x514b27c', 'bytes': '48395f18', 'mnemonic': 'cmp', 'operands': '%rbx,0x18(%rdi)'}, {'va': '0x514b280', 'bytes': '7416', 'mnemonic': 'je', 'operands': '514b298'}, {'va': '0x514b282', 'bytes': '4889df', 'mnemonic': 'mov', 'operands': '%rbx,%rdi'}, {'va': '0x514b285', 'bytes': 'e826525100', 'mnemonic': 'call', 'operands': '56604b0'}, {'va': '0x514b28a', 'bytes': '4889de', 'mnemonic': 'mov', 'operands': '%rbx,%rsi'}, {'va': '0x514b28d', 'bytes': '8b5020', 'mnemonic': 'mov', 'operands': '0x20(%rax),%edx'}, {'va': '0x514b290', 'bytes': '4889c3', 'mnemonic': 'mov', 'operands': '%rax,%rbx'}, {'va': '0x514b293', 'bytes': 'ebc3', 'mnemonic': 'jmp', 'operands': '514b258'}, {'va': '0x514b295', 'bytes': '0f1f00', 'mnemonic': 'nopl', 'operands': '(%rax)'}, {'va': '0x514b298', 'bytes': '4889de', 'mnemonic': 'mov', 'operands': '%rbx,%rsi'}, {'va': '0x514b29b', 'bytes': '4883c408', 'mnemonic': 'add', 'operands': '$0x8,%rsp'}, {'va': '0x514b29f', 'bytes': '31db', 'mnemonic': 'xor', 'operands': '%ebx,%ebx'}, {'va': '0x514b2a1', 'bytes': '4889d8', 'mnemonic': 'mov', 'operands': '%rbx,%rax'}, {'va': '0x514b2a4', 'bytes': '4889f2', 'mnemonic': 'mov', 'operands': '%rsi,%rdx'}, {'va': '0x514b2a7', 'bytes': '5b', 'mnemonic': 'pop', 'operands': '%rbx'}, {'va': '0x514b2a8', 'bytes': '5d', 'mnemonic': 'pop', 'operands': '%rbp'}, {'va': '0x514b2a9', 'bytes': 'c3', 'mnemonic': 'ret', 'operands': ''}]
ENTRY_B_INSTR = [{'va': '0x514b2b0', 'bytes': '55', 'mnemonic': 'push', 'operands': '%rbp'}, {'va': '0x514b2b1', 'bytes': '89f5', 'mnemonic': 'mov', 'operands': '%esi,%ebp'}, {'va': '0x514b2b3', 'bytes': '53', 'mnemonic': 'push', 'operands': '%rbx'}, {'va': '0x514b2b4', 'bytes': '4883ec08', 'mnemonic': 'sub', 'operands': '$0x8,%rsp'}, {'va': '0x514b2b8', 'bytes': '488b5f10', 'mnemonic': 'mov', 'operands': '0x10(%rdi),%rbx'}, {'va': '0x514b2bc', 'bytes': '4885db', 'mnemonic': 'test', 'operands': '%rbx,%rbx'}, {'va': '0x514b2bf', 'bytes': '750a', 'mnemonic': 'jne', 'operands': '514b2cb'}, {'va': '0x514b2c1', 'bytes': 'eb45', 'mnemonic': 'jmp', 'operands': '514b308'}, {'va': '0x514b2c3', 'bytes': '0f1f440000', 'mnemonic': 'nopl', 'operands': '0x0(%rax,%rax,1)'}, {'va': '0x514b2c8', 'bytes': '4889c3', 'mnemonic': 'mov', 'operands': '%rax,%rbx'}, {'va': '0x514b2cb', 'bytes': '8b5320', 'mnemonic': 'mov', 'operands': '0x20(%rbx),%edx'}, {'va': '0x514b2ce', 'bytes': '488b4318', 'mnemonic': 'mov', 'operands': '0x18(%rbx),%rax'}, {'va': '0x514b2d2', 'bytes': '39ea', 'mnemonic': 'cmp', 'operands': '%ebp,%edx'}, {'va': '0x514b2d4', 'bytes': '480f4f4310', 'mnemonic': 'cmovg', 'operands': '0x10(%rbx),%rax'}, {'va': '0x514b2d9', 'bytes': '0f9fc1', 'mnemonic': 'setg', 'operands': '%cl'}, {'va': '0x514b2dc', 'bytes': '4885c0', 'mnemonic': 'test', 'operands': '%rax,%rax'}, {'va': '0x514b2df', 'bytes': '75e7', 'mnemonic': 'jne', 'operands': '514b2c8'}, {'va': '0x514b2e1', 'bytes': '4889de', 'mnemonic': 'mov', 'operands': '%rbx,%rsi'}, {'va': '0x514b2e4', 'bytes': '84c9', 'mnemonic': 'test', 'operands': '%cl,%cl'}, {'va': '0x514b2e6', 'bytes': '7524', 'mnemonic': 'jne', 'operands': '514b30c'}, {'va': '0x514b2e8', 'bytes': '31c0', 'mnemonic': 'xor', 'operands': '%eax,%eax'}, {'va': '0x514b2ea', 'bytes': '39ea', 'mnemonic': 'cmp', 'operands': '%ebp,%edx'}, {'va': '0x514b2ec', 'bytes': '480f4df0', 'mnemonic': 'cmovge', 'operands': '%rax,%rsi'}, {'va': '0x514b2f0', 'bytes': '480f4cd8', 'mnemonic': 'cmovl', 'operands': '%rax,%rbx'}, {'va': '0x514b2f4', 'bytes': '4883c408', 'mnemonic': 'add', 'operands': '$0x8,%rsp'}, {'va': '0x514b2f8', 'bytes': '4889d8', 'mnemonic': 'mov', 'operands': '%rbx,%rax'}, {'va': '0x514b2fb', 'bytes': '4889f2', 'mnemonic': 'mov', 'operands': '%rsi,%rdx'}, {'va': '0x514b2fe', 'bytes': '5b', 'mnemonic': 'pop', 'operands': '%rbx'}, {'va': '0x514b2ff', 'bytes': '5d', 'mnemonic': 'pop', 'operands': '%rbp'}, {'va': '0x514b300', 'bytes': 'c3', 'mnemonic': 'ret', 'operands': ''}, {'va': '0x514b301', 'bytes': '0f1f8000000000', 'mnemonic': 'nopl', 'operands': '0x0(%rax)'}, {'va': '0x514b308', 'bytes': '488d5f08', 'mnemonic': 'lea', 'operands': '0x8(%rdi),%rbx'}, {'va': '0x514b30c', 'bytes': '48395f18', 'mnemonic': 'cmp', 'operands': '%rbx,0x18(%rdi)'}, {'va': '0x514b310', 'bytes': '7416', 'mnemonic': 'je', 'operands': '514b328'}, {'va': '0x514b312', 'bytes': '4889df', 'mnemonic': 'mov', 'operands': '%rbx,%rdi'}, {'va': '0x514b315', 'bytes': 'e896515100', 'mnemonic': 'call', 'operands': '56604b0'}, {'va': '0x514b31a', 'bytes': '4889de', 'mnemonic': 'mov', 'operands': '%rbx,%rsi'}, {'va': '0x514b31d', 'bytes': '8b5020', 'mnemonic': 'mov', 'operands': '0x20(%rax),%edx'}, {'va': '0x514b320', 'bytes': '4889c3', 'mnemonic': 'mov', 'operands': '%rax,%rbx'}, {'va': '0x514b323', 'bytes': 'ebc3', 'mnemonic': 'jmp', 'operands': '514b2e8'}, {'va': '0x514b325', 'bytes': '0f1f00', 'mnemonic': 'nopl', 'operands': '(%rax)'}, {'va': '0x514b328', 'bytes': '4889de', 'mnemonic': 'mov', 'operands': '%rbx,%rsi'}, {'va': '0x514b32b', 'bytes': '4883c408', 'mnemonic': 'add', 'operands': '$0x8,%rsp'}, {'va': '0x514b32f', 'bytes': '31db', 'mnemonic': 'xor', 'operands': '%ebx,%ebx'}, {'va': '0x514b331', 'bytes': '4889d8', 'mnemonic': 'mov', 'operands': '%rbx,%rax'}, {'va': '0x514b334', 'bytes': '4889f2', 'mnemonic': 'mov', 'operands': '%rsi,%rdx'}, {'va': '0x514b337', 'bytes': '5b', 'mnemonic': 'pop', 'operands': '%rbx'}, {'va': '0x514b338', 'bytes': '5d', 'mnemonic': 'pop', 'operands': '%rbp'}, {'va': '0x514b339', 'bytes': 'c3', 'mnemonic': 'ret', 'operands': ''}]

EXPECTED_CALLERS_A = []
EXPECTED_CALLERS_B = [0x5150F6E]

_HEADER = "header"


def u64(text):
    return int(text, 16)


def _inorder(container):
    """Node ids of a valid BST in ascending key order."""
    nodes = container["nodes"]
    order = []

    def walk(node):
        if node is None:
            return
        walk(nodes[node]["left"])
        order.append(node)
        walk(nodes[node]["right"])

    walk(container["root"])
    return order


def _predecessor(container, node):
    """In-order predecessor, matching _Rb_tree_decrement on a valid BST.

    The decrement of the leftmost node (or of the header on an empty
    tree) is the header sentinel, which is exactly when the window
    skips the call; this helper is only reached for nodes that have
    a predecessor, plus the header on a non-empty tree, whose
    predecessor is the maximum node.
    """
    order = _inorder(container)
    if node == container["header"]:
        return order[-1] if order else container["header"]
    if node not in order:
        return container["header"]
    idx = order.index(node)
    return order[idx - 1] if idx > 0 else container["header"]


def bracket_search(container, sought):
    """Faithful model of the 0x514b220 / 0x514b2b0 windows.

    ``container`` is {"root": node id or None, "leftmost": node id
    or the header sentinel, "header": sentinel id, "nodes": {id:
    {"left", "right", "key"}}}. Node ids stand in for node
    addresses; None stands for the zero address. The return is a
    pair (first, second):

    - (exact node, None) when ``sought`` is present in the tree;
    - (None, neighbour) otherwise, where the neighbour is the
      predecessor when the walk ends going right, or the successor
      when it ends going left (and the smallest node when
      ``sought`` is below every key);
    - (None, header) on an empty tree.

    All comparisons are signed 32-bit, matching cmp/setg/cmovg/
    cmovge/cmovl on the int32 key at node+0x20.
    """
    nodes = container["nodes"]
    header = container["header"]
    node = container["root"]
    if node is None:
        # Empty path: rbx = container+0x8 (the header), then the
        # decrement check below.
        return _decrement_check(container, header, sought, header)
    while True:
        key = nodes[node]["key"]
        nxt = nodes[node]["left"] if key > sought else nodes[node]["right"]
        went_left = key > sought
        if nxt is not None:
            node = nxt
            continue
        # Leaf: rsi = node, cl = (key > sought).
        if went_left:
            return _decrement_check(container, node, sought, node)
        # Tail at 0x514b258: edx still holds this node's key.
        if key >= sought:
            return (node, None)
        return (None, node)


def _decrement_check(container, node, sought, old_node):
    """The shared tail at 0x514b27c: skip or take the decrement."""
    if container["leftmost"] == node:
        return (None, node)
    pred = _predecessor(container, node)
    # Tail at 0x514b258 with edx = key[pred], rbx = pred,
    # rsi = old_node.
    if container["nodes"][pred]["key"] >= sought:
        return (pred, None)
    return (None, old_node)


def elf_sections(binary):
    """Return {name: (sh_addr, sh_offset, sh_size)} for ELF64 sections."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if binary[4] != 2 or binary[5] != 1:
        raise ValueError("expected ELF64 little-endian")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    headers = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, _type, _flags, addr, offset, size) = struct.unpack_from(
            "<IIQQQQ", binary, off)
        headers.append((name, addr, offset, size))
    str_off = headers[e_shstrndx][2]
    out = {}
    for (name_off, addr, offset, size) in headers:
        end = binary.index(b"\x00", str_off + name_off)
        name = binary[str_off + name_off:end].decode()
        out[name] = (addr, offset, size)
    return out


def read_va(binary, sections, va, count):
    addr, offset, size = sections[".text"]
    if not (addr <= va and va + count <= addr + size):
        raise ValueError("VA %#x outside .text" % va)
    start = offset + (va - addr)
    return binary[start:start + count]


def scan_callers(binary, sections, target):
    addr, offset, size = sections[".text"]
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


def _check_window(ev, binary, sections, key, instr_table, expected_start):
    fn = ev[key]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    if start != expected_start:
        return "%s start mismatch" % key
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        return "%s length mismatch: %d != %d" % (key, len(body), fn["bytes"])
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        return "%s body SHA-256 mismatch" % key
    for va, hexbytes in instr_table.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "%s instruction bytes mismatch at %#x" % (key, va)
    pos = start
    for instr in fn["instructions"]:
        va = u64(instr["va"])
        if va != pos:
            return "%s instructions do not tile the body at %#x" % (key, va)
        want = bytes.fromhex(instr["bytes"])
        got = read_va(binary, sections, va, len(want))
        if got != want:
            return "%s evidence instruction bytes mismatch at %#x" % (key, va)
        pos += len(want)
    if pos != end:
        return "%s instructions do not end at the FDE end" % key
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        return "%s padding length mismatch" % key
    if pad != b"\xcc" * len(pad):
        return "%s padding bytes are not int3" % key
    return None


def check_window_a(ev, binary, sections, packet_dir):
    table = {u64(i["va"]): i["bytes"] for i in ENTRY_A_INSTR}
    return _check_window(ev, binary, sections, "entry", table, ENTRY_A_START)


def check_window_b(ev, binary, sections, packet_dir):
    table = {u64(i["va"]): i["bytes"] for i in ENTRY_B_INSTR}
    return _check_window(ev, binary, sections, "twin", table, ENTRY_B_START)


def check_twin_relation(ev, binary, sections, packet_dir):
    a = read_va(binary, sections, ENTRY_A_START, 138)
    b = read_va(binary, sections, ENTRY_B_START, 138)
    diffs = [i for i in range(138) if a[i] != b[i]]
    if diffs != [0x66, 0x67]:
        return "twin bodies differ outside the decrement call rel32: %s" % diffs
    rec = ev["decrement"]
    for site_key, body_off in (("site_a", 0x65), ("site_b", 0x65)):
        site = u64(rec[site_key])
        want = bytes.fromhex(rec["bytes_a" if site_key == "site_a" else "bytes_b"])
        got = read_va(binary, sections, site, 5)
        if got != want:
            return "decrement call bytes mismatch at %#x" % site
        (rel,) = struct.unpack_from("<i", got, 1)
        if site + 5 + rel != u64(rec["target"]):
            return "decrement call target mismatch at %#x" % site
        if site + 5 + rel != DECREMENT_TARGET:
            return "decrement call target is not the PLT stub"
    if rec["target"] != "0x56604b0":
        return "decrement target mismatch"
    if rec["symbol"] != "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base@plt":
        return "decrement symbol mismatch"
    return None


def check_frames(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        frames = fh.read()
    for needle in ("pc=000000000514b220..000000000514b2aa",
                   "pc=000000000514b2b0..000000000514b33a",
                   "pc=0000000005150e50..0000000005151000",
                   "0x0029a4a4", "0x0029a4d8", "0x0029ade0"):
        if needle not in frames:
            return "FDE record missing from frames.txt: %s" % needle
    return None


def check_consumer(ev, binary, sections, packet_dir):
    rec = ev["consumer"]
    site = u64(rec["call_site"])
    want = bytes.fromhex(rec["call_bytes"])
    got = read_va(binary, sections, site, 5)
    if got != want:
        return "consumer call bytes mismatch at %#x" % site
    (rel,) = struct.unpack_from("<i", got, 1)
    if site + 5 + rel != u64(rec["target"]):
        return "consumer call target mismatch"
    if u64(rec["target"]) != ENTRY_B_START:
        return "consumer call target is not the twin window"
    if rec["insert_symbol"] != "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_@plt":
        return "insert symbol mismatch"
    if rec["free_symbol"] != "_ZdlPvm@plt":
        return "free symbol mismatch"
    if rec["new_symbol"] != "_Znwm@plt":
        return "new symbol mismatch"
    return None


def check_callers(ev, binary, sections, packet_dir):
    found_a = scan_callers(binary, sections, ENTRY_A_START)
    if found_a != EXPECTED_CALLERS_A:
        return "entry A direct e8 caller scan mismatch: %s" % (
            [hex(x) for x in found_a])
    found_b = scan_callers(binary, sections, ENTRY_B_START)
    if found_b != EXPECTED_CALLERS_B:
        return "twin direct e8 caller scan mismatch: %s" % (
            [hex(x) for x in found_b])
    listed_a = [u64(x) for x in ev["incoming"]["entry_a_direct_e8_callers"]]
    listed_b = [u64(x) for x in ev["incoming"]["twin_direct_e8_callers"]]
    if listed_a != EXPECTED_CALLERS_A or listed_b != EXPECTED_CALLERS_B:
        return "evidence caller list mismatch"
    return None


def check_excerpts(ev, binary, sections, packet_dir):
    with open(os.path.join(packet_dir, "window.objdump.txt")) as fh:
        window = fh.read()
    with open(os.path.join(packet_dir, "caller.objdump.txt")) as fh:
        caller = fh.read()
    for needle, name in (
            ("514b220:", "entry A excerpt start"),
            ("514b2b0:", "twin excerpt start"),
            ("514b285:", "decrement call site A"),
            ("514b315:", "decrement call site B"),
            ("_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base@plt",
             "decrement PLT label")):
        if needle not in window:
            return "%s missing from window excerpt" % name
    for needle, name in (
            ("5150f6e:", "consumer call site"),
            ("_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_@plt",
             "insert PLT label"),
            ("_ZdlPvm@plt", "free PLT label"),
            ("_Znwm@plt", "new PLT label")):
        if needle not in caller:
            return "%s missing from caller excerpt" % name
    for instr in ev["entry"]["instructions"] + ev["twin"]["instructions"]:
        if instr["mnemonic"] not in window:
            return "mnemonic %s missing from window excerpt" % instr["mnemonic"]
    return None


def check_edges(ev, binary, sections, packet_dir):
    for edge in ev["rule"]["edges"]:
        container = {"root": edge["root"],
                     "leftmost": edge["leftmost"],
                     "header": edge["header"],
                     "nodes": {k: {"left": v["left"], "right": v["right"],
                                   "key": v["key"]}
                               for k, v in edge["nodes"].items()}}
        got = bracket_search(container, edge["sought"])
        if list(got) != edge["outcome"]:
            return "rule edge mismatch: %s (got %s)" % (edge, got)
    return None


CHECKS = (
    ("target digest", check_target_digest),
    ("entry window", check_window_a),
    ("twin window", check_window_b),
    ("twin relation", check_twin_relation),
    ("frames", check_frames),
    ("consumer", check_consumer),
    ("callers", check_callers),
    ("excerpts", check_excerpts),
    ("rule edges", check_edges),
)


def run_evidence(ev, binary, sections, packet_dir):
    """Run every check against an already-loaded evidence dict.

    Returns a list of failure strings (empty on success). Corruption
    controls in the unit tests call this directly with mutated dicts.
    """
    failures = []
    for name, fn in CHECKS:
        try:
            err = fn(ev, binary, sections, packet_dir)
        except Exception as exc:  # corrupted input must fail, not crash
            err = "%s (%s)" % (name, exc)
        if err:
            failures.append("%s: %s" % (name, err))
    return failures


def run_all(evidence_path, binary_path):
    """Return a list of failure strings (empty on success)."""
    with open(evidence_path) as fh:
        ev = json.load(fh)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    with open(binary_path, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    return run_evidence(ev, binary, sections, packet_dir)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", required=True)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    failures = run_all(args.check, args.binary)
    if failures:
        for failure in failures:
            print("FAIL: %s" % failure, file=sys.stderr)
        return 1
    print("Bracket-search evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
