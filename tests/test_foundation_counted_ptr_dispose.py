#!/usr/bin/env python3
"""Tests for node #94 counted-pointer dispose at 0x514bb10 (RE-001).

Covers the model in tools/foundation_counted_ptr_dispose.py, the
packet verifier, and the independent tools checker, including
corruption controls that must make the checkers fail.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    REPO_ROOT, "research", "work-items", "RE-001-counted-ptr-dispose-94")
BINARY = os.path.join(REPO_ROOT, "artifacts", "node", "94", "hl-node")

sys.path.insert(0, REPO_ROOT)

from tools.foundation_counted_ptr_dispose import (  # noqa: E402
    GUARD, Node, check_packet, dispose, dispose_full, guard_continue)


def load_packet_verify():
    spec = importlib.util.spec_from_file_location(
        "dispose_verify", os.path.join(PACKET_DIR, "verify.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def chain(disposes):
    """Build a +0x38 chain from a list of dispose markers."""
    head = None
    for marker in reversed(disposes):
        head = Node(dispose=marker, next_node=head)
    return head


class ModelTests(unittest.TestCase):
    def test_zero_value_returns_without_reading_head(self):
        # None head is only accepted on the zero path, mirroring
        # the bytes, which return before reading [object+0x10].
        self.assertEqual(dispose(0, None), ("return", None))

    def test_nonzero_value_with_no_head_is_an_error(self):
        with self.assertRaises(ValueError):
            dispose(7, None)

    def test_first_node_custom_is_a_call(self):
        head = chain(["custom"])
        kind, node, value, flag = dispose(7, head)
        self.assertEqual((kind, value, flag), ("call", 7, 0))
        self.assertIs(node, head)

    def test_first_node_guard_second_custom_is_a_tail_call(self):
        head = chain([GUARD, "custom"])
        kind, node, value, flag = dispose(7, head)
        self.assertEqual((kind, value, flag), ("tail", 7, 0))
        self.assertIs(node, head.next_node)

    def test_fifth_node_is_tail_called_unconditionally(self):
        head = chain([GUARD, GUARD, GUARD, GUARD, GUARD])
        kind, node, value, flag = dispose(7, head)
        self.assertEqual((kind, value, flag), ("tail", 7, 0))
        fifth = head.next_node.next_node.next_node.next_node
        self.assertIs(node, fifth)

    def test_guard_window_ninth_node_unconditional(self):
        # Guard invoked on a node: nine guard nodes, the ninth is
        # tail-called even though its dispose equals the guard.
        start = chain([GUARD] * 10)
        kind, node, value, flag = guard_continue(start, 7, 3)
        self.assertEqual((kind, value, flag), ("tail", 7, 3))
        ninth = start
        for _ in range(9):
            ninth = ninth.next_node
        self.assertIs(node, ninth)

    def test_guard_skips_to_first_custom(self):
        start = chain([GUARD, GUARD, GUARD, "custom", GUARD])
        kind, node, value, flag = guard_continue(start, 7, 3)
        self.assertEqual((kind, value, flag), ("tail", 7, 3))
        # Guard examines from start.next_node: indices 1, 2 are
        # guard nodes, index 3 is the first custom dispose.
        self.assertIs(node, start.next_node.next_node.next_node)

    def test_guard_flag_byte_passes_through(self):
        start = chain([GUARD, "custom"])
        kind, _node, _value, flag = guard_continue(start, 7, 0xAB)
        self.assertEqual((kind, flag), ("tail", 0xAB))

    def test_dispose_always_passes_flag_zero(self):
        head = chain([GUARD, "custom"])
        _kind, _node, _value, flag = dispose(7, head)
        self.assertEqual(flag, 0)

    def test_full_walk_past_both_windows(self):
        # 5 guard nodes in dispose's window + 9 in the guard's
        # window, then a custom dispose: the full simulation finds
        # it, proving the walk is unbounded, not 5 or 9 steps.
        head = chain([GUARD] * 14 + ["custom"])
        kind, node, value, flag = dispose_full(7, head)
        self.assertEqual((kind, value, flag), ("tail", 7, 0))
        want = head
        for _ in range(14):
            want = want.next_node
        self.assertIs(node, want)

    def test_full_walk_stops_at_first_custom(self):
        head = chain([GUARD, "first", "second"])
        kind, node, _value, _flag = dispose_full(7, head)
        self.assertEqual(kind, "tail")
        self.assertIs(node, head.next_node)


class PacketTests(unittest.TestCase):
    def test_packet_verify_passes(self):
        verify = load_packet_verify()
        self.assertEqual(verify.main(["--binary", BINARY]), 0)

    def test_tools_checker_passes(self):
        self.assertEqual(check_packet(PACKET_DIR, BINARY), [])

    def test_excerpts_regenerate_identically(self):
        names = ("window.objdump.txt", "guard.objdump.txt")
        before = {}
        for name in names:
            with open(os.path.join(PACKET_DIR, name), "rb") as handle:
                before[name] = handle.read()
        with tempfile.TemporaryDirectory() as temporary:
            packet = os.path.join(temporary, "packet")
            shutil.copytree(PACKET_DIR, packet)
            result = subprocess.run(
                [sys.executable, os.path.join(packet, "export_excerpts.py"),
                 "--binary", "artifacts/node/94/hl-node"],
                cwd=REPO_ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in names:
                with open(os.path.join(packet, name), "rb") as handle:
                    fresh = handle.read().replace(
                        b"artifacts/node/94/hl-node:", b"work/hl-node-94.bin:")
                self.assertEqual(fresh, before[name], name)
        for name in names:
            with open(os.path.join(PACKET_DIR, name), "rb") as handle:
                self.assertEqual(handle.read(), before[name], name)

    def test_sampled_excerpt_instructions_match_binary(self):
        # Pre-submit self-check: three instructions sampled from
        # the raw excerpts, verified byte-for-byte against a fresh
        # objdump run on the real binary.
        import hashlib
        with open(BINARY, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(
            digest,
            "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")
        for start, stop, addrs in (
                ("0x514bb10", "0x514bb95",
                 ("0x514bb10", "0x514bb28", "0x514bb6e")),
                ("0x4f9ea60", "0x4f9eb10",
                 ("0x4f9ea60", "0x4f9ea72", "0x4f9eaf6"))):
            fresh = subprocess.run(
                ["objdump", "-d", "--start-address=%s" % start,
                 "--stop-address=%s" % stop, BINARY],
                capture_output=True, text=True).stdout
            with open(os.path.join(
                    PACKET_DIR, "window.objdump.txt" if "514bb10" in start
                    else "guard.objdump.txt")) as f:
                shipped = f.read()
            for addr in addrs:
                fresh_line = [l for l in fresh.splitlines()
                              if l.strip().startswith(addr[2:] + ":")]
                ship_line = [l for l in shipped.splitlines()
                             if l.strip().startswith(addr[2:] + ":")]
                self.assertEqual(len(fresh_line), 1, addr)
                self.assertEqual(len(ship_line), 1, addr)
                self.assertEqual(fresh_line[0].split("<")[0],
                                 ship_line[0].split("<")[0], addr)

    def test_corrupt_records_breaks_packet_verify(self):
        # verify.py reads records.json from its own directory, so
        # run the copied packet's verifier as a subprocess.
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            with open(os.path.join(copy, "records.json")) as f:
                records = f.read()
            records = records.replace(
                "6f4d0354596f5ce7baeacbebb7d69ceb59ad1a6f69b8348677dce58a24c4c9db",
                "0000000000000000000000000000000000000000000000000000000000000000")
            with open(os.path.join(copy, "records.json"), "w") as f:
                f.write(records)
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "verify.py"),
                 "--binary", BINARY],
                capture_output=True, text=True, cwd=REPO_ROOT)
            self.assertNotEqual(result.returncode, 0)

    def test_corrupt_excerpt_byte_breaks_tools_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            path = os.path.join(copy, "window.objdump.txt")
            with open(path) as f:
                text = f.read()
            text = text.replace("f3 0f 1e fa", "f3 0f 1e fb", 1)
            with open(path, "w") as f:
                f.write(text)
            self.assertNotEqual(check_packet(copy, BINARY), [])


if __name__ == "__main__":
    unittest.main()
