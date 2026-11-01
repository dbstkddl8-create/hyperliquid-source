#!/usr/bin/env python3
"""Tests for node #94 chain-walk dispatch at 0x514ba10 (RE-001).

Covers the model in tools/foundation_chain_walk_dispatch.py, the
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
    REPO_ROOT, "research", "work-items", "RE-001-chain-walk-dispatch-94")
BINARY = os.path.join(REPO_ROOT, "artifacts", "node", "94", "hl-node")

sys.path.insert(0, REPO_ROOT)

from tools.foundation_chain_walk_dispatch import (  # noqa: E402
    DEFAULT, Node, Record, check_packet, default_handler, dispatch_from,
    table_lookup, walk)


def load_packet_verify():
    spec = importlib.util.spec_from_file_location(
        "walk_verify", os.path.join(PACKET_DIR, "verify.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def handler_returning(value):
    def handler(node, key):
        return value
    return handler


class ModelTests(unittest.TestCase):
    def test_null_head_returns_zero(self):
        self.assertEqual(walk(None, b"key"), 0)

    def test_head_with_no_next_returns_zero(self):
        self.assertEqual(walk(Node(), b"key"), 0)

    def test_non_default_handler_wins_over_table_hit(self):
        node = Node(handler=handler_returning(77),
                    table=[Record(b"key", 55)])
        head = Node(next_node=node)
        self.assertEqual(walk(head, b"key"), 77)

    def test_handler_returning_zero_stops_the_walk(self):
        # A tail-called handler's return is returned verbatim, even 0:
        # the walk does not continue to the next node.
        second = Node(table=[Record(b"key", 99)])
        first = Node(handler=handler_returning(0), next_node=second)
        head = Node(next_node=first)
        self.assertEqual(walk(head, b"key"), 0)

    def test_default_node_table_hit(self):
        node = Node(table=[Record(b"other", 1), Record(b"key", 42)])
        head = Node(next_node=node)
        self.assertEqual(walk(head, b"key"), 42)

    def test_table_miss_advances_to_next_node(self):
        second = Node(table=[Record(b"key", 9)])
        first = Node(table=[Record(b"nope", 1)], next_node=second)
        head = Node(next_node=first)
        self.assertEqual(walk(head, b"key"), 9)

    def test_walk_beyond_the_three_unrolled_iterations(self):
        # Hit on the fifth node: the bytes unroll three iterations and
        # then loop back to the head, so the walk must be unbounded.
        fifth = Node(table=[Record(b"key", 5)])
        fourth = Node(next_node=fifth)
        third = Node(next_node=fourth)
        second = Node(next_node=third)
        first = Node(next_node=second)
        head = Node(next_node=first)
        self.assertEqual(walk(head, b"key"), 5)

    def test_all_miss_returns_zero(self):
        third = Node(table=[Record(b"z", 3)])
        second = Node(table=[Record(b"y", 2)], next_node=third)
        first = Node(table=[Record(b"x", 1)], next_node=second)
        head = Node(next_node=first)
        self.assertEqual(walk(head, b"key"), 0)

    def test_empty_table_advances(self):
        second = Node(table=[Record(b"key", 8)])
        first = Node(table=[], next_node=second)
        head = Node(next_node=first)
        self.assertEqual(walk(head, b"key"), 8)

    def test_empty_key_matches_empty_record_key(self):
        node = Node(table=[Record(b"", 31)])
        head = Node(next_node=node)
        self.assertEqual(walk(head, b""), 31)

    def test_empty_key_does_not_match_nonempty_key(self):
        node = Node(table=[Record(b"a", 31)])
        head = Node(next_node=node)
        self.assertEqual(walk(head, b""), 0)

    def test_first_matching_record_wins(self):
        node = Node(table=[Record(b"key", 11), Record(b"key", 22)])
        self.assertEqual(table_lookup(node, b"key"), 11)

    def test_key_length_boundaries(self):
        # The helper materializes keys by three paths (1 byte, 2..15,
        # heap over 15); all three must compare identically.
        for key in (b"a", b"0123456789abcde", b"0123456789abcdef"):
            node = Node(table=[Record(key, 7)])
            self.assertEqual(table_lookup(node, key), 7)
            self.assertEqual(table_lookup(node, key + b"x"), 0)

    def test_sentinel_agrees_with_dispatch_on_default_chains(self):
        second = Node(handler=handler_returning(66))
        first = Node(table=[Record(b"miss", 1)], next_node=second)
        for key in (b"key", b"miss"):
            self.assertEqual(default_handler(first, key),
                             dispatch_from(first, key))

    def test_sentinel_null_next_returns_zero(self):
        node = Node(table=[Record(b"other", 1)])
        self.assertEqual(default_handler(node, b"key"), 0)

    def test_sentinel_table_hit_returns_without_stepping(self):
        nxt = Node(handler=handler_returning(66))
        node = Node(table=[Record(b"key", 44)], next_node=nxt)
        self.assertEqual(default_handler(node, b"key"), 44)


class BinaryTests(unittest.TestCase):
    def test_packet_verifier_passes(self):
        result = subprocess.run(
            [sys.executable, os.path.join(PACKET_DIR, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_tools_checker_passes(self):
        self.assertEqual(check_packet(PACKET_DIR, BINARY), [])

    def test_excerpt_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet_copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, packet_copy)
            before = {}
            for name in os.listdir(packet_copy):
                if name.endswith(".objdump.txt"):
                    with open(os.path.join(packet_copy, name), "rb") as f:
                        before[name] = f.read()
            result = subprocess.run(
                [sys.executable, os.path.join(packet_copy, "export_excerpts.py"),
                 "--binary", "artifacts/node/94/hl-node"],
                capture_output=True, text=True, cwd=REPO_ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name, blob in before.items():
                with open(os.path.join(packet_copy, name), "rb") as f:
                    self.assertEqual(f.read().replace(b"artifacts/node/94/hl-node:", b"work/hl-node-94.bin:"), blob, name)


class CorruptionTests(unittest.TestCase):
    def _packet_copy(self, tmp):
        packet_copy = os.path.join(tmp, "packet")
        shutil.copytree(PACKET_DIR, packet_copy)
        return packet_copy

    def test_flipped_excerpt_byte_fails_tools_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet_copy = self._packet_copy(tmp)
            path = os.path.join(packet_copy, "window.objdump.txt")
            with open(path) as f:
                text = f.read()
            # Flip one recorded byte digit in the first excerpt line.
            for i, ch in enumerate(text):
                if ch in "0123456789abcdef" and text[i - 1] == "\t":
                    flipped = "0" if ch != "0" else "1"
                    text = text[:i] + flipped + text[i + 1:]
                    break
            with open(path, "w") as f:
                f.write(text)
            self.assertNotEqual(check_packet(packet_copy, BINARY), [])

    def test_missing_excerpt_fails_tools_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet_copy = self._packet_copy(tmp)
            os.remove(os.path.join(packet_copy, "helper.objdump.txt"))
            self.assertNotEqual(check_packet(packet_copy, BINARY), [])

    def test_wrong_binary_fails_tools_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = os.path.join(tmp, "wrong.bin")
            with open(wrong, "wb") as f:
                f.write(b"not the node binary")
            self.assertNotEqual(check_packet(PACKET_DIR, wrong), [])

    def test_tampered_manifest_fails_packet_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet_copy = self._packet_copy(tmp)
            path = os.path.join(packet_copy, "MANIFEST.sha256")
            with open(path) as f:
                text = f.read()
            with open(path, "w") as f:
                f.write("0" * 64 + text[64:])
            result = subprocess.run(
                [sys.executable, os.path.join(packet_copy, "verify.py"),
                 "--binary", BINARY],
                capture_output=True, text=True, cwd=REPO_ROOT)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
