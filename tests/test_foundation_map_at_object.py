#!/usr/bin/env python3
"""Unit tests for the foundation map-at-object checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_map_at_object -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_map_at_object as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-map-at-object-94",
    "evidence.json")
PACKET_DIR = os.path.dirname(EVIDENCE)
ARTIFACTS_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
WORK_BINARY = os.path.join("work", "hl-node-94.bin")
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def load_binary():
    for path in (ARTIFACTS_BINARY, WORK_BINARY):
        if not os.path.exists(path):
            continue
        with open(path, "rb") as fh:
            binary = fh.read()
        if hashlib.sha256(binary).hexdigest() == TARGET_SHA:
            return binary
    return None


def load_fixture():
    with open(EVIDENCE) as fh:
        ev = json.load(fh)
    return ev, load_binary()


def tree(*pairs):
    """Build a balanced search tree from (key, value) pairs."""
    nodes = [checker.Node(k, v) for k, v in pairs]
    if not nodes:
        return None
    mid = len(nodes) // 2
    root = nodes[mid]
    root.left = tree(*pairs[:mid]) if mid else None
    root.right = tree(*pairs[mid + 1:]) if mid + 1 < len(pairs) else None
    return root


class ModelTests(unittest.TestCase):
    def test_empty_tree_throws(self):
        with self.assertRaises(checker.MapAtError):
            checker.map_at(None, 3)

    def test_single_node_hit_and_misses(self):
        root = checker.Node(5, 1.5)
        self.assertEqual(checker.map_at(root, 5), 1.5)
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, 4)
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, 6)

    def test_bracket_misses_throw_despite_neighbours(self):
        root = tree((3, 3.0), (7, 7.0), (10, 10.0))
        self.assertEqual(checker.map_at(root, 7), 7.0)
        # 5 has a predecessor (3) and a successor (7) but no exact hit.
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, 5)
        # 11 is past the greatest key; 2 is below the smallest key.
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, 11)
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, 2)

    def test_consumer_key_domain_all_hit(self):
        keys = [3, 4, 5, 6, 7, 9, 10, 13, 14, 16, 18, 19, 20, 21]
        root = tree(*[(k, float(k)) for k in keys])
        for k in keys:
            self.assertEqual(checker.map_at(root, k), float(k))
        # The keys the consumer does not call directly still throw
        # when absent from the tree, and hit when present.
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, 17)

    def test_signed_key_ordering(self):
        root = tree((-1, -1.0), (0, 0.0), (1, 1.0))
        self.assertEqual(checker.map_at(root, -1), -1.0)
        self.assertEqual(checker.map_at(root, 0), 0.0)
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, -2)

    def test_int32_edges(self):
        lo, hi = -2147483648, 2147483647
        root = tree((lo, 1.0), (0, 2.0), (hi, 3.0))
        self.assertEqual(checker.map_at(root, lo), 1.0)
        self.assertEqual(checker.map_at(root, hi), 3.0)
        with self.assertRaises(checker.MapAtError):
            checker.map_at(root, lo + 1)


class BinaryTests(unittest.TestCase):
    def test_checker_passes_on_target_binary(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        self.assertTrue(checker.check(ev, binary, packet_dir=PACKET_DIR))

    def test_function_bytes_reproduce_from_binary(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        body = checker.read_at(
            binary, checker.FUNCTION_START, ev["function"]["bytes"])
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         ev["function"]["sha256"])
        self.assertEqual(body[:4], bytes.fromhex("488b5710"))

    def test_caller_census_reproduces(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        sites = checker.caller_census(binary)
        recorded = [int(c["call_va"], 16)
                    for c in ev["consumer"]["callers"]]
        self.assertEqual(sites, recorded)
        self.assertEqual(len(sites), 14)

    def test_corrupt_function_byte_fails(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        bad = bytearray(binary)
        off = checker.va_to_offset(binary, checker.FUNCTION_START)
        bad[off] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.check(ev, bytes(bad), packet_dir=PACKET_DIR)

    def test_corrupt_throw_string_fails(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        bad = bytearray(binary)
        off = checker.va_to_offset(binary, checker.STRING_VA)
        bad[off] = ord("n")  # "map::at" -> "nap::at"
        with self.assertRaises(ValueError):
            checker.check(ev, bytes(bad), packet_dir=PACKET_DIR)

    def test_corrupt_caller_call_fails(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        bad = bytearray(binary)
        first = int(ev["consumer"]["callers"][0]["call_va"], 16)
        off = checker.va_to_offset(binary, first)
        bad[off] = 0xE9  # direct call -> direct jump: census loses a site
        with self.assertRaises(ValueError):
            checker.check(ev, bytes(bad), packet_dir=PACKET_DIR)

    def test_corrupt_key_setup_fails(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        bad = bytearray(binary)
        setup = ev["consumer"]["callers"][0]["key_setup"]
        off = checker.va_to_offset(binary, int(setup["va"], 16))
        bad[off + 1] ^= 0x01  # key 21 -> key 20 in the setup bytes
        with self.assertRaises(ValueError):
            checker.check(ev, bytes(bad), packet_dir=PACKET_DIR)


if __name__ == "__main__":
    unittest.main()
