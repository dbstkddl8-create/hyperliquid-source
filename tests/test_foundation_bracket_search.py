#!/usr/bin/env python3
"""Unit tests for the foundation bracket-search checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_bracket_search -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_bracket_search as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-bracket-search-twin-94",
    "evidence.json")
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
    binary = load_binary()
    if binary is None:
        return ev, None, None, os.path.dirname(os.path.abspath(EVIDENCE))
    sections = checker.elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(EVIDENCE))
    return ev, binary, sections, packet_dir


def tree(root, leftmost, nodes, header="header"):
    return {"root": root, "leftmost": leftmost, "header": header,
            "nodes": nodes}


def node(key, left=None, right=None):
    return {"key": key, "left": left, "right": right}


def three_node():
    return {"n10": node(10), "n20": node(20, "n10", "n30"), "n30": node(30)}


class TestBracketSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_empty_tree_returns_header(self):
        self.assertEqual(
            checker.bracket_search(tree(None, "header", {}), 5),
            (None, "header"))

    def test_single_node_hit_and_both_misses(self):
        table = tree("a", "a", {"a": node(5)})
        self.assertEqual(checker.bracket_search(table, 5), ("a", None))
        self.assertEqual(checker.bracket_search(table, 4), (None, "a"))
        self.assertEqual(checker.bracket_search(table, 6), (None, "a"))

    def test_three_node_hit_via_predecessor_step(self):
        table = tree("n20", "n10", three_node())
        # Root 20 equals sought, so the walk goes right to 30, whose
        # key is greater; the predecessor step returns 20 exactly.
        self.assertEqual(checker.bracket_search(table, 20), ("n20", None))
        self.assertEqual(checker.bracket_search(table, 10), ("n10", None))
        self.assertEqual(checker.bracket_search(table, 30), ("n30", None))

    def test_three_node_brackets(self):
        table = tree("n20", "n10", three_node())
        self.assertEqual(checker.bracket_search(table, 25), (None, "n30"))
        self.assertEqual(checker.bracket_search(table, 15), (None, "n10"))
        self.assertEqual(checker.bracket_search(table, 5), (None, "n10"))
        self.assertEqual(checker.bracket_search(table, 35), (None, "n30"))

    def test_int32_edges(self):
        nodes = {"lo": node(-2147483648), "r": node(0, "lo", "hi"),
                 "hi": node(2147483647)}
        table = tree("r", "lo", nodes)
        self.assertEqual(checker.bracket_search(table, -2147483648),
                         ("lo", None))
        self.assertEqual(checker.bracket_search(table, 2147483647),
                         ("hi", None))
        # -1 sits between INT32_MIN and 0: predecessor is lo.
        self.assertEqual(checker.bracket_search(table, -1), (None, "lo"))
        # 1 sits between 0 and INT32_MAX: successor is hi.
        self.assertEqual(checker.bracket_search(table, 1), (None, "hi"))

    def test_leftmost_skip_means_successor(self):
        # Sought below every key: the walk ends at the smallest node
        # with cl = 1, and the leftmost check skips the decrement.
        nodes = {"a": node(10, None, "b"), "b": node(20)}
        table = tree("a", "a", nodes)
        self.assertEqual(checker.bracket_search(table, 5), (None, "a"))

    def test_corrupted_instruction_byte_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        ev = copy.deepcopy(self.ev)
        ev["entry"]["instructions"][0]["bytes"] = "54"
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corrupted_body_sha_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        ev = copy.deepcopy(self.ev)
        ev["twin"]["sha256"] = "0" * 64
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corrupted_twin_call_target_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        ev = copy.deepcopy(self.ev)
        ev["decrement"]["target"] = "0x56604b1"
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corrupted_caller_list_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        ev = copy.deepcopy(self.ev)
        ev["incoming"]["twin_direct_e8_callers"] = []
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corrupted_rule_edge_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][0]["outcome"] = ["header", None]
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corrupted_consumer_target_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        ev = copy.deepcopy(self.ev)
        ev["consumer"]["target"] = "0x514b220"
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)


if __name__ == "__main__":
    unittest.main()
