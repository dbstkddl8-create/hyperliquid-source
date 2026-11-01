#!/usr/bin/env python3
"""Unit tests for the foundation map-at checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_map_at -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_map_at as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-map-at-94",
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


def tree(root, nodes):
    return {"root": root, "nodes": nodes}


def node(key, left=None, right=None):
    return {"key": key, "left": left, "right": right}


class TestMapAt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_empty_tree_throws(self):
        with self.assertRaises(LookupError):
            checker.map_at(tree(None, {}), 5)

    def test_single_node_hit_and_both_misses(self):
        table = tree("a", {"a": node(5)})
        self.assertEqual(checker.map_at(table, 5), "a")
        with self.assertRaises(LookupError):
            checker.map_at(table, 4)
        with self.assertRaises(LookupError):
            checker.map_at(table, 6)

    def test_candidate_refined_through_left_subtree(self):
        table = tree("r", {
            "r": node(10, left="l", right="g"),
            "l": node(5, right="m"),
            "m": node(7),
            "g": node(20),
        })
        self.assertEqual(checker.map_at(table, 7), "m")
        self.assertEqual(checker.map_at(table, 20), "g")
        self.assertEqual(checker.map_at(table, 10), "r")

    def test_refinement_miss_throws_on_greater_candidate(self):
        table = tree("r", {
            "r": node(10, left="l", right="g"),
            "l": node(5, right="m"),
            "m": node(7),
            "g": node(20),
        })
        with self.assertRaises(LookupError):
            checker.map_at(table, 8)
        with self.assertRaises(LookupError):
            checker.map_at(table, 3)

    def test_right_subtree_hit_after_less_key(self):
        table = tree("r", {
            "r": node(10, left="l", right="g"),
            "l": node(5),
            "g": node(20, left="h"),
            "h": node(15),
        })
        self.assertEqual(checker.map_at(table, 15), "h")
        with self.assertRaises(LookupError):
            checker.map_at(table, 17)

    def test_signed_comparison_edges(self):
        table = tree("a", {"a": node(-1)})
        self.assertEqual(checker.map_at(table, -1), "a")
        with self.assertRaises(LookupError):
            checker.map_at(table, -2)
        with self.assertRaises(LookupError):
            checker.map_at(table, 0)
        table = tree("a", {"a": node(-2147483648)})
        self.assertEqual(checker.map_at(table, -2147483648), "a")
        with self.assertRaises(LookupError):
            checker.map_at(table, -2147483647)
        table = tree("a", {"a": node(2147483647)})
        self.assertEqual(checker.map_at(table, 2147483647), "a")
        with self.assertRaises(LookupError):
            checker.map_at(table, 2147483646)

    def test_return_is_value_slot_address_concept(self):
        # The window returns candidate+0x28, not the key: two nodes
        # with distinct ids must return distinct slots even when the
        # sought key differs only by which subtree holds it.
        table = tree("r", {
            "r": node(10, left="l", right="g"),
            "l": node(5),
            "g": node(20),
        })
        self.assertNotEqual(
            checker.map_at(table, 5), checker.map_at(table, 20))

    def test_corruption_instruction_byte_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["entry"]["instructions"][0]["bytes"] = "4c8d05590d6401"
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corruption_body_sha_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["entry"]["sha256"] = "0" * 64
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corruption_table_displacement_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["table"]["displacement"] = "0x640d58"
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corruption_throw_target_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["throw_call"]["target"] = "0x5660711"
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corruption_message_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["throw_call"]["message"] = "map::find"
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corruption_caller_list_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["incoming"]["direct_e8_callers"] = (
            mutated["incoming"]["direct_e8_callers"][:-1])
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_corruption_rule_edge_fails(self):
        if self.binary is None:
            self.skipTest("digest-verified node #94 binary not available")
        mutated = copy.deepcopy(self.ev)
        mutated["rule"]["edges"][1]["outcome"] = "throw"
        failures = checker.run_evidence(
            mutated, self.binary, self.sections, self.packet_dir)
        self.assertTrue(failures)

    def test_evidence_instructions_cover_body_exactly(self):
        # The recorded instructions must tile the 96-byte body with
        # no gaps and no overlaps, independent of the binary.
        pos = 0x514B1C0
        for instr in self.ev["entry"]["instructions"]:
            self.assertEqual(int(instr["va"], 16), pos)
            pos += len(bytes.fromhex(instr["bytes"]))
        self.assertEqual(pos, 0x514B220)


if __name__ == "__main__":
    unittest.main()
