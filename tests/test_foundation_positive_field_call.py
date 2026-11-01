#!/usr/bin/env python3
"""Unit tests for the foundation positive-field call checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_positive_field_call -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_positive_field_call as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-positive-field-call-94",
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


class TestPositiveFieldCall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_positive_fields_yield_one(self):
        for field in (1, 256, 0x12345678, 0x7FFFFFFF):
            self.assertEqual(checker.entry_out(field), 1)

    def test_nonpositive_fields_yield_zero(self):
        for field in (0, 0xFFFFFFFF, 0x80000000, 0xFFFFFF00):
            self.assertEqual(checker.entry_out(field), 0)

    def test_signed_32bit_not_unsigned(self):
        # 0x80000000 is INT32_MIN, not a large positive.
        self.assertEqual(checker.s32(0x80000000), -2147483648)
        self.assertEqual(checker.entry_out(0x80000000), 0)
        self.assertEqual(checker.s32(0xFFFFFFFF), -1)

    def test_callee_full_value_is_not_clean(self):
        # The callee's setg rewrites only %al; the entry's movzbl is
        # what sanitizes the composed output.
        self.assertEqual(checker.callee_full(0x12345678), 0x12345601)
        self.assertEqual(checker.callee_full(0xFFFFFFFF), 0xFFFFFF00)
        self.assertEqual(checker.callee_full(0x100), 0x101)
        self.assertEqual(checker.callee_full(0), 0)
        for field in (0x12345678, 0xFFFFFFFF, 0x100, 0):
            self.assertEqual(checker.entry_out(field),
                             checker.callee_low(field))

    def test_mutated_call_target_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["call"]["target"] = "0x5228ff0"
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("call" in f for f in failures))

    def test_mutated_entry_sha_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["entry"]["sha256"] = "0" * 64
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("entry body" in f for f in failures))

    def test_mutated_padding_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["callee"]["padding_bytes"] = 5
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("padding" in f for f in failures))

    def test_mutated_rule_edge_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][0]["out"] = 1
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("rule edges" in f for f in failures))

    def test_mutated_callee_caller_list_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["callee_callers"]["direct_e8_callers"] = (
            ev["callee_callers"]["direct_e8_callers"][:-1])
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("callers" in f for f in failures))


if __name__ == "__main__":
    unittest.main()
