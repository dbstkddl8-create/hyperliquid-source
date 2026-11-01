#!/usr/bin/env python3
"""Unit tests for the foundation accessor-pair checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_accessor_pair -v

Binary-dependent tests load the first candidate binary whose SHA-256
matches the provenance digest (the ignored work copy, or the materialized
LFS artifact); they skip when neither is available, so a checkout with
only LFS pointers still runs the pure simulation and corruption checks.
No file in the packet directory is modified by any test.
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import foundation_accessor_pair as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-accessor-pair-94")
EVIDENCE_PATH = os.path.join(PACKET_DIR, "evidence.json")


def load_verified_binary():
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "work", "hl-node-94.bin"),
        checker.TARGET,
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path, "rb") as fh:
                data = fh.read()
            if hashlib.sha256(data).hexdigest() == checker.SHA256:
                return data
    return None


def load_evidence():
    with open(EVIDENCE_PATH) as fh:
        return json.load(fh)


class TestAccessorPair(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev = load_evidence()
        cls.binary = load_verified_binary()

    def test_packet_mode_reproduces(self):
        checker.analyze(None, copy.deepcopy(self.ev))

    def test_binary_mode_reproduces(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        checker.analyze(self.binary, copy.deepcopy(self.ev))

    def test_simulate_plain_copy(self):
        for field in (0, 1, 0xABCD, 0xFFFFFFFFFFFFFFFF):
            out, ret = checker.simulate_plain_copy(field)
            self.assertEqual((out, ret), (field, 1))

    def test_simulate_virtual_call_zero_extends(self):
        self.assertEqual(checker.simulate_virtual_call(0x00), (0, 1))
        self.assertEqual(checker.simulate_virtual_call(0x7F), (0x7F, 1))
        self.assertEqual(checker.simulate_virtual_call(0xFF), (0xFF, 1))
        # Only the low byte survives: a wider callee result is truncated.
        self.assertEqual(checker.simulate_virtual_call(0x1FF), (0xFF, 1))

    def test_corrupt_window_byte(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        binary = bytearray(self.binary)
        sections = checker.sections(bytes(binary))
        by_name = {s["name"]: s for s in sections}
        text = by_name[".text"]
        # Flip the plain-copy field-offset byte (0x28 -> 0xd7).
        pos = text["offset"] + (0x514AB97 - text["address"])
        binary[pos] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.analyze(bytes(binary), copy.deepcopy(self.ev))

    def test_corrupt_padding_byte(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        binary = bytearray(self.binary)
        sections = checker.sections(bytes(binary))
        by_name = {s["name"]: s for s in sections}
        text = by_name[".text"]
        pos = text["offset"] + (0x514ABA4 - text["address"])
        binary[pos] = 0x90
        with self.assertRaises(ValueError):
            checker.analyze(bytes(binary), copy.deepcopy(self.ev))

    def test_corrupt_fde_range(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        binary = bytearray(self.binary)
        sections = checker.sections(bytes(binary))
        by_name = {s["name"]: s for s in sections}
        eh = by_name[".eh_frame"]
        pos = eh["offset"] + 0x29A0EC + 12
        binary[pos] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.analyze(bytes(binary), copy.deepcopy(self.ev))

    def test_corrupt_digest(self):
        ev = copy.deepcopy(self.ev)
        ev["target_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_window_hash(self):
        ev = copy.deepcopy(self.ev)
        ev["windows"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_field_offset(self):
        ev = copy.deepcopy(self.ev)
        ev["windows"][0]["field_offset"] = 0x1230
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_caller_count(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["direct_callers"]["plain_copy"] += 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == "__main__":
    unittest.main()
