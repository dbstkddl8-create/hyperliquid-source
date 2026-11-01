#!/usr/bin/env python3
"""Unit tests for the foundation ad0 accessor + composite checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_ad0_accessor_composite -v

Binary-dependent tests load the first candidate binary whose SHA-256
matches the provenance digest (the ignored work copy, or the
materialized LFS artifact); they skip when neither is available, so a
checkout with only LFS pointers still runs the pure simulation and
corruption checks. No file in the packet directory is modified by any
test.
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import foundation_ad0_accessor_composite as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-ad0-accessor-composite-94")
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


class TestAd0AccessorComposite(unittest.TestCase):
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

    def test_simulation_accessor_returns_callee_result(self):
        seen = []
        result = checker.simulate_ad0_accessor(
            0x2000, lambda a: (seen.append(a), 99)[1])
        self.assertEqual(result, (99, 1))
        self.assertEqual(seen, [0x2000])

    def test_simulation_accessor_zero_field(self):
        self.assertEqual(
            checker.simulate_ad0_accessor(0, lambda a: 0), (0, 1))

    def test_simulation_composite_positive_excess(self):
        # S = 100 + 10 + 5 = 115; T = 2 * (20 + 10) = 60; out = 55.
        self.assertEqual(
            checker.simulate_ad0_composite(100, 10, 5, 10, 20), (55, 1))

    def test_simulation_composite_zero_when_doubled_covers(self):
        # S = 50; T = 2 * (20 + 10) = 60 >= 50, so out = 0.
        self.assertEqual(
            checker.simulate_ad0_composite(50, 0, 0, 10, 20), (0, 1))

    def test_simulation_composite_boundary_equal_is_zero(self):
        # S = 60; T = 2 * (20 + 10) = 60, equal, so out = 0.
        self.assertEqual(
            checker.simulate_ad0_composite(60, 0, 0, 10, 20), (0, 1))

    def test_simulation_composite_one_over_boundary(self):
        # S = 61; T = 60, so out = 1.
        self.assertEqual(
            checker.simulate_ad0_composite(61, 0, 0, 10, 20), (1, 1))

    def test_simulation_composite_a70_a78_distinct(self):
        # Swapping a70/a78 must change the result: a70 feeds S, a78
        # feeds the doubled term.
        forward = checker.simulate_ad0_composite(100, 0, 0, 0, 0)
        swapped = checker.simulate_ad0_composite(0, 0, 0, 100, 0)
        self.assertEqual(forward, (100, 1))
        self.assertEqual(swapped, (0, 1))

    def test_corruption_accessor_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x5172ad1'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_accessor_field_load_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[18] = 0xF9  # field offset 0x8f8 destroyed
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_composite_first_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][1]['call_targets'][0] = '0x5172a31'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_composite_a78_load_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[92] = 0x79  # a78 field offset destroyed (0xa78 -> 0xa79)
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_composite_cmovb_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[131] = 0x43  # cmovb -> cmovae, changing the unsigned rule
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['ad0_accessor'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
