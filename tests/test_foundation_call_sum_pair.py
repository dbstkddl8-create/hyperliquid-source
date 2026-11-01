#!/usr/bin/env python3
"""Unit tests for the foundation call-sum pair checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_call_sum_pair -v

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
import foundation_call_sum_pair as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-call-sum-pair-94")
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


class TestCallSumPair(unittest.TestCase):
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

    def test_simulation_adds_field_to_callee_result(self):
        seen = []
        result = checker.simulate_call_sum(
            0x1000, lambda a: (seen.append(a), 40)[1], 2)
        self.assertEqual(result, (42, 1))
        self.assertEqual(seen, [0x1000 + 0x8F0])

    def test_simulation_zero_field_unchanged(self):
        self.assertEqual(
            checker.simulate_call_sum(0, lambda a: 7, 0), (7, 1))

    def test_simulation_wraps_mod_2_to_64(self):
        self.assertEqual(
            checker.simulate_call_sum(0, lambda a: 0xFFFFFFFFFFFFFFFF, 1),
            (0, 1))

    def test_pair_callees_distinct(self):
        targets = [w['call_target'] for w in self.ev['windows']]
        self.assertEqual(len(set(targets)), 2)

    def test_pair_windows_byte_identical(self):
        self.assertEqual(self.ev['windows'][0]['bytes_hex'],
                         self.ev['windows'][1]['bytes_hex'])

    def test_corruption_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x5172db1'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_sum_add_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[46] = 0x29  # add %rbp,%rax destroyed: sub instead of add
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_third_field_load_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[37] = 0xD8  # third-field offset 0xcd0 destroyed
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_window_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[13] = 0x8A  # first-hop load opcode destroyed
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['call_sum_db0'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
