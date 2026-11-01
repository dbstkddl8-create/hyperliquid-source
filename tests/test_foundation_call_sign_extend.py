#!/usr/bin/env python3
"""Unit tests for the foundation call-sign-extend checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_call_sign_extend -v

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
import foundation_call_sign_extend as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-call-sign-extend-94")
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


class TestCallSignExtend(unittest.TestCase):
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

    def test_simulation_sign_extends_negative(self):
        seen = []
        result = checker.simulate_call(
            {0x700: 7, 0x1440: 0xFFFFFF80}, seen.append)
        self.assertEqual(result, (-128, 1))
        self.assertEqual(seen, [7])

    def test_simulation_positive_unchanged(self):
        self.assertEqual(
            checker.simulate_call({0x700: 1, 0x1440: 42}, lambda a: None),
            (42, 1))

    def test_simulation_callee_result_discarded(self):
        # The callee's return value must not leak into the stored value.
        self.assertEqual(
            checker.simulate_call({0x700: 3, 0x1440: 5}, lambda a: 999),
            (5, 1))

    def test_simulation_requires_both_fields(self):
        with self.assertRaises(KeyError):
            checker.simulate_call({0x1440: 5}, lambda a: None)
        with self.assertRaises(KeyError):
            checker.simulate_call({0x700: 3}, lambda a: None)

    def test_corruption_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x5334d61'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_field_offset_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['field_offset'] = 0x1444
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_window_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[28] = 0x8B  # movslq -> plain mov: not the window's protocol
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_padding_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['padding_int3_bytes'] = 12
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['call_sign_extend_700'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
