#!/usr/bin/env python3
"""Unit tests for the foundation call-wrapper checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_call_wrapper -v

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
import foundation_call_wrapper as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-call-wrapper-94")
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


class TestCallWrapper(unittest.TestCase):
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

    def test_simulation_delegates_field_to_callee(self):
        state = {0x788: 111}
        self.assertEqual(
            checker.simulate_call(state, lambda field: field * 2), (222, 1))

    def test_simulation_distinguishes_callee_results(self):
        self.assertEqual(
            checker.simulate_call({0x788: 5}, lambda field: 0), (0, 1))
        self.assertEqual(
            checker.simulate_call({0x788: 5}, lambda field: 9), (9, 1))

    def test_simulation_requires_the_788_field(self):
        # A state keyed only under the trio's 0x8e8 chain must not
        # satisfy this window, whose only load is [rdi + 0x788].
        with self.assertRaises(KeyError):
            checker.simulate_call({0x8E8: 999}, lambda field: field)

    def test_corruption_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x4fec391'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_window_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[15] = 0xE9  # call -> jmp: not the window's protocol
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_return_value_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['rules']['call_wrapper_788']['return_value'] = 0
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_padding_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['padding_int3_bytes'] = 3
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['call_wrapper_788'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
