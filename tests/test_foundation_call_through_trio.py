#!/usr/bin/env python3
"""Unit tests for the foundation call-through trio checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_call_through_trio -v

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
import foundation_call_through_trio as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-call-through-trio-94")
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


class TestCallThroughTrio(unittest.TestCase):
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

    def test_simulation_cltq_sign_extends_negative(self):
        seen = []
        result = checker.simulate_call_through(
            0x1000, lambda a: (seen.append(a), 0xFFFFFF80)[1], 'cltq')
        self.assertEqual(result, (-128, 1))
        self.assertEqual(seen, [0x1000 + 0x8F0])

    def test_simulation_cltq_positive_unchanged(self):
        self.assertEqual(
            checker.simulate_call_through(0, lambda a: 42, 'cltq'),
            (42, 1))

    def test_simulation_cltq_boundary(self):
        self.assertEqual(
            checker.simulate_call_through(0, lambda a: 0x80000000, 'cltq'),
            (-2147483648, 1))
        self.assertEqual(
            checker.simulate_call_through(0, lambda a: 0x7FFFFFFF, 'cltq'),
            (2147483647, 1))

    def test_simulation_movzbl_masks_to_low_byte(self):
        seen = []
        result = checker.simulate_call_through(
            0x2000, lambda a: (seen.append(a), 0x1AB)[1], 'movzbl')
        self.assertEqual(result, (0xAB, 1))
        self.assertEqual(seen, [0x2000 + 0x8F0])

    def test_simulation_movzbl_zero(self):
        self.assertEqual(
            checker.simulate_call_through(0, lambda a: 0x100, 'movzbl'),
            (0, 1))

    def test_trio_callees_distinct(self):
        targets = [w['call_target'] for w in self.ev['windows']]
        self.assertEqual(len(set(targets)), 3)

    def test_corruption_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x51723e1'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_extension_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[27] = 0x99  # cltq prefix destroyed: not the window's protocol
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_movzbl_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][2]['bytes_hex']))
        raw[27] = 0x0F  # movzbl opcode destroyed
        raw[28] = 0xB7  # movzwl instead of movzbl
        ev['windows'][2]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_window_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[5] = 0x8B  # first-hop load opcode destroyed
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_padding_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['windows'][2]['padding_int3_bytes'] = 7
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['call_through_cltq_23e0'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
