#!/usr/bin/env python3
"""Unit tests for the foundation conditional-call checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_conditional_call -v

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
import foundation_conditional_call as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-conditional-call-94")
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


class TestConditionalCall(unittest.TestCase):
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

    def test_simulation_null_stores_zero_without_calling(self):
        seen = []
        result = checker.simulate_conditional_call(
            0, lambda a: (seen.append(a), 99)[1])
        self.assertEqual(result, (0, 1))
        self.assertEqual(seen, [])

    def test_simulation_nonnull_passes_rcx_itself(self):
        seen = []
        result = checker.simulate_conditional_call(
            0x2000, lambda a: (seen.append(a), 77)[1])
        self.assertEqual(result, (77, 1))
        self.assertEqual(seen, [0x2000])

    def test_simulation_nonnull_callee_zero_differs_from_null(self):
        # A callee returning 0 for a non-null argument still counts
        # as a call: the out value coincides with the null path,
        # but the call itself happened.
        seen = []
        result = checker.simulate_conditional_call(
            0x3000, lambda a: (seen.append(a), 0)[1])
        self.assertEqual(result, (0, 1))
        self.assertEqual(seen, [0x3000])

    def test_simulation_always_returns_one(self):
        self.assertEqual(
            checker.simulate_conditional_call(0, lambda a: 5), (0, 1))
        self.assertEqual(
            checker.simulate_conditional_call(9, lambda a: 5), (5, 1))

    def test_corruption_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x51ca581'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_guard_jump_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[14] = 0x09  # je would land past the store, skipping it
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_zeroing_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[5] = 0x33  # xor eax,eax destroyed: null path no longer 0
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_guard_test_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[12] = 0xC8  # test rcx,rcx destroyed
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_out_store_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[24] = 0x0B  # store opcode destroyed, changing the out rule
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_callee_census_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['callee_direct_callers']['0x51ca580'] = 2
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['conditional_call'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
