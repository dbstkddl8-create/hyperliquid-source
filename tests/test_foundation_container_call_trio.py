#!/usr/bin/env python3
"""Unit tests for the foundation container-call trio checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_container_call_trio -v

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
import foundation_container_call_trio as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-container-call-trio-94")
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


class TestContainerCallTrio(unittest.TestCase):
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

    def test_simulation_returns_callee_result(self):
        seen = []
        result = checker.simulate_container_call(
            0x2000, lambda a: (seen.append(a), 99)[1])
        self.assertEqual(result, (99, 1))
        self.assertEqual(seen, [0x2000])

    def test_simulation_zero_root(self):
        self.assertEqual(
            checker.simulate_container_call(0, lambda a: 0), (0, 1))

    def test_simulation_windows_call_distinct_callees(self):
        # Each window passes the same root to its own callee; the
        # callee identity, not the root, distinguishes the windows.
        results = [
            checker.simulate_container_call(0x3000, lambda a: 11),
            checker.simulate_container_call(0x3000, lambda a: 22),
            checker.simulate_container_call(0x3000, lambda a: 33),
        ]
        self.assertEqual(results, [(11, 1), (22, 1), (33, 1)])

    def test_simulation_byte_identical_pair_shares_rule(self):
        # Windows B and C are byte-identical, so the same simulation
        # with the same stub callee must give the same result; only
        # the recorded call target differs.
        self.assertEqual(
            checker.simulate_container_call(7, lambda a: a + 1),
            checker.simulate_container_call(7, lambda a: a + 1))

    def test_corruption_first_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x4fec371'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_third_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][2]['call_target'] = '0x4fec3a1'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_root_load_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[8] = 0x89  # container-root offset 0x788 destroyed
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_out_store_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[21] = 0x0B  # store opcode destroyed, changing the out rule
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_callee_census_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['callee_direct_callers']['0x4fec3a0'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['container_call_b'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
