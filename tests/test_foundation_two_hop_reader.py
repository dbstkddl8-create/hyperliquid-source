#!/usr/bin/env python3
"""Unit tests for the foundation two-hop reader checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_two_hop_reader -v

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
import foundation_two_hop_reader as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-two-hop-reader-94")
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


class TestTwoHopReader(unittest.TestCase):
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

    def test_simulation_projects_inner_qword(self):
        state = {0x788: {0x928: 4242}}
        self.assertEqual(checker.simulate_load(state), (4242, 1))

    def test_simulation_distinguishes_928_from_trio_8e8_chain(self):
        # The trio's inner offset is 0x8e8, this window's is 0x928:
        # a state keyed only under 0x8e8 must not satisfy this window.
        state = {0x788: {0x8E8: 999}}
        with self.assertRaises(KeyError):
            checker.simulate_load(state)

    def test_simulation_distinguishes_neighbor_fields(self):
        # Two different inner values must project independently.
        self.assertEqual(
            checker.simulate_load({0x788: {0x928: 7}}), (7, 1))
        self.assertEqual(
            checker.simulate_load({0x788: {0x928: 8}}), (8, 1))

    def test_corrupt_window_byte_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev["windows"][0]["bytes_hex"]))
        raw[14] ^= 0x01  # inner load offset byte
        ev["windows"][0]["bytes_hex"] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_window_hash_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev["windows"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_wrong_window_count_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev["windows"] = ev["windows"] + ev["windows"]
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_binary_padding_corruption_rejected(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        # Corrupt a byte of the binary; the digest check must fail
        # first, proving binary mode is digest-bound.
        tampered = bytearray(self.binary)
        tampered[0] ^= 0x01
        with self.assertRaises(ValueError):
            checker.analyze(bytes(tampered), copy.deepcopy(self.ev))


if __name__ == "__main__":
    unittest.main()
