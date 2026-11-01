#!/usr/bin/env python3
"""Unit tests for the foundation indexed-accumulator checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_indexed_accumulator -v

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
import foundation_indexed_accumulator as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-indexed-accumulator-94")
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


class TestIndexedAccumulator(unittest.TestCase):
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

    def test_simulate_index_default_when_table_null(self):
        # The je skips the movslq, so eax keeps the default 13.
        self.assertEqual(checker.simulate_index(False, 0), 13)
        self.assertEqual(checker.simulate_index(False, 0x7FFFFFFF), 13)

    def test_simulate_index_sign_extends_field(self):
        self.assertEqual(checker.simulate_index(True, 0), 0)
        self.assertEqual(checker.simulate_index(True, 5), 5)
        self.assertEqual(checker.simulate_index(True, 0x7FFFFFFF), 0x7FFFFFFF)
        # movslq: a 32-bit value with the high bit set goes negative.
        self.assertEqual(checker.simulate_index(True, 0x80000000), -2147483648)
        self.assertEqual(checker.simulate_index(True, 0xFFFFFFFF), -1)
        # Only the low 32 bits are loaded.
        self.assertEqual(checker.simulate_index(True, 0x1FFFFFFFF), -1)

    def test_simulate_entry_stride_eight(self):
        self.assertEqual(checker.simulate_entry(0x1000, 13), 0x1000 + 104)
        self.assertEqual(checker.simulate_entry(0x1000, 0), 0x1000)
        self.assertEqual(checker.simulate_entry(0x1000, -1), 0x1000 - 8)

    def test_simulate_apply_updates_count_and_sum(self):
        index, entry, count, total = checker.simulate_apply(
            0x1000, False, 0, 7, 41, 100)
        self.assertEqual((index, entry, count, total),
                         (13, 0x1000 + 104, 42, 107))
        index, entry, count, total = checker.simulate_apply(
            0x1000, True, 2, 3, 0, 0)
        self.assertEqual((index, entry, count, total), (2, 0x1010, 1, 3))

    def test_corrupt_window_byte_fails(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[10] ^= 0xFF  # default-index immediate
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_window_hash_fails(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_field_offset_fails(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['index_field_offset'] = 0x24
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_caller_count_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['indexed_accumulator'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corrupt_rule_offset_fails(self):
        ev = copy.deepcopy(self.ev)
        ev['rules']['indexed_accumulator']['count_offset'] = '0xb8'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corrupt_digest_fails(self):
        ev = copy.deepcopy(self.ev)
        ev['target_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_binary_window_byte_flip_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        # Flip one window byte in a copy of the verified binary: the
        # digest check must fail before any window comparison runs.
        data = bytearray(self.binary)
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
        from elf_index import sections
        secs = sections(bytes(data))
        text = [s for s in secs if s['name'] == '.text'][0]
        off = text['offset'] + 0x514ac60 - text['address']
        data[off] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.analyze(bytes(data), copy.deepcopy(self.ev))


if __name__ == '__main__':
    unittest.main()
