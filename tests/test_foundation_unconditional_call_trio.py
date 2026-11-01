#!/usr/bin/env python3
"""Unit tests for the foundation unconditional-call-trio checker (node #94).

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_unconditional_call_trio -v

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
import foundation_unconditional_call_trio as checker

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "foundation-unconditional-call-trio-94")
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


class TestUnconditionalCallTrio(unittest.TestCase):
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

    def test_simulation_lea_arg_adds_offset(self):
        seen = []
        result = checker.simulate_unconditional_call(
            0x1000 + 0x40, lambda a: (seen.append(a), 77)[1])
        self.assertEqual(result, (77, 1))
        self.assertEqual(seen, [0x1040])

    def test_simulation_rdx_arg_passes_rdx(self):
        seen = []
        result = checker.simulate_unconditional_call(
            0x2000, lambda a: (seen.append(a), 55)[1])
        self.assertEqual(result, (55, 1))
        self.assertEqual(seen, [0x2000])

    def test_simulation_callee_zero_still_returns_one(self):
        result = checker.simulate_unconditional_call(
            0x3000, lambda a: 0)
        self.assertEqual(result, (0, 1))

    def test_simulation_trio_callees_distinct(self):
        targets = [w['call_target'] for w in self.ev['windows']]
        self.assertEqual(len(set(targets)), 3)

    def test_simulation_rdx_windows_share_argument_protocol(self):
        args = [self.ev['rules'][n]['call_argument'] for n in
                ('rdx_arg_call_a', 'rdx_arg_call_b')]
        self.assertEqual(args[0], args[1])
        self.assertNotEqual(
            args[0], self.ev['rules']['lea_arg_call']['call_argument'])

    def test_corruption_lea_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][0]['call_target'] = '0x51cc541'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_rdx_call_target_rejected(self):
        ev = copy.deepcopy(self.ev)
        ev['windows'][1]['call_target'] = '0x50aaf21'
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_lea_displacement_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][0]['bytes_hex']))
        raw[8] = 0x41  # lea offset 0x40 destroyed
        ev['windows'][0]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_rdx_argument_move_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][1]['bytes_hex']))
        raw[7] = 0xD6  # mov rdx,rdi destroyed (would move rsi instead)
        ev['windows'][1]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_out_store_rejected(self):
        ev = copy.deepcopy(self.ev)
        raw = bytearray(bytes.fromhex(ev['windows'][2]['bytes_hex']))
        raw[17] = 0x0B  # store opcode destroyed
        ev['windows'][2]['bytes_hex'] = raw.hex()
        with self.assertRaises(ValueError):
            checker.analyze(None, ev)

    def test_corruption_callee_census_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['callee_direct_callers']['0x50aaf20'] = 5
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)

    def test_corruption_caller_count_rejected_in_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev['direct_callers']['lea_arg_call'] = 1
        with self.assertRaises(ValueError):
            checker.analyze(self.binary, ev)


if __name__ == '__main__':
    unittest.main()
