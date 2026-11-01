#!/usr/bin/env python3
"""Unit tests for the foundation virtual-dispatch checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_virtual_dispatch -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_virtual_dispatch as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-virtual-dispatch-94",
    "evidence.json")
ARTIFACTS_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
WORK_BINARY = os.path.join("work", "hl-node-94.bin")
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
GUARD = 0x700000000  # symbolic load base + 0x4fe8fe0 stand-in


def load_binary():
    for path in (ARTIFACTS_BINARY, WORK_BINARY):
        if not os.path.exists(path):
            continue
        with open(path, "rb") as fh:
            binary = fh.read()
        if hashlib.sha256(binary).hexdigest() == TARGET_SHA:
            return binary
    return None


def load_fixture():
    with open(EVIDENCE) as fh:
        ev = json.load(fh)
    binary = load_binary()
    if binary is None:
        return ev, None, None, os.path.dirname(os.path.abspath(EVIDENCE))
    sections = checker.elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(EVIDENCE))
    return ev, binary, sections, packet_dir


def fake_root(slot, base=0x5000):
    field_object = {"head": {0x28: slot}}
    return {0x950: field_object, 0x30: base}, field_object


class TestVirtualDispatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ev, cls.binary, cls.sections, cls.packet_dir = load_fixture()

    def test_checker_passes_pristine_evidence(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        failures = checker.run_evidence(
            self.ev, self.binary, self.sections, self.packet_dir)
        self.assertEqual(failures, [])

    def test_checker_passes_binary_mode(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        failures = checker.run_all(EVIDENCE, ARTIFACTS_BINARY)
        self.assertEqual(failures, [])

    def test_fast_path_stores_zero_without_calling(self):
        out, called, ret = checker.dispatch(GUARD, GUARD)
        self.assertEqual((out, called, ret), (0, False, 1))

    def test_slow_path_stores_callee_low_byte(self):
        out, called, ret = checker.dispatch(GUARD + 8, GUARD, 0xAB)
        self.assertEqual((out, called, ret), (0xAB, True, 1))

    def test_slow_path_movzbl_masks_to_low_byte(self):
        out, called, ret = checker.dispatch(GUARD + 8, GUARD, 0x1234)
        self.assertEqual(out, 0x34)
        self.assertTrue(called)

    def test_slow_path_zero_result_still_calls(self):
        # Output alone cannot distinguish the paths when the callee
        # returns 0; the model tracks the call explicitly.
        out, called, ret = checker.dispatch(GUARD + 8, GUARD, 0)
        self.assertEqual(out, 0)
        self.assertTrue(called)
        self.assertEqual(ret, 1)

    def test_return_value_is_one_on_every_path(self):
        self.assertEqual(checker.dispatch(GUARD, GUARD)[2], 1)
        self.assertEqual(checker.dispatch(GUARD + 8, GUARD, 0xFF)[2], 1)

    def test_guard_target_returns_zero(self):
        self.assertEqual(checker.guard_target_result(), 0)

    def test_simulate_fast_path_end_to_end(self):
        root, field_object = fake_root(GUARD)
        calls = []

        def callee(obj, arg, slot):
            calls.append((obj, arg, slot))
            return 0x77

        out, called, ret = checker.simulate_window(root, GUARD, callee)
        self.assertEqual((out, called, ret), (0, False, 1))
        self.assertEqual(calls, [])

    def test_simulate_slow_path_end_to_end(self):
        root, field_object = fake_root(GUARD + 8, base=0x5000)
        seen = {}

        def callee(obj, arg, slot):
            seen["obj"] = obj
            seen["arg"] = arg
            seen["slot"] = slot
            return 0x1AB

        out, called, ret = checker.simulate_window(root, GUARD, callee)
        self.assertEqual((out, called, ret), (0xAB, True, 1))
        self.assertIs(seen["obj"], field_object)
        self.assertEqual(seen["arg"], 0x5000 + 0x40)
        self.assertEqual(seen["slot"], GUARD + 8)

    def test_cmp_rip_relative_lands_on_got_slot(self):
        cmp_rec = self.ev["guard_cmp"]
        site = int(cmp_rec["site"], 16)
        disp = int(cmp_rec["displacement"], 16)
        self.assertEqual(site + 7 + disp, 0x5777F18)
        self.assertEqual(cmp_rec["target"], "0x5777f18")

    def test_relocation_resolves_slot_to_guard_target(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        entry = checker.relocation_entry(
            self.binary, self.sections, 0x5777F18)
        self.assertIsNotNone(entry)
        rel_type, addend = entry
        self.assertEqual(rel_type, 8)  # R_X86_64_RELATIVE
        self.assertEqual(addend, 0x4FE8FE0)

    def test_got_file_bytes_are_zero_not_the_guard_value(self):
        # The file bytes are loader-filled, so zero here must not be
        # mistaken for the runtime guard value.
        self.assertEqual(self.ev["got_slot"]["file_bytes"],
                         "0000000000000000")
        self.assertEqual(self.ev["got_slot"]["relocation_addend"],
                         "0x4fe8fe0")

    def test_corruption_cmp_displacement_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["guard_cmp"]["displacement"] = "0x62cd83"
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("guard cmp" in f for f in failures))

    def test_corruption_guard_sha_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["guard_target"]["sha256"] = "0" * 64
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("guard body" in f for f in failures))

    def test_corruption_padding_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["entry"]["padding_bytes"] = 2
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("padding" in f for f in failures))

    def test_corruption_got_addend_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["got_slot"]["relocation_addend"] = "0x4fe8fe1"
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("relocation" in f for f in failures))

    def test_corruption_rule_edge_fails(self):
        if self.binary is None:
            self.skipTest("no digest-verified node #94 binary available")
        ev = copy.deepcopy(self.ev)
        ev["rule"]["edges"][0]["out"] = 1
        failures = checker.run_evidence(
            ev, self.binary, self.sections, self.packet_dir)
        self.assertTrue(any("rule edges" in f for f in failures))


if __name__ == "__main__":
    unittest.main()
