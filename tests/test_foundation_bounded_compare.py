#!/usr/bin/env python3
"""Unit tests for the foundation bounded-compare checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_bounded_compare -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_bounded_compare as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-bounded-compare-94",
    "evidence.json")
PACKET_DIR = os.path.dirname(EVIDENCE)
ARTIFACTS_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
WORK_BINARY = os.path.join("work", "hl-node-94.bin")
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


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
    return ev, load_binary()


class ModelTests(unittest.TestCase):
    def test_equal_inputs_return_zero(self):
        self.assertEqual(checker.compare_bytes(b"abc", b"abc"), 0)
        self.assertEqual(checker.compare_bytes(b"", b""), 0)

    def test_strict_prefix_sign_follows_length_difference(self):
        self.assertLess(checker.compare_bytes(b"ab", b"abc"), 0)
        self.assertGreater(checker.compare_bytes(b"abc", b"ab"), 0)
        self.assertEqual(checker.compare_bytes(b"ab", b"abc"), -1)
        self.assertEqual(checker.compare_bytes(b"abc", b"ab"), 1)

    def test_empty_against_nonempty(self):
        self.assertEqual(checker.compare_bytes(b"", b"abc"), -3)
        self.assertEqual(checker.compare_bytes(b"abc", b""), 3)

    def test_first_differing_byte_wins_over_length(self):
        # 'b' > 'a' at index 0, even though the second input is longer.
        self.assertGreater(checker.compare_bytes(b"b", b"ax"), 0)
        self.assertEqual(checker.compare_bytes(b"b", b"ax"), ord("b") - ord("a"))
        self.assertLess(checker.compare_bytes(b"a", b"bx"), 0)

    def test_memcmp_compares_bytes_unsigned(self):
        # 0xff as an unsigned byte is greater than 0x01.
        self.assertEqual(checker.compare_bytes(b"\xff", b"\x01"), 254)
        self.assertEqual(checker.compare_bytes(b"\x01", b"\xff"), -254)

    def test_length_difference_is_not_memcmp_when_prefix_equal(self):
        self.assertEqual(checker.compare_bytes(b"aaa", b"aaaaa"), -2)
        self.assertEqual(checker.compare_bytes(b"aaaaa", b"aaa"), 2)

    def test_saturation_at_int32_edges(self):
        big = 2147483647
        self.assertEqual(checker.compare_parts(None, big, 0), big)
        self.assertEqual(checker.compare_parts(None, 0, big), -big)
        self.assertEqual(checker.compare_parts(None, big + 1, 0), 2147483647)
        self.assertEqual(checker.compare_parts(None, 0, big + 1), -2147483648)
        self.assertEqual(checker.compare_parts(None, big + 1000, 5),
                         2147483647)
        self.assertEqual(checker.compare_parts(None, 5, big + 1000),
                         -2147483648)
        self.assertEqual(checker.compare_parts(None, 2147483648, 0),
                         2147483647)

    def test_nonzero_prefix_result_ignores_length(self):
        self.assertEqual(checker.compare_parts(7, 0, 10 ** 9), 7)
        self.assertEqual(checker.compare_parts(-3, 10 ** 9, 0), -3)
        self.assertEqual(checker.compare_parts(0, 2, 5), -3)

    def test_64_bit_wrap_of_length_difference(self):
        # len_a - len_b wraps modulo 2**64 before the signed reading.
        self.assertEqual(checker.compare_parts(None, 0, (1 << 64) - 1), 1)
        self.assertEqual(checker.compare_parts(None, 1 << 63, 0),
                         -2147483648)


class CheckerTests(unittest.TestCase):
    def test_checker_passes_on_real_binary(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("digest-verified node #94 binary not present")
        self.assertEqual(checker.check_evidence(ev, binary, PACKET_DIR), [])

    def test_function_range_and_caller_census(self):
        ev, _binary = load_fixture()
        self.assertEqual(ev["function"]["start_va"], "0x514b340")
        self.assertEqual(ev["function"]["end_va_exclusive"], "0x514b38e")
        self.assertEqual(ev["function"]["bytes"], 78)
        self.assertEqual(len(ev["function"]["instructions"]), 25)
        self.assertEqual(
            [c["site"] for c in ev["callers"]],
            ["0x515352c", "0x5153564", "0x51535aa", "0x51535e5",
             "0x51537b9", "0x5153a49", "0x5159629"])
        self.assertEqual(ev["memcmp_call"]["plt_target"], "0x5660150")

    def test_corruption_controls(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("digest-verified node #94 binary not present")
        mutated = copy.deepcopy(ev)
        mutated["function"]["instructions"][0]["bytes"] = "90"
        self.assertNotEqual(
            checker.check_evidence(mutated, binary, PACKET_DIR), [])
        mutated = copy.deepcopy(ev)
        mutated["callers"] = mutated["callers"][:-1]
        self.assertNotEqual(
            checker.check_evidence(mutated, binary, PACKET_DIR), [])
        mutated = copy.deepcopy(ev)
        mutated["memcmp_call"]["plt_target"] = "0x5660151"
        self.assertNotEqual(
            checker.check_evidence(mutated, binary, PACKET_DIR), [])
        mutated = copy.deepcopy(ev)
        mutated["function"]["sha256"] = "0" * 64
        self.assertNotEqual(
            checker.check_evidence(mutated, binary, PACKET_DIR), [])

    def test_sampled_instructions_match_binary(self):
        # Pre-submit self-check: three instructions sampled from
        # evidence.json, verified byte-for-byte against a fresh
        # read of the real binary (not the packet's own excerpts).
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("digest-verified node #94 binary not present")
        sections = checker.elf_sections(binary)
        by_va = {i["va"]: i for i in ev["function"]["instructions"]}
        for va in ("0x514b355", "0x514b35e", "0x514b384"):
            ins = by_va[va]
            got = checker.read_va(binary, sections, int(va, 16),
                                  len(bytes.fromhex(ins["bytes"])))
            self.assertEqual(got.hex(), ins["bytes"])
        self.assertEqual(by_va["0x514b355"]["mnemonic"], "cmovbe")
        self.assertEqual(by_va["0x514b35e"]["mnemonic"], "call")
        self.assertEqual(by_va["0x514b384"]["mnemonic"], "cmovge")


if __name__ == "__main__":
    unittest.main()
