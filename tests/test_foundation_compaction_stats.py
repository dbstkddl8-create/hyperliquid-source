#!/usr/bin/env python3
"""Unit tests for the foundation compaction-stats checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_compaction_stats -v
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_compaction_stats as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-compaction-stats-94",
    "evidence.json")
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


def full_container():
    pairs = [(key, "v%d" % key) for key in checker.KEY_DOMAIN]
    return checker.make_container(pairs)


class ModelTests(unittest.TestCase):
    def test_key_domain_is_one_to_twenty_one_without_two(self):
        self.assertEqual(checker.KEY_DOMAIN,
                         [k for k in range(1, 22) if k != 2])
        self.assertNotIn(2, checker.KEY_DOMAIN)
        self.assertEqual(len(checker.KEY_DOMAIN), 20)

    def test_map_at_hit_and_miss(self):
        container = full_container()
        self.assertEqual(checker.map_at(container, 21), "v21")
        self.assertEqual(checker.map_at(container, 1), "v1")
        container["nodes"].pop(13)
        # Removing a node from the model dict breaks the links too;
        # rebuild without key 13 instead.
        container = checker.make_container(
            [(k, "v%d" % k) for k in checker.KEY_DOMAIN if k != 13])
        with self.assertRaises(checker.OutOfRange):
            checker.map_at(container, 13)

    def test_map_at_empty_tree_throws(self):
        container = checker.make_container([])
        with self.assertRaises(checker.OutOfRange):
            checker.map_at(container, 1)

    def test_successor_requires_exact_next_key(self):
        container = checker.make_container([(3, "v3"), (5, "v5")])
        # Sought 3, next key is 5, not 4: the inline block throws.
        with self.assertRaises(checker.OutOfRange):
            checker.successor_lookup(container, 3)
        # Sought 4, next key is exactly 5: accepted.
        self.assertEqual(checker.successor_lookup(container, 4), "v5")

    def test_successor_differs_from_exact_match(self):
        # Key 3 present but 4 absent: successor lookup for sought 3
        # throws even though an exact map::at(3) would succeed.
        container = checker.make_container([(3, "v3")])
        self.assertEqual(checker.map_at(container, 3), "v3")
        with self.assertRaises(checker.OutOfRange):
            checker.successor_lookup(container, 3)

    def test_collect_row_order_and_first_column(self):
        container = full_container()
        row = checker.collect_row(container, "FIRST")
        self.assertEqual(len(row), 21)
        self.assertEqual(row[0], "FIRST")
        self.assertEqual(row[1:], ["v%d" % k for k in checker.KEY_DOMAIN])

    def test_collect_row_missing_any_key_throws(self):
        for missing in checker.KEY_DOMAIN:
            container = checker.make_container(
                [(k, "v%d" % k) for k in checker.KEY_DOMAIN
                 if k != missing])
            with self.assertRaises(checker.OutOfRange):
                checker.collect_row(container, "FIRST")

    def test_collect_row_ignores_key_two(self):
        # Key 2 is not in the domain: its presence or absence must
        # not change the row.
        container = checker.make_container(
            [(k, "v%d" % k) for k in checker.KEY_DOMAIN] + [(2, "v2")])
        self.assertEqual(checker.collect_row(container, "FIRST"),
                         checker.collect_row(full_container(), "FIRST"))

    def test_render_shape_and_separator(self):
        out = checker.render_row("nodeA", "FIRST", full_container())
        lines = out.split("\n")
        self.assertEqual(lines[0], "")
        self.assertEqual(lines[1], "** Compaction Stats [nodeA] **")
        self.assertEqual(lines[2].split(), ["FIRST"] +
                         ["v%d" % k for k in checker.KEY_DOMAIN])
        row = lines[2] + "\n"
        self.assertEqual(lines[3], "-" * len(row))
        self.assertEqual(lines[4], "")

    def test_render_clamps_to_buffer_budget(self):
        container = full_container()
        long_name = "n" * 3000
        out = checker.render_row(long_name, "FIRST", container)
        self.assertLessEqual(len(out), 2000)
        self.assertTrue(out.startswith("\n** Compaction Stats ["))

    def test_signed_key_edges(self):
        container = checker.make_container([(-5, "neg"), (0, "zero"),
                                            (2147483647, "max")])
        self.assertEqual(checker.map_at(container, -5), "neg")
        self.assertEqual(checker.map_at(container, 2147483647), "max")
        with self.assertRaises(checker.OutOfRange):
            checker.map_at(container, -6)
        with self.assertRaises(checker.OutOfRange):
            checker.successor_lookup(container, 2147483647)


class BinaryTests(unittest.TestCase):
    def test_checker_passes_on_real_binary(self):
        ev, binary = load_fixture()
        self.assertIsNotNone(binary, "digest-verified binary not found")
        sections = checker.elf_sections(binary)
        packet_dir = os.path.dirname(EVIDENCE)
        for name, fn in checker.CHECKS:
            self.assertIsNone(fn(ev, binary, sections, packet_dir), name)

    def test_checker_cli_passes(self):
        binary = load_binary()
        self.assertIsNotNone(binary)
        result = subprocess.run(
            [sys.executable, "tools/foundation_compaction_stats.py",
             "--check", EVIDENCE, "--binary",
             WORK_BINARY if os.path.exists(WORK_BINARY)
             else ARTIFACTS_BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_sampled_instructions_match_fresh_objdump(self):
        # Pre-submit self-check: three instructions re-verified
        # byte-for-byte against a fresh objdump run on the real binary.
        samples = {
            "514d7cb": "e8f0d9ffff",
            "514db62": "e859d6ffff",
            "514dc14": "e8d7295100",
        }
        result = subprocess.run(
            ["objdump", "-d", "--start-address=0x514d770",
             "--stop-address=0x514dcdc", ARTIFACTS_BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        for va, hexbytes in samples.items():
            line = [ln for ln in result.stdout.splitlines()
                    if ln.strip().startswith(va + ":")]
            self.assertEqual(len(line), 1, va)
            parts = line[0].split("\t")
            shown = "".join(parts[1].split())
            self.assertEqual(shown, hexbytes, va)

    def test_multi_line_instruction_bytes_are_complete(self):
        expected = {
            "0x514d7a2": "64488b042528000000",
            "0x514d7ab": "48898424b8000000",
            "0x514da3d": "4889b42480000000",
            "0x514dafe": "4889b42488000000",
            "0x514dc19": "4c8dac2430010000",
        }
        with open(EVIDENCE) as handle:
            evidence = json.load(handle)
        by_va = {row["va"]: row for row in evidence["function"]["instructions"]}
        for va, raw in expected.items():
            self.assertEqual(by_va[va]["bytes"], raw, va)

    def test_truncated_instruction_record_is_rejected(self):
        with open(EVIDENCE) as handle:
            evidence = json.load(handle)
        record = next(row for row in evidence["function"]["instructions"]
                      if row["va"] == "0x514d7a2")
        record["bytes"] = record["bytes"][:14]
        binary = load_binary()
        sections = checker.elf_sections(binary)
        self.assertIsNotNone(checker.check_instructions(
            evidence, binary, sections, os.path.dirname(EVIDENCE)))

    def test_corruption_controls(self):
        ev, binary = load_fixture()
        self.assertIsNotNone(binary)
        sections = checker.elf_sections(binary)
        packet_dir = os.path.dirname(EVIDENCE)
        # A flipped function byte breaks the body check.
        bad = bytearray(binary)
        addr, offset, size = checker.text_section(binary, sections)
        bad[offset + (0x514D770 - addr)] ^= 0xFF
        self.assertIsNotNone(
            checker.check_function(ev, bytes(bad), sections, packet_dir))
        # A wrong call census breaks the caller check.
        ev2 = copy.deepcopy(ev)
        ev2["consumer_callers"] = ev2["consumer_callers"][:1]
        self.assertIsNotNone(
            checker.check_callers(ev2, binary, sections, packet_dir))
        # A wrong key domain breaks the domain check.
        ev3 = copy.deepcopy(ev)
        ev3["key_domain"] = ev3["key_domain"] + [2]
        self.assertIsNotNone(
            checker.check_key_domain(ev3, binary, sections, packet_dir))
        # A wrong row order breaks the domain check.
        ev4 = copy.deepcopy(ev)
        cols = ev4["row_columns"]
        cols[1], cols[2] = cols[2], cols[1]
        self.assertIsNotNone(
            checker.check_key_domain(ev4, binary, sections, packet_dir))


if __name__ == "__main__":
    unittest.main()
