#!/usr/bin/env python3
"""Tests for RE-001 field sum (function 0x514bcd0, node #94).

Run from the repository root:

    python3 tests/test_foundation_field_sum.py

The binary path defaults to the canonical captured artifact; pass
``--binary`` to point at another copy of node #94.  All expectations
are read from the bytes: the per-entry contribution is the qword at
[slot + 0x50], the callee return is discarded, the sum wraps at 64
bits, the empty range stores 0, and the function always returns 1.
"""

import argparse
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.foundation_field_sum import (  # noqa: E402
    CALLEE_ADDEND, Entry, callee, check_packet, field_sum)

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-field-sum-94")
DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
BINARY = os.environ.get("HL_NODE94_BIN", DEFAULT_BINARY)


class CalleeTests(unittest.TestCase):
    def test_addend_is_62(self):
        self.assertEqual(CALLEE_ADDEND, 0x3E)
        self.assertEqual(callee(Entry(0, 0)), 62)
        self.assertEqual(callee(Entry(100, 0)), 162)

    def test_callee_wraps_at_64_bits(self):
        self.assertEqual(callee(Entry((1 << 64) - 1, 0)), 61)
        self.assertEqual(callee(Entry((1 << 64) - 62, 0)), 0)


class FieldSumTests(unittest.TestCase):
    def test_empty_range_stores_zero_and_returns_one(self):
        self.assertEqual(field_sum([]), (1, 0, 0))

    def test_single_entry(self):
        self.assertEqual(field_sum([Entry(10, 5)]), (1, 5, 1))

    def test_multiple_entries_in_order(self):
        entries = [Entry(0, 0), Entry(1, 1), Entry(2, 2), Entry(1000, 1000)]
        self.assertEqual(field_sum(entries), (1, 0 + 1 + 2 + 1000, 4))

    def test_callee_return_is_discarded(self):
        # Same +0x50 fields, wildly different callee fields: the total
        # must not move, because the bytes overwrite the callee return
        # with the reloaded slot before adding the +0x50 field.
        a = [Entry(0, 7), Entry(0, 8)]
        b = [Entry((1 << 64) - 1, 7), Entry(123456, 8)]
        self.assertEqual(field_sum(a), (1, 15, 2))
        self.assertEqual(field_sum(b), (1, 15, 2))
        # And a callee return that differs from the field must not
        # leak into the total: callee(Entry(100, 0)) is 162, but the
        # entry contributes its field50 of 0, not 162.
        self.assertEqual(field_sum([Entry(100, 0)]), (1, 0, 1))

    def test_sum_wraps_at_64_bits(self):
        big = (1 << 64) - 10
        ret, total, calls = field_sum([Entry(0, big), Entry(0, 100)])
        self.assertEqual((ret, total, calls), (1, 90, 2))

    def test_zero_fields_still_count_calls(self):
        self.assertEqual(field_sum([Entry(0, 0)] * 3), (1, 0, 3))

    def test_field50_is_unsigned(self):
        # A field with the top bit set is a large unsigned qword,
        # not a negative number.
        self.assertEqual(
            field_sum([Entry(0, 1 << 63)]), (1, 1 << 63, 1))

    def test_callee_called_once_per_entry(self):
        entries = [Entry(i, i) for i in range(5)]
        ret, total, calls = field_sum(entries)
        self.assertEqual(calls, 5)
        self.assertEqual((ret, total), (1, 0 + 1 + 2 + 3 + 4))


class PacketTests(unittest.TestCase):
    def test_packet_verifies_against_binary(self):
        errors = check_packet(PACKET_DIR, BINARY)
        self.assertEqual(errors, [])

    def test_packet_verify_script_passes(self):
        import subprocess
        packet_verify = os.path.join(PACKET_DIR, "verify.py")
        result = subprocess.run(
            [sys.executable, packet_verify, "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    def test_excerpts_regenerate_byte_identically(self):
        import shutil
        import subprocess
        import tempfile
        packet_dir = os.path.abspath(PACKET_DIR)
        names = ("window.objdump.txt", "callee.objdump.txt")
        before = {}
        for name in names:
            with open(os.path.join(packet_dir, name), "rb") as f:
                before[name] = f.read()
        with tempfile.TemporaryDirectory() as temporary:
            copied = os.path.join(temporary, "packet")
            shutil.copytree(packet_dir, copied)
            result = subprocess.run(
                [sys.executable, os.path.join(copied, "export_excerpts.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pattern = rb"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s|$))+)"
            rows = lambda raw: [(va, b"".join(code.split())) for va, code in
                                re.findall(pattern, raw, re.M)]
            for name in names:
                with open(os.path.join(copied, name), "rb") as f:
                    fresh = f.read()
                self.assertTrue(rows(fresh), name)
                self.assertEqual(rows(fresh), rows(before[name]), name)
        for name in names:
            with open(os.path.join(packet_dir, name), "rb") as f:
                self.assertEqual(f.read(), before[name], name)


class CorruptionTests(unittest.TestCase):
    def test_corrupted_manifest_is_caught(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(os.path.abspath(PACKET_DIR), copy_dir)
            manifest = os.path.join(copy_dir, "MANIFEST.sha256")
            with open(manifest, "a") as f:
                f.write("0" * 64 + "  window.objdump.txt\n")
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(
                any("MANIFEST" in e for e in errors),
                "corrupted manifest was not caught: %r" % (errors,))

    def test_corrupted_excerpt_is_caught(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy_dir = os.path.join(tmp, "packet")
            shutil.copytree(os.path.abspath(PACKET_DIR), copy_dir)
            excerpt = os.path.join(copy_dir, "window.objdump.txt")
            with open(excerpt) as f:
                text = f.read()
            # Flip one byte hex token on the entry line.
            text = text.replace("f3 0f 1e fa", "f3 0f 1e fb", 1)
            with open(excerpt, "w") as f:
                f.write(text)
            errors = check_packet(copy_dir, BINARY)
            self.assertTrue(
                any("excerpt" in e for e in errors),
                "corrupted excerpt was not caught: %r" % (errors,))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=BINARY)
    args, rest = ap.parse_known_args()
    BINARY = args.binary
    unittest.main(argv=[sys.argv[0]] + rest)
