#!/usr/bin/env python3
"""Tests for RE-001 range sum (function 0x514bc60, node #94).

Run from the repository root:

    python3 tests/test_foundation_range_sum.py

The binary path defaults to the digest-verified work copy; pass
``--binary`` to point at another copy of node #94.  All expectations
are read from the bytes: the per-entry contribution is field + 62,
the sum wraps at 64 bits, the empty range stores 0, and the function
always returns 1.
"""

import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.foundation_range_sum import (  # noqa: E402
    CALLEE_ADDEND, Target, callee, check_packet, range_sum)

PACKET_DIR = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-range-sum-94")
DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
BINARY = os.environ.get("HL_NODE94_BIN", DEFAULT_BINARY)


class CalleeTests(unittest.TestCase):
    def test_addend_is_62(self):
        self.assertEqual(CALLEE_ADDEND, 0x3E)
        self.assertEqual(callee(Target(0)), 62)
        self.assertEqual(callee(Target(100)), 162)

    def test_callee_wraps_at_64_bits(self):
        self.assertEqual(callee(Target((1 << 64) - 1)), 61)
        self.assertEqual(callee(Target((1 << 64) - 62)), 0)


class RangeSumTests(unittest.TestCase):
    def test_empty_range_stores_zero_and_returns_one(self):
        self.assertEqual(range_sum([]), (1, 0))

    def test_single_entry(self):
        self.assertEqual(range_sum([Target(10)]), (1, 72))

    def test_multiple_entries_in_order(self):
        # Order does not change the sum, but the model walks in order.
        targets = [Target(0), Target(1), Target(2), Target(1000)]
        self.assertEqual(range_sum(targets), (1, 0 + 62 + 63 + 64 + 1062))

    def test_second_entry_qword_is_ignored(self):
        # The model takes one target per 16-byte entry; the entry's
        # +0x8 qword never reaches the callee in the bytes, so there
        # is no second input per entry to vary.
        self.assertEqual(range_sum([Target(5), Target(5)]), (1, 2 * 67))

    def test_sum_wraps_at_64_bits(self):
        big = (1 << 64) - 10
        ret, total = range_sum([Target(big), Target(100)])
        # (big + 62) wraps to 52; 52 + (100 + 62) = 214.
        self.assertEqual((ret, total), (1, 214))

    def test_zero_fields_still_add_the_constant(self):
        self.assertEqual(range_sum([Target(0)] * 3), (1, 186))

    def test_negative_looking_field_is_unsigned(self):
        # A field with the top bit set is a large unsigned qword,
        # not a negative number: 2**63 + 62, no sign extension.
        self.assertEqual(
            range_sum([Target(1 << 63)]), (1, (1 << 63) + 62))


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
        import hashlib
        import subprocess
        import tempfile
        packet_dir = os.path.abspath(PACKET_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            # Run the generator into a scratch copy of the packet dir
            # layout by invoking it with cwd tricks: it writes next to
            # itself, so instead compare its stdout contract by
            # re-running objdump directly for both ranges.
            for name, start, stop in (
                    ("window.objdump.txt", "0x514bc60", "0x514bcd0"),
                    ("callee.objdump.txt", "0x5032f40", "0x5032f4d")):
                result = subprocess.run(
                    ["objdump", "-d", "--start-address=%s" % start,
                     "--stop-address=%s" % stop, BINARY],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0)
                with open(os.path.join(packet_dir, name), "rb") as f:
                    shipped = f.read()
                self.assertEqual(
                    hashlib.sha256(result.stdout.encode()).hexdigest(),
                    hashlib.sha256(shipped).hexdigest(),
                    "%s excerpt differs from a fresh objdump run" % name)


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
