"""Tests for node #94's decimal-index replace at 0x514b390 (RE-001)."""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from foundation_decimal_index_replace import (
    check, decimal_index_replace, parse_decimal, parse_objdump_window, table_count)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(
    ROOT, "research", "work-items", "foundation-decimal-index-replace-94",
    "evidence.json")
BINARY = os.path.join(ROOT, "artifacts", "node", "94", "hl-node")
TABLE = [(0, 40), (100, 124), (200, 216)]  # counts: 5, 3, 2


class TestParser(unittest.TestCase):
    def test_objdump_continuation_is_part_of_previous_instruction(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = os.path.join(temporary, "excerpt.txt")
            with open(path, "w") as handle:
                handle.write(" 514b3b5:\t64 48 8b 04 25 28 00 \tmov %fs:0x28,%rax\n"
                             " 514b3bc:\t00 00 \n"
                             " 514b3be:\t48 89 84 24 08 01 00 \tmov %rax,0x108(%rsp)\n"
                             " 514b3c5:\t00 \n")
            rows = parse_objdump_window(path)
        self.assertEqual(rows[0x514b3b5][0], "64488b042528000000")
        self.assertEqual(rows[0x514b3be][0], "4889842408010000")
        self.assertNotIn(0x514b3bc, rows)

    def test_empty_returns_zero(self):
        self.assertEqual(parse_decimal(b""), (False, 0, 0, True, 0))

    def test_zero_and_leading_zeroes(self):
        self.assertEqual(parse_decimal(b"0"), (True, 0, 1, True, 0))
        self.assertEqual(parse_decimal(b"007"), (True, 7, 3, True, 7))

    def test_plain_value(self):
        self.assertEqual(parse_decimal(b"42"), (True, 42, 2, True, 42))

    def test_trailing_junk_stops_without_consuming_it(self):
        self.assertEqual(parse_decimal(b"12a"), (True, 12, 2, True, 12))

    def test_leading_junk_returns_zero(self):
        self.assertEqual(parse_decimal(b"a"), (False, 0, 0, True, 0))

    def test_uint64_max_accepted(self):
        self.assertEqual(parse_decimal(b"18446744073709551615"),
                         (True, 18446744073709551615, 20, True,
                          18446744073709551615))

    def test_uint64_max_plus_one_overflows_without_writing_out(self):
        ok, value, consumed, written, out = parse_decimal(b"18446744073709551616")
        self.assertFalse(ok)
        self.assertIsNone(value)
        self.assertEqual(consumed, 19)
        self.assertFalse(written)
        self.assertIsNone(out)


class TestEntry(unittest.TestCase):
    def test_replace_with_formatted_count(self):
        self.assertEqual(decimal_index_replace(5, TABLE, b"1"), (1, "3"))

    def test_index_zero(self):
        self.assertEqual(decimal_index_replace(5, TABLE, b"0"), (1, "5"))

    def test_threshold_equal_fails(self):
        self.assertEqual(decimal_index_replace(5, TABLE, b"5"), (0, None))

    def test_threshold_below_fails(self):
        self.assertEqual(decimal_index_replace(2, TABLE, b"2"), (0, None))

    def test_trailing_junk_fails(self):
        self.assertEqual(decimal_index_replace(5, TABLE, b"1x"), (0, None))

    def test_empty_input_fails(self):
        self.assertEqual(decimal_index_replace(5, TABLE, b""), (0, None))

    def test_negative_index_is_out_of_modelled_domain(self):
        # Low32 0xFFFFFFFF sign-extends to -1, which passes a threshold
        # of 5 in the bytes but reads before the table: no value claimed.
        with self.assertRaises(ValueError):
            decimal_index_replace(5, TABLE, b"4294967295")

    def test_negative_table_difference(self):
        self.assertEqual(table_count(200, 100), -13)

    def test_checker_passes_on_real_binary(self):
        self.assertEqual(check(EVIDENCE, BINARY), [])

    def _corrupted_copy(self, mutate):
        tmp = tempfile.mkdtemp()
        packet = os.path.join(tmp, "packet")
        shutil.copytree(os.path.dirname(EVIDENCE), packet)
        ev_path = os.path.join(packet, "evidence.json")
        with open(ev_path) as f:
            ev = json.load(f)
        mutate(ev)
        with open(ev_path, "w") as f:
            json.dump(ev, f, indent=2)
        return ev_path

    def test_corruption_wrong_entry_byte_fails(self):
        path = self._corrupted_copy(
            lambda ev: ev["entry"]["instructions"][0].__setitem__("bytes", "90909090"))
        self.assertTrue(check(path, BINARY))

    def test_corruption_wrong_parser_byte_fails(self):
        path = self._corrupted_copy(
            lambda ev: ev["parser"]["instructions"][0].__setitem__("bytes", "90909090"))
        self.assertTrue(check(path, BINARY))

    def test_corruption_wrong_format_fails(self):
        path = self._corrupted_copy(
            lambda ev: ev["format"].__setitem__("address", "0x1f6ff3"))
        self.assertTrue(check(path, BINARY))

    def test_corruption_manifest_hash_fails(self):
        tmp = tempfile.mkdtemp()
        packet = os.path.join(tmp, "packet")
        shutil.copytree(os.path.dirname(EVIDENCE), packet)
        with open(os.path.join(packet, "README.md"), "a") as f:
            f.write("\ntampered\n")
        self.assertTrue(check(os.path.join(packet, "evidence.json"), BINARY))


if __name__ == "__main__":
    unittest.main()
