#!/usr/bin/env python3
"""Unit tests for the foundation string move-assign checker.

Stdlib only. Run from the repository root:

    python3 -m unittest tests.test_foundation_string_move_assign -v
"""

import copy
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join("tools"))
import foundation_string_move_assign as checker

EVIDENCE = os.path.join(
    "research", "work-items", "foundation-string-move-assign-94",
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
    def test_heap_to_heap_steals_buffer_and_empties_source(self):
        dest = checker.make_heap(b"old", 32)
        src = checker.make_heap(b"hello", 64)
        old_dest_buf, src_buf = dest.ptr, src.ptr
        checker.move_assign(dest, src)
        self.assertIs(dest.ptr, src_buf)
        self.assertEqual(dest.data(), b"hello")
        self.assertEqual(dest.cap, 64)
        self.assertIs(src.ptr, old_dest_buf)
        self.assertEqual(src.cap, 32)
        self.assertEqual(src.data(), b"")
        self.assertEqual(src.size, 0)

    def test_sso_dest_heap_src_takes_heap_and_source_gets_internal(self):
        dest = checker.make_sso(b"hi")
        src = checker.make_heap(b"world!", 48)
        src_buf = src.ptr
        checker.move_assign(dest, src)
        self.assertIs(dest.ptr, src_buf)
        self.assertEqual(dest.data(), b"world!")
        self.assertIs(src.ptr, dest.internal)
        self.assertEqual(src.data(), b"")
        self.assertEqual(src.size, 0)

    def test_heap_dest_sso_src_copies_and_keeps_dest_buffer(self):
        dest = checker.make_heap(b"old-long-buffer", 64)
        src = checker.make_sso(b"abc")
        dest_buf, src_buf = dest.ptr, src.ptr
        checker.move_assign(dest, src)
        self.assertIs(dest.ptr, dest_buf)
        self.assertEqual(dest.cap, 64)
        self.assertEqual(dest.data(), b"abc")
        self.assertIs(src.ptr, src_buf)
        self.assertEqual(src.data(), b"")

    def test_sso_to_sso_copies_into_internal_buffer(self):
        dest = checker.make_sso(b"zz")
        src = checker.make_sso(b"q")
        checker.move_assign(dest, src)
        self.assertTrue(dest.is_sso())
        self.assertEqual(dest.data(), b"q")
        self.assertTrue(src.is_sso())
        self.assertEqual(src.data(), b"")

    def test_sso_src_empty_and_single_byte_copy(self):
        dest = checker.make_heap(b"keep-buffer", 40)
        src = checker.make_sso(b"")
        checker.move_assign(dest, src)
        self.assertEqual(dest.data(), b"")
        dest2 = checker.make_sso(b"xx")
        src2 = checker.make_sso(b"Z")
        checker.move_assign(dest2, src2)
        self.assertEqual(dest2.data(), b"Z")

    def test_self_move_heap_clears(self):
        s = checker.make_heap(b"self", 16)
        checker.move_assign(s, s)
        self.assertEqual(s.data(), b"")
        self.assertEqual(s.size, 0)

    def test_self_move_sso_clears(self):
        s = checker.make_sso(b"self")
        checker.move_assign(s, s)
        self.assertEqual(s.data(), b"")
        self.assertEqual(s.size, 0)

    def test_null_old_dest_ptr_heap_src_source_becomes_sso(self):
        dest = checker.Str(None, 0, 0, checker.Buffer())
        src = checker.make_heap(b"payload", 24)
        src_buf = src.ptr
        checker.move_assign(dest, src)
        self.assertIs(dest.ptr, src_buf)
        self.assertEqual(dest.data(), b"payload")
        self.assertIs(src.ptr, src.internal)
        self.assertEqual(src.data(), b"")

    def test_copy_arm_leaves_dest_capacity_untouched(self):
        dest = checker.make_heap(b"short", 128)
        src = checker.make_sso(b"longer-than-before")
        checker.move_assign(dest, src)
        self.assertEqual(dest.cap, 128)
        self.assertEqual(dest.data(), b"longer-than-before")


class BinaryTests(unittest.TestCase):
    def test_checker_passes_on_target_binary(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        self.assertTrue(checker.check(ev, binary, packet_dir=PACKET_DIR))

    def test_function_bytes_reproduce_from_binary(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        body = checker.read_at(
            binary, checker.FUNCTION_START, ev["function"]["bytes"])
        self.assertEqual(
            hashlib.sha256(body).hexdigest(), ev["function"]["sha256"])

    def test_sampled_instructions_match_fresh_binary_read(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        by_va = {i["va"]: i for i in ev["function"]["instructions"]}
        # entry push, the memcpy call, and the terminator store.
        for va, want in (("0x514b4f0", "55"),
                         ("0x514b580", "e87b4b5100"),
                         ("0x514b591", "c6041700")):
            ins = by_va[va]
            self.assertEqual(ins["bytes"], want)
            raw = checker.read_at(binary, int(va, 16), len(bytes.fromhex(want)))
            self.assertEqual(raw.hex(), want)

    def test_caller_census_reproduces_from_binary(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        self.assertEqual(checker.caller_census(binary),
                         checker.EXPECTED_CALLERS)
        self.assertEqual(len(ev["callers"]), 20)

    def test_corruption_controls(self):
        ev, binary = load_fixture()
        if binary is None:
            self.skipTest("no digest-matching node #94 binary available")
        # Flipped function byte.
        bad = bytearray(binary)
        off = checker.va_to_offset(binary, checker.FUNCTION_START)
        bad[off] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.check(ev, bytes(bad), packet_dir=PACKET_DIR)
        # Flipped memcpy call target.
        bad = bytearray(binary)
        off = checker.va_to_offset(binary, checker.MEMCPY_CALL)
        bad[off + 1] ^= 0xFF
        with self.assertRaises(ValueError):
            checker.check(ev, bytes(bad), packet_dir=PACKET_DIR)
        # Dropped caller record.
        ev2 = copy.deepcopy(ev)
        ev2["callers"] = ev2["callers"][:-1]
        with self.assertRaises(ValueError):
            checker.check(ev2, binary, packet_dir=PACKET_DIR)
        # Broken manifest hash.
        manifest = os.path.join(PACKET_DIR, "MANIFEST.sha256")
        with open(manifest) as fh:
            original = fh.read()
        try:
            with open(manifest, "w") as fh:
                fh.write(original.replace("a", "b", 1))
            with self.assertRaises(ValueError):
                checker.check(ev, binary, packet_dir=PACKET_DIR)
        finally:
            with open(manifest, "w") as fh:
                fh.write(original)
