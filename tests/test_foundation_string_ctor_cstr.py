#!/usr/bin/env python3
"""Tests for node #94 string construction from a C string (RE-001).

Covers the model in tools/foundation_string_ctor_cstr.py, the
packet verifier, and the independent tools checker, including
corruption controls that must make the checkers fail.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    REPO_ROOT, "research", "work-items", "RE-001-string-ctor-cstr-94")
BINARY = os.path.join(REPO_ROOT, "work", "hl-node-94.bin")

sys.path.insert(0, REPO_ROOT)

from tools.foundation_string_ctor_cstr import (  # noqa: E402
    LogicError, StringObject, check as tools_check, construct)


def load_packet_verify():
    spec = importlib.util.spec_from_file_location(
        "ctor_verify", os.path.join(PACKET_DIR, "verify.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModelTests(unittest.TestCase):
    def test_null_raises_with_exact_message(self):
        with self.assertRaises(LogicError) as caught:
            construct(None)
        self.assertEqual(
            str(caught.exception),
            "basic_string: construction from null is not valid")

    def test_empty_is_sso(self):
        obj = construct(b"")
        self.assertFalse(obj.is_heap)
        self.assertEqual(obj.pointer, "sso")
        self.assertEqual(obj.length, 0)
        self.assertEqual(obj.content, b"")
        self.assertEqual(obj.capacity_or_buffer, b"\x00")

    def test_single_byte_uses_sso(self):
        obj = construct(b"a")
        self.assertFalse(obj.is_heap)
        self.assertEqual(obj.length, 1)
        self.assertEqual(obj.content, b"a")
        self.assertEqual(obj.capacity_or_buffer, b"a\x00")

    def test_short_sso_content(self):
        obj = construct(b"hello")
        self.assertFalse(obj.is_heap)
        self.assertEqual(obj.length, 5)
        self.assertEqual(obj.content, b"hello")
        self.assertEqual(obj.capacity_or_buffer, b"hello\x00")

    def test_length_15_boundary_is_sso(self):
        obj = construct(b"0123456789abcde")
        self.assertFalse(obj.is_heap)
        self.assertEqual(obj.length, 15)

    def test_length_16_boundary_is_heap(self):
        obj = construct(b"0123456789abcdef")
        self.assertTrue(obj.is_heap)
        self.assertEqual(obj.length, 16)
        self.assertEqual(obj.capacity_or_buffer, 16)
        self.assertEqual(obj.content, b"0123456789abcdef")

    def test_long_heap(self):
        payload = bytes(range(1, 101))
        obj = construct(payload)
        self.assertTrue(obj.is_heap)
        self.assertEqual(obj.length, 100)
        self.assertEqual(obj.capacity_or_buffer, 100)
        self.assertEqual(obj.content, payload)

    def test_nul_truncates_like_strlen(self):
        obj = construct(b"abc\x00defgh")
        self.assertEqual(obj.content, b"abc")
        self.assertEqual(obj.length, 3)

    def test_heap_pointer_differs_from_sso_buffer(self):
        heap = construct(b"x" * 20)
        sso = construct(b"x" * 5)
        self.assertNotEqual(heap.pointer, sso.pointer)
        self.assertEqual(sso.pointer, "sso")


class CheckerTests(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_packet_verify_passes(self):
        verify = load_packet_verify()
        failures = verify.check(
            os.path.join(PACKET_DIR, "records.json"), BINARY, PACKET_DIR)
        self.assertEqual(failures, [])

    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_tools_checker_passes(self):
        self.assertEqual(tools_check(PACKET_DIR, BINARY), [])

    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_both_checkers_pass_via_subprocess(self):
        for script in ("verify.py",):
            result = subprocess.run(
                [sys.executable,
                 os.path.join(PACKET_DIR, script),
                 "--binary", BINARY],
                capture_output=True, text=True, cwd=REPO_ROOT)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("ALL CHECKS PASSED", result.stdout)
        result = subprocess.run(
            [sys.executable, "tools/foundation_string_ctor_cstr.py",
             "--binary", BINARY],
            capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_corruption_controls(self):
        verify = load_packet_verify()
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            records_path = os.path.join(copy, "records.json")

            def tampered_records(mutate):
                with open(records_path) as f:
                    rec = json.load(f)
                mutate(rec)
                with open(records_path, "w") as f:
                    json.dump(rec, f)

            # Tampered function SHA must fail the packet verifier.
            tampered_records(
                lambda r: r["function"].__setitem__("sha256", "0" * 64))
            self.assertNotEqual(
                verify.check(records_path, BINARY, copy), [])
            shutil.copytree(PACKET_DIR, copy, dirs_exist_ok=True)

            # A dropped caller must fail the census check.
            tampered_records(lambda r: r["callers_e8"].pop())
            self.assertNotEqual(
                verify.check(records_path, BINARY, copy), [])
            shutil.copytree(PACKET_DIR, copy, dirs_exist_ok=True)

            # A tampered manifest hash must fail the verifier.
            manifest = os.path.join(copy, "MANIFEST.sha256")
            with open(manifest) as f:
                lines = f.read().splitlines()
            digest, name = lines[0].split()
            lines[0] = "0" * 64 + " " + name
            with open(manifest, "w") as f:
                f.write("\n".join(lines) + "\n")
            self.assertNotEqual(
                verify.check(records_path, BINARY, copy), [])
            shutil.copytree(PACKET_DIR, copy, dirs_exist_ok=True)

            # A tampered excerpt byte must fail the tools checker.
            window = os.path.join(copy, "window.objdump.txt")
            with open(window) as f:
                text = f.read()
            lines = text.splitlines(keepends=True)
            for i, line in enumerate(lines):
                if ":\t" in line and i > 3:
                    head, rest = line.split(":\t", 1)
                    tokens = rest.split("\t")
                    byte_tokens = tokens[0].split()
                    byte_tokens[0] = "00" if byte_tokens[0] != "00" else "ff"
                    lines[i] = head + ":\t" + " ".join(byte_tokens)
                    if len(tokens) > 1:
                        lines[i] += "\t" + "\t".join(tokens[1:])
                    break
            with open(window, "w") as f:
                f.write("".join(lines))
            self.assertNotEqual(tools_check(copy, BINARY), [])


if __name__ == "__main__":
    unittest.main()
