#!/usr/bin/env python3
"""Tests for node #94 two-piece string concat at 0x514bbb0 (RE-001).

Covers the model in tools/foundation_string_concat_two.py, the
packet verifier, and the independent tools checker, including
corruption controls that must make the checkers fail.
"""

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(
    REPO_ROOT, "research", "work-items", "RE-001-string-concat-two-94")
BINARY = os.path.join(REPO_ROOT, "artifacts", "node", "94", "hl-node")

sys.path.insert(0, REPO_ROOT)

from tools.foundation_string_concat_two import (  # noqa: E402
    MAX_SIZE, LengthError_, check_binary, concat_two, reserve_total)


def load_packet_verify():
    spec = importlib.util.spec_from_file_location(
        "concat_verify", os.path.join(PACKET_DIR, "verify.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModelTest(unittest.TestCase):
    def test_empty_pieces(self):
        self.assertEqual(concat_two(b"", 0, b"", 0), b"")

    def test_plain_concat(self):
        self.assertEqual(concat_two(b"hello", 5, b"world", 5),
                         b"helloworld")

    def test_lengths_truncate(self):
        self.assertEqual(concat_two(b"hello!", 5, b"world!", 5),
                         b"helloworld")

    def test_zero_first_piece(self):
        self.assertEqual(concat_two(b"ignored", 0, b"abc", 3), b"abc")

    def test_zero_second_piece(self):
        self.assertEqual(concat_two(b"abc", 3, b"ignored", 0), b"abc")

    def test_first_piece_at_max(self):
        self.assertEqual(concat_two(b"x", MAX_SIZE, b"", 0), b"x")

    def test_first_piece_over_max_throws(self):
        with self.assertRaises(LengthError_):
            concat_two(b"x", MAX_SIZE + 1, b"", 0)

    def test_second_piece_exact_fit(self):
        self.assertEqual(concat_two(b"ab", 2, b"cdef", MAX_SIZE - 2),
                         b"abcdef")

    def test_second_piece_one_over_throws(self):
        with self.assertRaises(LengthError_):
            concat_two(b"ab", 2, b"c", MAX_SIZE - 1)

    def test_reserve_total_plain(self):
        self.assertEqual(reserve_total(5, 7), 12)

    def test_reserve_total_wraps(self):
        # Arithmetic only: successful paths never wrap, because both
        # appends enforce len1 + len2 <= MAX_SIZE first.
        self.assertEqual(reserve_total(2 ** 64 - 1, 1), 0)


class BinaryTest(unittest.TestCase):
    def test_tools_checker_passes(self):
        self.assertEqual(check_binary(BINARY), [])

    def test_packet_verifier_passes(self):
        module = load_packet_verify()
        self.assertEqual(module.main(["--binary", BINARY]), 0)

    def test_sampled_instructions_match_binary(self):
        # Byte-for-byte spot check of three excerpt instructions
        # against a fresh read of the real binary.
        with open(BINARY, "rb") as f:
            data = f.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d"
                         "575eff1c0459f")
        module = load_packet_verify()
        elf = module.Elf(data)
        # lea out+0x10 at the function entry.
        self.assertEqual(elf.read(0x514BBB0, 4), bytes.fromhex("488d4710"))
        # reserve call at 0x514bbde targets the reserve PLT stub.
        self.assertEqual(module.call_target(elf, 0x514BBDE), 0x5660610)
        # first throw-arm lea targets the throw string.
        self.assertEqual(module.lea_target(elf, 0x514BC31), 0x1F822D)

    def test_excerpt_regeneration_is_stable(self):
        before = {}
        for name in ("window.objdump.txt", "landing.objdump.txt",
                     "callers.objdump.txt", "plt.objdump.txt"):
            with open(os.path.join(PACKET_DIR, name), "rb") as f:
                before[name] = hashlib.sha256(f.read()).hexdigest()
        # Relative binary path: objdump embeds the path in the
        # excerpt header, so an absolute path would change the
        # hashes (the same trap prior packets fixed).
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET_DIR, "export_excerpts.py"),
             "--binary", os.path.join("artifacts", "node", "94", "hl-node")],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, digest in before.items():
            with open(os.path.join(PACKET_DIR, name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest,
                                 name)

    def test_tampered_records_fail_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            verify = os.path.join(copy, "verify.py")
            # Point the copy's verifier at its own directory by
            # running it in place (PACKET_DIR is derived from the
            # script path), with a tampered digest in records.json.
            import json
            path = os.path.join(copy, "records.json")
            with open(path) as f:
                records = json.load(f)
            records["target_sha256"] = "0" * 64
            with open(path, "w") as f:
                json.dump(records, f)
            result = subprocess.run(
                [sys.executable, verify, "--binary", BINARY],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_tampered_manifest_fails_verifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            manifest = os.path.join(copy, "MANIFEST.sha256")
            with open(manifest) as f:
                lines = f.readlines()
            digest, name = lines[0].split()
            lines[0] = "0" * 64 + " " + name + "\n"
            with open(manifest, "w") as f:
                f.writelines(lines)
            result = subprocess.run(
                [sys.executable, os.path.join(copy, "verify.py"),
                 "--binary", BINARY],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_tampered_excerpt_fails_tools_checker(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET_DIR, copy)
            window = os.path.join(copy, "window.objdump.txt")
            with open(window) as f:
                text = f.read()
            # Flip one byte in the first instruction's byte field.
            text = text.replace("48 8d 47 10", "48 8d 47 11", 1)
            with open(window, "w") as f:
                f.write(text)
            module = load_packet_verify()
            # The tools checker reads the packet from its own fixed
            # location, so exercise the same excerpt-byte logic
            # through a copied module namespace instead: patch the
            # packet dir used by the tools module.
            import tools.foundation_string_concat_two as tool
            old = tool.PACKET_DIR
            tool.PACKET_DIR = copy
            try:
                errors = tool.check_binary(BINARY)
            finally:
                tool.PACKET_DIR = old
            self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
