#!/usr/bin/env python3
"""Tests for node #94's _Sp_counted_ptr_inplace _M_get_deleter 0x514b5d0 (RE-001).

End-to-end through the model (type_info in, stored-object address or
null out), plus binary reproduction and corruption controls against
the digest-verified work copy. Stdlib only; run from the repository
root: python3 -m unittest tests.test_foundation_sp_counted_get_deleter -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.dirname(__file__))

from foundation_sp_counted_get_deleter import (  # noqa: E402
    TAG_NAME,
    TAG_NAME_PTR,
    VTABLE_SLOTS,
    TypeInfo,
    check,
    get_deleter,
)

PACKET = os.path.join(
    "research", "work-items", "foundation-sp-counted-get-deleter-94")
EVIDENCE = os.path.join(PACKET, "evidence.json")
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
HOLDER = 0x1000000


def find_binary():
    """The materialized node #94 binary, or None if it is not present."""
    for path in (os.path.join("artifacts", "node", "94", "hl-node"),
                 os.path.join("work", "hl-node-94.bin")):
        if not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            head = f.read(64)
        if head.startswith(b"version https://git-lfs"):
            continue
        return path
    return None


def tag_ti(name_ptr=None, name=TAG_NAME):
    return TypeInfo(name=name, name_ptr=name_ptr)


class TestGetDeleter(unittest.TestCase):
    def test_sentinel_returns_storage_without_reading_name(self):
        # The sentinel arm precedes the name load: even a type_info
        # whose name is never readable still matches.
        ti = TypeInfo(name=None, is_sentinel=True)
        self.assertEqual(get_deleter(HOLDER, ti), HOLDER + 0x10)

    def test_sentinel_ignores_name(self):
        ti = TypeInfo(name="something-else", name_ptr=0x1234, is_sentinel=True)
        self.assertEqual(get_deleter(HOLDER, ti), HOLDER + 0x10)

    def test_name_pointer_equal_returns_storage(self):
        ti = tag_ti(name_ptr=TAG_NAME_PTR, name="unrelated-bytes")
        self.assertEqual(get_deleter(HOLDER, ti), HOLDER + 0x10)

    def test_name_content_equal_returns_storage(self):
        ti = tag_ti(name_ptr=0x999999, name=TAG_NAME)
        self.assertEqual(get_deleter(HOLDER, ti), HOLDER + 0x10)

    def test_other_name_returns_null(self):
        ti = tag_ti(name_ptr=0x999999, name="St23_Sp_counted_ptr_inplaceE")
        self.assertIsNone(get_deleter(HOLDER, ti))

    def test_star_name_returns_null(self):
        # A name beginning with '*' short-circuits before strcmp.
        ti = tag_ti(name_ptr=0x999999,
                    name="*ZN7rocksdb13InternalStats19CacheEntryRoleStatsE_")
        self.assertIsNone(get_deleter(HOLDER, ti))

    def test_empty_name_returns_null(self):
        ti = tag_ti(name_ptr=0x999999, name="")
        self.assertIsNone(get_deleter(HOLDER, ti))

    def test_vtable_slot_index(self):
        # The function is the fifth virtual (index 4) of its vtable:
        # dispatch through the slot must reach 0x514b5d0.
        slots = sorted(VTABLE_SLOTS.items())
        self.assertEqual(slots[4], (0x575B068, 0x514B5D0))
        self.assertEqual(len(slots), 5)

    def test_dispatch_through_vtable(self):
        # Simulate virtual dispatch: the object's vtable pointer
        # selects slot 4, whose target is this gate.
        vtable = dict(VTABLE_SLOTS)
        target = vtable[0x575B068]
        self.assertEqual(target, 0x514B5D0)
        # And the gate itself, reached that way, answers the tag.
        self.assertEqual(get_deleter(HOLDER, tag_ti()), HOLDER + 0x10)
        self.assertIsNone(get_deleter(HOLDER, tag_ti(name="other")))


class TestBinaryReproduction(unittest.TestCase):
    def test_checker_passes_on_real_binary(self):
        binary = find_binary()
        if binary is None:
            self.skipTest("materialized node #94 binary not present")
        failures = check(EVIDENCE, binary)
        self.assertEqual(failures, [])

    def test_evidence_binds_to_target_digest(self):
        with open(EVIDENCE) as f:
            ev = json.load(f)
        self.assertEqual(ev["target"]["sha256"], TARGET_SHA)
        self.assertEqual(ev["function"]["address"], "0x514b5d0")
        self.assertEqual(ev["vtable"]["slots"]["0x575b068"], "0x514b5d0")
        self.assertEqual(len(ev["instructions"]), 23)


class TestCorruptionControls(unittest.TestCase):
    def _copy_packet(self, tmp):
        dest = os.path.join(tmp, "packet")
        shutil.copytree(PACKET, dest)
        return dest

    def test_flipped_function_byte_fails(self):
        binary = find_binary()
        if binary is None:
            self.skipTest("materialized node #94 binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "hl-node-94.bin")
            shutil.copyfile(binary, bad)
            with open(bad, "r+b") as f:
                # .text file offset = VA - 0x1000.
                f.seek(0x514B5D0 - 0x1000)
                byte = f.read(1)
                f.seek(0x514B5D0 - 0x1000)
                f.write(bytes([byte[0] ^ 0xFF]))
            failures = check(EVIDENCE, bad)
            self.assertTrue(failures)

    def test_flipped_tag_name_byte_fails(self):
        binary = find_binary()
        if binary is None:
            self.skipTest("materialized node #94 binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "hl-node-94.bin")
            shutil.copyfile(binary, bad)
            with open(bad, "r+b") as f:
                # .rodata file offset = VA.
                f.seek(0x7EA0D0)
                f.write(b"X")
            failures = check(EVIDENCE, bad)
            self.assertTrue(failures)

    def test_wrong_mnemonic_fails(self):
        binary = find_binary()
        if binary is None:
            self.skipTest("materialized node #94 binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            packet = self._copy_packet(tmp)
            ev_path = os.path.join(packet, "evidence.json")
            with open(ev_path) as f:
                ev = json.load(f)
            ev["instructions"][0]["mnemonic"] = "nop"
            with open(ev_path, "w") as f:
                json.dump(ev, f, indent=2)
            failures = check(ev_path, binary)
            self.assertTrue(failures)

    def test_broken_manifest_fails(self):
        binary = find_binary()
        if binary is None:
            self.skipTest("materialized node #94 binary not present")
        with tempfile.TemporaryDirectory() as tmp:
            packet = self._copy_packet(tmp)
            manifest = os.path.join(packet, "MANIFEST.sha256")
            with open(manifest) as f:
                lines = f.read().splitlines()
            lines[0] = "0" * 64 + lines[0][64:]
            with open(manifest, "w") as f:
                f.write("\n".join(lines) + "\n")
            failures = check(os.path.join(packet, "evidence.json"), binary)
            self.assertTrue(failures)


if __name__ == "__main__":
    unittest.main()
