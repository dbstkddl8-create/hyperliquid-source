"""Tests for node #94's recursive destructor at 0x514b690 (RE-001)."""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from foundation_recursive_destructor import check, destroy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items", "RE-001-recursive-destructor-94")
RECORDS = os.path.join(PACKET, "records.json")
BINARY = os.path.join(ROOT, "artifacts", "node", "94", "hl-node")


def heap_of(links):
    """links: {node: (next10, child18)} with None for a null link."""
    return dict(links)


class TestDestroy(unittest.TestCase):
    def test_null_head_deletes_nothing(self):
        self.assertEqual(destroy({}, None), [])

    def test_single_node(self):
        self.assertEqual(destroy(heap_of({0x1000: (None, None)}), 0x1000),
                         [(0x1000, 0x30)])

    def test_next_chain_order(self):
        heap = heap_of({0x1000: (0x2000, None), 0x2000: (0x3000, None),
                        0x3000: (None, None)})
        self.assertEqual(destroy(heap, 0x1000),
                         [(0x1000, 0x30), (0x2000, 0x30), (0x3000, 0x30)])

    def test_child_deleted_before_parent(self):
        heap = heap_of({0x1000: (None, 0x2000), 0x2000: (None, None)})
        self.assertEqual(destroy(heap, 0x1000),
                         [(0x2000, 0x30), (0x1000, 0x30)])

    def test_child_chain_deleted_before_parent(self):
        heap = heap_of({0x1000: (None, 0x2000), 0x2000: (0x3000, None),
                        0x3000: (None, None)})
        self.assertEqual(destroy(heap, 0x1000),
                         [(0x2000, 0x30), (0x3000, 0x30), (0x1000, 0x30)])

    def test_worked_example_from_readme(self):
        # H+0x10 = A, H+0x18 = C, C+0x10 = D, rest null: C, D, H, A.
        heap = heap_of({0x1000: (0x4000, 0x2000), 0x2000: (0x3000, None),
                        0x3000: (None, None), 0x4000: (None, None)})
        self.assertEqual(destroy(heap, 0x1000),
                         [(0x2000, 0x30), (0x3000, 0x30),
                          (0x1000, 0x30), (0x4000, 0x30)])

    def test_deep_nesting(self):
        heap = heap_of({0x1000: (None, 0x2000), 0x2000: (None, 0x3000),
                        0x3000: (0x4000, None), 0x4000: (None, None)})
        self.assertEqual(destroy(heap, 0x1000),
                         [(0x3000, 0x30), (0x4000, 0x30),
                          (0x2000, 0x30), (0x1000, 0x30)])

    def test_next_link_read_before_free(self):
        # The model reads +0x10 before deleting, so a node whose next
        # link is set is always followed even though the node itself
        # is freed first in program order.
        heap = heap_of({0x1000: (0x2000, 0x3000), 0x3000: (None, None),
                        0x2000: (None, None)})
        self.assertEqual(destroy(heap, 0x1000),
                         [(0x3000, 0x30), (0x1000, 0x30), (0x2000, 0x30)])

    def test_delete_size_always_0x30(self):
        heap = heap_of({0x1000: (0x2000, 0x3000), 0x2000: (None, None),
                        0x3000: (None, None)})
        self.assertTrue(all(size == 0x30 for _addr, size in destroy(heap, 0x1000)))

    def test_branch_and_call_targets_from_raw_bytes(self):
        # Branch/call targets re-derived from the raw encodings at the
        # recorded sites, using the digest-verified binary bytes.
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
        from foundation_recursive_destructor import Elf
        with open(BINARY, "rb") as f:
            elf = Elf(f.read())
        with open(RECORDS) as f:
            rec = json.load(f)
        for br in rec["branches"]:
            addr = int(br["site"], 16)
            raw = elf.read_at(addr, 2)
            (rel,) = struct.unpack_from("<b", raw, 1)
            self.assertEqual(addr + 2 + rel, int(br["target"], 16))
        for call in rec["calls"]:
            addr = int(call["site"], 16)
            raw = elf.read_at(addr, 5)
            self.assertEqual(raw[0], 0xE8)
            (rel,) = struct.unpack_from("<i", raw, 1)
            self.assertEqual(addr + 5 + rel, int(call["target"], 16))


class TestChecker(unittest.TestCase):
    def test_checker_passes_on_real_binary(self):
        self.assertEqual(check(RECORDS, BINARY), [])

    def test_packet_verify_passes_on_real_binary(self):
        sys.path.insert(0, PACKET)
        import verify as packet_verify
        self.assertEqual(
            packet_verify.check(RECORDS, BINARY), [])

    def _mutated_check(self, mutate):
        tmp = tempfile.mkdtemp()
        try:
            copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, copy)
            rec_path = os.path.join(copy, "records.json")
            with open(rec_path) as f:
                rec = json.load(f)
            mutate(rec, copy)
            with open(rec_path, "w") as f:
                json.dump(rec, f)
            return check(rec_path, BINARY)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_corruption_wrong_function_sha_fails(self):
        def mutate(rec, _copy):
            rec["function"]["sha256"] = "0" * 64
        self.assertNotEqual(self._mutated_check(mutate), [])

    def test_corruption_wrong_census_fails(self):
        def mutate(ev, _copy):
            ev["callers_e8"] = ev["callers_e8"][:-1]
        self.assertNotEqual(self._mutated_check(mutate), [])

    def test_corruption_wrong_delete_symbol_fails(self):
        def mutate(ev, _copy):
            ev["delete_plt"]["symbol"] = "_ZdlPvm_other"
        self.assertNotEqual(self._mutated_check(mutate), [])

    def test_corruption_manifest_hash_fails(self):
        def mutate(_ev, copy):
            with open(os.path.join(copy, "frames.txt"), "a") as f:
                f.write("# tampered\n")
        self.assertNotEqual(self._mutated_check(mutate), [])


if __name__ == "__main__":
    unittest.main()
