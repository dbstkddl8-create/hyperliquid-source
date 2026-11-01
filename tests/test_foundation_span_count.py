"""Unit tests for the foundation span-count window (node #94, 0x53c7490).

Run from the repository root:

    python3 -m unittest tests.test_foundation_span_count -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
callee, the padding, the caller list, the FDE records, and every rule edge
including the empty-span wraparound and the negative-span edge.
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-span-count-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_span_count",
        os.path.join(REPO_ROOT, "tools", "foundation_span_count.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def run_checker_on(evidence_dict):
    """Run the checker against a mutated evidence copy; return exit code."""
    tmp = tempfile.mkdtemp()
    try:
        packet_dir = os.path.join(tmp, "packet")
        shutil.copytree(os.path.dirname(EVIDENCE), packet_dir)
        path = os.path.join(packet_dir, "evidence.json")
        with open(path, "w") as fh:
            json.dump(evidence_dict, fh)
        return CHECKER.main(["prog", "--check", path])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def good_evidence():
    with open(EVIDENCE) as fh:
        return json.load(fh)


class TestSpanCount(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            with self.subTest(note=edge["note"]):
                CHECKER.evaluate_edge(edge)

    def test_window_is_43_bytes_5_padding(self):
        ev = good_evidence()
        self.assertEqual(ev["function"]["bytes"], 43)
        self.assertEqual(ev["function"]["padding_bytes"], 5)

    def test_callee_is_1514_byte_fde_start(self):
        ev = good_evidence()
        self.assertEqual(ev["callee"]["bytes"], 1514)
        self.assertTrue(ev["callee"]["is_fde_start"])
        self.assertEqual(ev["callee"]["padding_bytes"], 6)

    def test_zero_callers(self):
        ev = good_evidence()
        self.assertEqual(ev["incoming"]["direct_e8_callers"], [])

    def test_call_target_is_callee(self):
        ev = good_evidence()
        self.assertEqual(ev["callee"]["start_va"], "0x53c6e80")

    def test_tail_jump_target(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["tail_jump"], "0x53c4ec0")
        self.assertEqual(ev["jump_target"]["start_va"], "0x53c4ec0")
        self.assertTrue(ev["jump_target"]["is_fde_start"])

    def test_empty_span_wraps(self):
        ev = good_evidence()
        edge = [e for e in ev["rule"]["edges"]
                if e["start"] == e["end"]][0]
        self.assertEqual(edge["stored"], "0xffffffff")

    def test_negative_span_edge(self):
        ev = good_evidence()
        edge = [e for e in ev["rule"]["edges"]
                if e["note"].startswith("negative span")][0]
        self.assertEqual(edge["stored"], "0xfffffffe")

    def test_corrupt_body_sha(self):
        ev = good_evidence()
        ev["function"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_padding(self):
        ev = good_evidence()
        ev["function"]["padding_bytes"] = 4
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_digest(self):
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_call_target(self):
        ev = good_evidence()
        ev["callee"]["start_va"] = "0x53c6e81"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_jump_target(self):
        ev = good_evidence()
        ev["rule"]["tail_jump"] = "0x53c4ec1"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x002b637d"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_next_fde_offset(self):
        ev = good_evidence()
        ev["function"]["next_fde_section_offset"] = "0x002b6399"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_sha(self):
        ev = good_evidence()
        ev["callee"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_extent(self):
        ev = good_evidence()
        ev["callee"]["end_va_exclusive"] = "0x53c746b"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_padding(self):
        ev = good_evidence()
        ev["callee"]["padding_bytes"] = 5
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = ["0x53c7498"]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_jump_target_fde_offset(self):
        ev = good_evidence()
        ev["jump_target"]["fde_section_offset"] = "0x002b61c9"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_stored(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["stored"] = "0x40"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_end(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["end"] = "0x1104"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_store(self):
        ev = good_evidence()
        ev["rule"]["store"] = "dword at [obj+0x84]"
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
