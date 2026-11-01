"""Unit tests for the foundation modulo-index-byte window (node #94).

Run from the repository root:

    python3 -m unittest tests.test_foundation_modulo_index_byte -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
callee, the padding, the caller list, the FDE records, and every rule edge
including the divisor-zero fault limit and the 64-bit max-index edge.
"""

import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVIDENCE = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-modulo-index-byte-94",
    "evidence.json")


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_modulo_index_byte",
        os.path.join(REPO_ROOT, "tools", "foundation_modulo_index_byte.py"))
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


class TestModuloIndexByte(unittest.TestCase):
    def test_checker_reproduces_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            with self.subTest(note=edge["note"]):
                CHECKER.evaluate_edge(edge)

    def test_window_is_57_bytes_7_padding(self):
        ev = good_evidence()
        self.assertEqual(ev["function"]["bytes"], 57)
        self.assertEqual(ev["function"]["padding_bytes"], 7)

    def test_callee_is_133_byte_fde_start(self):
        ev = good_evidence()
        self.assertEqual(ev["callee"]["bytes"], 133)
        self.assertTrue(ev["callee"]["is_fde_start"])
        self.assertEqual(ev["callee"]["padding_bytes"], 11)

    def test_single_caller(self):
        ev = good_evidence()
        self.assertEqual(ev["incoming"]["direct_e8_callers"], ["0x535bea9"])
        self.assertEqual(ev["incoming"]["caller_fde_start"], "0x535be50")
        self.assertEqual(ev["incoming"]["caller_fde_end"], "0x535c4ab")

    def test_call_args_seed(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["call_args"]["rdx"], "0x18d")
        self.assertEqual(ev["rule"]["call_args"]["rdi"], "[rcx]")
        self.assertEqual(ev["rule"]["call_args"]["rsi"], "[rcx + 8]")

    def test_divisor_is_word_at_rdi(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["divisor"],
                         "word at [rdi], zero-extended to 32 bits")

    def test_fault_edge_divisor_zero(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["fault_edge"]["divisor"], "0x0")
        self.assertEqual(ev["rule"]["fault_edge"]["fault"], "#DE")

    def test_max_index_edge_64_bit(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][4]
        self.assertEqual(edge["idx"], "0xffffffff")
        self.assertEqual(edge["read_addr"], "0x100001004")

    def test_max_u16_divisor_remainder_zero(self):
        ev = good_evidence()
        edge = ev["rule"]["edges"][5]
        self.assertEqual(edge["divisor"], "0xffff")
        self.assertEqual(edge["callee_result"], "0xffffffff")
        self.assertEqual(edge["remainder"], "0x0")

    def test_corrupt_body_sha(self):
        ev = good_evidence()
        ev["function"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_padding(self):
        ev = good_evidence()
        ev["function"]["padding_bytes"] = 10
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_digest(self):
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_call_target(self):
        ev = good_evidence()
        ev["callee"]["start_va"] = "0x5422e71"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x002b379d"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_next_fde_offset(self):
        ev = good_evidence()
        ev["function"]["next_fde_section_offset"] = "0x002b37cd"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_sha(self):
        ev = good_evidence()
        ev["callee"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_extent(self):
        ev = good_evidence()
        ev["callee"]["end_va_exclusive"] = "0x5422ef6"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_callee_padding(self):
        ev = good_evidence()
        ev["callee"]["padding_bytes"] = 5
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_list(self):
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = ["0x538c800"]
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_caller_fde_offset(self):
        ev = good_evidence()
        ev["incoming"]["caller_fde_section_offset"] = "0x002b2079"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_remainder(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["remainder"] = "0x6"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_read_addr(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["read_addr"] = "0x1009"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_ret(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["ret"] = "0x42"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_edge_seed(self):
        ev = good_evidence()
        ev["rule"]["edges"][0]["call_rdx"] = "0x18e"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_fault_edge(self):
        ev = good_evidence()
        ev["rule"]["fault_edge"]["divisor"] = "0x1"
        self.assertNotEqual(run_checker_on(ev), 0)


if __name__ == "__main__":
    unittest.main()
