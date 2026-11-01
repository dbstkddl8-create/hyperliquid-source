"""Unit tests for the foundation sentinel-checked field-reader window
(node #94, 0x514abb0).

Run from the repository root:

    python3 -m unittest tests.test_foundation_sentinel_field_read -v

The checker is exercised on the real evidence plus in-memory corruption
controls: each control mutates one recorded fact and must make the checker
fail, so a passing suite means the checker actually locks the bytes, the
padding, the FDE records, and every rule edge. The binary cross-check runs
only when a hash-verified copy of the node #94 binary is present locally
(work/hl-node-94.bin); otherwise it is skipped, and the packet-consistency
checks above still run.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PACKET_DIR = os.path.join(
    REPO_ROOT, "research", "work-items", "foundation-sentinel-field-read-94")
EVIDENCE = os.path.join(PACKET_DIR, "evidence.json")
WORK_BINARY = os.path.join(REPO_ROOT, "work", "hl-node-94.bin")
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_sentinel_field_read",
        os.path.join(REPO_ROOT, "tools", "foundation_sentinel_field_read.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


def verified_binary():
    if not os.path.exists(WORK_BINARY):
        return None
    with open(WORK_BINARY, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return WORK_BINARY if digest == TARGET_SHA else None


def run_checker_on(evidence_dict, binary_path=None):
    """Run the checker against a mutated evidence copy; return exit code."""
    tmp = tempfile.mkdtemp()
    try:
        packet_dir = os.path.join(tmp, "packet")
        shutil.copytree(PACKET_DIR, packet_dir)
        path = os.path.join(packet_dir, "evidence.json")
        with open(path, "w") as fh:
            json.dump(evidence_dict, fh)
        argv = ["prog", "--check", path]
        if binary_path is not None:
            argv += ["--binary", binary_path]
        return CHECKER.main(argv)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_checker_on_window(window_text, binary_path=None):
    """Run the checker with a mutated window.objdump.txt; return exit code."""
    tmp = tempfile.mkdtemp()
    try:
        packet_dir = os.path.join(tmp, "packet")
        shutil.copytree(PACKET_DIR, packet_dir)
        with open(os.path.join(packet_dir, "window.objdump.txt"), "w") as fh:
            fh.write(window_text)
        argv = ["prog", "--check", os.path.join(packet_dir, "evidence.json")]
        if binary_path is not None:
            argv += ["--binary", binary_path]
        return CHECKER.main(argv)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def good_evidence():
    with open(EVIDENCE) as fh:
        return json.load(fh)


def good_window_text():
    with open(os.path.join(PACKET_DIR, "window.objdump.txt")) as fh:
        return fh.read()


class TestSentinelFieldRead(unittest.TestCase):
    def test_checker_reproduces_packet_evidence(self):
        self.assertEqual(CHECKER.main(["prog", "--check", EVIDENCE]), 0)

    def test_model_empty_stores_zero(self):
        self.assertEqual(CHECKER.sentinel_field_read(0x3000, 0x3000, 0x99),
                         (0, 1))

    def test_model_nonempty_stores_field30(self):
        self.assertEqual(CHECKER.sentinel_field_read(0x4000, 0x3000, 0xABCD),
                         (0xABCD, 1))

    def test_model_nonempty_zero_field_still_returns_one(self):
        self.assertEqual(CHECKER.sentinel_field_read(0x4000, 0x3000, 0),
                         (0, 1))

    def test_rule_edges_evaluate(self):
        ev = good_evidence()
        for edge in ev["rule"]["edges"]:
            with self.subTest(note=edge["note"]):
                CHECKER.evaluate_edge(edge)

    def test_window_is_51_byte_fde(self):
        ev = good_evidence()
        fn = ev["function"]
        self.assertEqual(fn["start_va"], "0x514abb0")
        self.assertEqual(fn["end_va_exclusive"], "0x514abe3")
        self.assertEqual(fn["bytes"], 51)
        self.assertEqual(fn["padding_bytes"], 13)

    def test_zero_direct_callers_recorded(self):
        ev = good_evidence()
        self.assertEqual(ev["incoming"]["direct_e8_callers"], [])

    def test_sentinel_and_field_offsets(self):
        ev = good_evidence()
        self.assertEqual(ev["rule"]["elem_offset"], "0x1200")
        self.assertEqual(ev["rule"]["sentinel_delta"], "0x11e0")
        self.assertEqual(ev["rule"]["field_offset"], "0x30")
        self.assertEqual(ev["rule"]["return_value"], 1)

    def test_corrupt_body_sha(self):
        ev = good_evidence()
        ev["function"]["sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_padding_count(self):
        ev = good_evidence()
        ev["function"]["padding_bytes"] = 12
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_fde_offset(self):
        ev = good_evidence()
        ev["function"]["fde_section_offset"] = "0x0029a101"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_next_fde_offset(self):
        ev = good_evidence()
        ev["function"]["next_fde_section_offset"] = "0x0029a115"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_window_byte(self):
        text = good_window_text().replace("48 8b 40 30", "48 8b 40 31", 1)
        self.assertNotEqual(run_checker_on_window(text), 0)

    def test_corrupt_edge_out(self):
        ev = good_evidence()
        ev["rule"]["edges"][1]["out"] = "0xabce"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_sentinel_delta(self):
        ev = good_evidence()
        ev["rule"]["sentinel_delta"] = "0x11e1"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_field_offset(self):
        ev = good_evidence()
        ev["rule"]["field_offset"] = "0x31"
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_corrupt_return_value(self):
        ev = good_evidence()
        ev["rule"]["return_value"] = 0
        self.assertNotEqual(run_checker_on(ev), 0)

    def test_binary_cross_check(self):
        binary = verified_binary()
        if binary is None:
            self.skipTest("no hash-verified node #94 binary present locally")
        self.assertEqual(
            CHECKER.main(["prog", "--check", EVIDENCE,
                          "--binary", binary]), 0)

    def test_binary_cross_check_rejects_corrupt_caller_list(self):
        binary = verified_binary()
        if binary is None:
            self.skipTest("no hash-verified node #94 binary present locally")
        ev = good_evidence()
        ev["incoming"]["direct_e8_callers"] = [{"site": "0x514ab000"}]
        self.assertNotEqual(run_checker_on(ev, binary_path=binary), 0)

    def test_binary_cross_check_rejects_corrupt_digest(self):
        binary = verified_binary()
        if binary is None:
            self.skipTest("no hash-verified node #94 binary present locally")
        ev = good_evidence()
        ev["target_sha256"] = "0" * 64
        self.assertNotEqual(run_checker_on(ev, binary_path=binary), 0)


if __name__ == "__main__":
    unittest.main()
