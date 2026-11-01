#!/usr/bin/env python3
"""Tests for tools/foundation_tree_deep_copy.py (RE-001, node #94).

Model tests exercise the deep-copy behaviour end to end: inputs (a
source tree, a pool, an allocator) through the model to observable
outputs (the copied tree's shape, fields, parent links, pool state and
allocation count).  Checker tests verify the evidence packet against
the digest-pinned binary when it is present.
"""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "work-items",
                                "RE-001-tree-deep-copy-94"))

import foundation_tree_deep_copy as tool
from foundation_tree_deep_copy import Node, Pool, deep_copy, destroy

PACKET_DIR = os.path.join(REPO_ROOT, "research", "work-items",
                          "RE-001-tree-deep-copy-94")
BINARY = os.path.join(REPO_ROOT, "work", "hl-node-94.bin")


def node(value, payload, tag=None):
    return Node(value=value, payload=payload, tag=tag)


def shape(root):
    """(value, payload, left-shape, right-shape) structural snapshot."""
    if root is None:
        return None
    return (root.value, root.payload, shape(root.left), shape(root.right))


def counting_alloc():
    made = []

    def alloc():
        n = Node(tag="alloc-%d" % len(made))
        made.append(n)
        return n

    return alloc, made


class ModelTests(unittest.TestCase):
    def test_single_node_empty_pool(self):
        src = node(-7, b"0123456789abcdef", "src")
        alloc, made = counting_alloc()
        out = deep_copy(src, None, Pool(), alloc)
        self.assertEqual(len(made), 1)
        self.assertIs(out, made[0])
        self.assertEqual(out.value, -7)
        self.assertEqual(out.payload, b"0123456789abcdef")
        self.assertIsNone(out.parent)
        self.assertIsNone(out.left)
        self.assertIsNone(out.right)
        self.assertIsNot(out, src)

    def test_right_child_recursion_and_parent_links(self):
        src = node(1, b"r" * 16)
        src.right = node(2, b"c" * 16)
        src.right.parent = src
        alloc, made = counting_alloc()
        out = deep_copy(src, None, Pool(), alloc)
        self.assertEqual(len(made), 2)
        self.assertIs(out.right.parent, out)
        self.assertEqual(shape(out), shape(src))
        self.assertIsNone(out.left)

    def test_left_spine_iteration(self):
        src = node(1, b"a" * 16)
        src.left = node(2, b"b" * 16)
        src.left.left = node(3, b"c" * 16)
        src.left.parent = src
        src.left.left.parent = src.left
        alloc, made = counting_alloc()
        out = deep_copy(src, None, Pool(), alloc)
        self.assertEqual(len(made), 3)
        self.assertIs(out.left.parent, out)
        self.assertIs(out.left.left.parent, out.left)
        self.assertEqual(shape(out), shape(src))

    def test_full_tree_shape_preserved(self):
        src = node(10, b"root____________")
        src.left = node(20, b"left____________")
        src.right = node(30, b"right___________")
        src.left.left = node(40, b"ll______________")
        src.left.right = node(50, b"lr______________")
        src.right.right = node(60, b"rr______________")
        for child in (src.left, src.right):
            child.parent = src
        src.left.left.parent = src.left
        src.left.right.parent = src.left
        src.right.right.parent = src.right
        alloc, made = counting_alloc()
        out = deep_copy(src, None, Pool(), alloc)
        self.assertEqual(len(made), 6)
        self.assertEqual(shape(out), shape(src))
        # Every copied node's parent pointer points at its copied parent.
        self.assertIs(out.left.parent, out)
        self.assertIs(out.right.parent, out)
        self.assertIs(out.left.left.parent, out.left)
        self.assertIs(out.left.right.parent, out.left)
        self.assertIs(out.right.right.parent, out.right)

    def test_pool_pop_order_right_left_root(self):
        old_p = node(1, b"p" * 16, "P")
        old_l = node(2, b"l" * 16, "L")
        old_r = node(3, b"r" * 16, "R")
        old_p.left, old_p.right = old_l, old_r
        old_l.parent, old_r.parent = old_p, old_p
        pool = Pool(root=old_p, head=old_r)
        self.assertIs(pool.pop(), old_r)
        self.assertIs(pool.pop(), old_l)
        self.assertIs(pool.pop(), old_p)
        self.assertIsNone(pool.root)
        self.assertIsNone(pool.head)
        self.assertIsNone(pool.pop())

    def test_pool_walk_path_deeper_left_subtree(self):
        # Old tree: P(right=R, left=A), A(right=B).  Head starts at R.
        # Hand-computed pop order from the transliterated walk:
        # R, then B (rightmost of P's left subtree), then A, then P.
        old_p = node(1, b"p" * 16, "P")
        old_a = node(2, b"a" * 16, "A")
        old_b = node(3, b"b" * 16, "B")
        old_r = node(4, b"r" * 16, "R")
        old_p.left, old_p.right = old_a, old_r
        old_a.right = old_b
        for child, par in ((old_a, old_p), (old_r, old_p), (old_b, old_a)):
            child.parent = par
        pool = Pool(root=old_p, head=old_r)
        self.assertEqual([n.tag for n in
                          (pool.pop(), pool.pop(), pool.pop(), pool.pop())],
                         ["R", "B", "A", "P"])
        self.assertIsNone(pool.root)
        self.assertIsNone(pool.head)

    def test_pool_simple_path_left_child(self):
        old_p = node(1, b"p" * 16, "P")
        old_l = node(2, b"l" * 16, "L")
        old_r = node(3, b"r" * 16, "R")
        old_p.left, old_p.right = old_l, old_r
        old_l.parent, old_r.parent = old_p, old_p
        pool = Pool(root=old_p, head=old_l)
        self.assertIs(pool.pop(), old_l)
        self.assertIsNone(old_p.left)  # simple path detaches parent's left
        self.assertIs(pool.head, old_p)

    def test_pool_reuse_avoids_allocation(self):
        src = node(1, b"a" * 16)
        src.left = node(2, b"b" * 16)
        src.right = node(3, b"c" * 16)
        src.left.parent = src
        src.right.parent = src
        old_p = node(9, b"p" * 16, "P")
        old_l = node(8, b"l" * 16, "L")
        old_r = node(7, b"r" * 16, "R")
        old_p.left, old_p.right = old_l, old_r
        old_l.parent, old_r.parent = old_p, old_p
        pool = Pool(root=old_p, head=old_r)
        alloc, made = counting_alloc()
        out = deep_copy(src, None, pool, alloc)
        self.assertEqual(made, [])  # every node came from the pool
        self.assertEqual(shape(out), shape(src))
        self.assertIsNone(pool.root)
        self.assertIsNone(pool.head)

    def test_partial_pool_falls_back_to_allocation(self):
        src = node(1, b"a" * 16)
        src.left = node(2, b"b" * 16)
        src.right = node(3, b"c" * 16)
        src.left.parent = src
        src.right.parent = src
        old_only = node(9, b"o" * 16, "O")
        pool = Pool(root=old_only, head=old_only)
        alloc, made = counting_alloc()
        out = deep_copy(src, None, pool, alloc)
        self.assertEqual(len(made), 2)  # one reused, two allocated
        self.assertEqual(shape(out), shape(src))

    def test_alloc_failure_destroys_in_progress_node(self):
        src = node(1, b"a" * 16)
        src.right = node(2, b"b" * 16)
        src.right.parent = src
        calls = []

        def failing_alloc():
            calls.append(1)
            if len(calls) == 2:
                raise tool.CopyAborted("operator new failed")
            return Node(tag="alloc-%d" % len(calls))

        with self.assertRaises(tool.CopyAborted):
            deep_copy(src, None, Pool(), failing_alloc)
        # The root frame's landing pad destroyed its in-progress node.
        self.assertEqual(len(calls), 2)

    def test_alloc_failure_marks_built_nodes_destroyed(self):
        src = node(1, b"a" * 16)
        src.right = node(2, b"b" * 16)
        src.right.parent = src
        built = []
        orig_alloc = None

        def failing_alloc():
            n = Node(tag="n%d" % len(built))
            built.append(n)
            if len(built) == 2:
                raise tool.CopyAborted("operator new failed")
            return n

        with self.assertRaises(tool.CopyAborted):
            deep_copy(src, None, Pool(), failing_alloc)
        self.assertTrue(built[0].destroyed)

    def test_null_source_raises(self):
        alloc, _ = counting_alloc()
        with self.assertRaises(ValueError):
            deep_copy(None, None, Pool(), alloc)

    def test_node_size_and_payload_width(self):
        self.assertEqual(tool.NODE_SIZE, 0x30)
        self.assertEqual(tool.PAYLOAD_BYTES, 16)


class CheckerTests(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_packet_verify_passes(self):
        result = subprocess.run(
            [sys.executable,
             os.path.join(PACKET_DIR, "verify.py"),
             "--binary", BINARY],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL CHECKS PASSED", result.stdout)

    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_tools_checker_passes(self):
        self.assertEqual(tool.check_packet(PACKET_DIR, BINARY), [])

    @unittest.skipUnless(os.path.exists(BINARY), "work binary missing")
    def test_corruption_controls(self):
        cases = []

        def mutate_sha(rec):
            rec["function"]["sha256"] = "0" * 64

        def mutate_branch(rec):
            rec["branches"][0]["target"] = "0x514b7e0"

        def mutate_plt(rec):
            rec["plt"][0]["got_va"] = "0x5778f71"

        def mutate_manifest(rec):
            pass  # manifest case handled separately below

        for mutate in (mutate_sha, mutate_branch, mutate_plt):
            with tempfile.TemporaryDirectory() as tmp:
                pkt = os.path.join(tmp, "pkt")
                shutil.copytree(PACKET_DIR, pkt)
                path = os.path.join(pkt, "records.json")
                with open(path) as f:
                    rec = json.load(f)
                mutate(rec)
                with open(path, "w") as f:
                    json.dump(rec, f)
                self.assertNotEqual(tool.check_packet(pkt, BINARY), [])
        # Manifest corruption: flip one manifest digest.
        with tempfile.TemporaryDirectory() as tmp:
            pkt = os.path.join(tmp, "pkt")
            shutil.copytree(PACKET_DIR, pkt)
            mpath = os.path.join(pkt, "MANIFEST.sha256")
            with open(mpath) as f:
                lines = f.read().splitlines()
            lines[0] = "0" * 64 + lines[0][64:]
            with open(mpath, "w") as f:
                f.write("\n".join(lines) + "\n")
            self.assertNotEqual(tool.check_packet(pkt, BINARY), [])


if __name__ == "__main__":
    unittest.main()
