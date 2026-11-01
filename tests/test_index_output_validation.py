"""Rejected retained inventories must not publish or overwrite index packets."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_fde_extents import build

ROOT = Path(__file__).resolve().parents[1]


class IndexOutputValidationTests(unittest.TestCase):
    def stage(self, root, inventory):
        (root / 'tools').mkdir()
        for name in ('elf_index.py', 'fde_extents.py', 'artifacts.py'):
            (root / 'tools' / name).write_bytes((ROOT / 'tools' / name).read_bytes())
        data = bytes(build()[0])
        relative = 'artifacts/node/94/hl-node'
        binary = root / relative
        binary.parent.mkdir(parents=True)
        binary.write_bytes(data)
        (root / 'provenance').mkdir()
        (root / 'provenance/artifacts.json').write_text(json.dumps({'files': [
            {'path': relative, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]}))
        path = root / 'research/imported/hl-node-94.inventory.json'
        path.parent.mkdir(parents=True)
        if inventory is not None:
            path.write_text(inventory)

    def run_cli(self, root, tool):
        return subprocess.run([sys.executable, str(root / 'tools' / (tool + '.py')),
                               '--release', '94', '--output-dir', str(root / 'out')],
                              capture_output=True, text=True)

    def test_rejected_inventories_preserve_existing_outputs(self):
        for tool, prefix, suffixes in [('elf_index', 'node-94-unwind', ['.json', '.tsv']),
                                       ('fde_extents', 'node-94-fde', ['.json', '.tsv', '-gaps.tsv'])]:
            for inventory in [None, '{', '{"fde_count_eh_frame_hdr":null}',
                              '{"fde_count_eh_frame_hdr":-1}', '{"fde_count_eh_frame_hdr":true}',
                              '{"fde_count_eh_frame_hdr":4}',
                              '{"fde_count_eh_frame_hdr":3,"fde_count_eh_frame_hdr":4}']:
                with self.subTest(tool=tool, inventory=inventory), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self.stage(root, inventory)
                    (root / 'out').mkdir()
                    expected = {}
                    for suffix in suffixes:
                        path = root / 'out' / (prefix + suffix)
                        path.write_bytes(b'previous validated packet\n')
                        expected[path.name] = path.read_bytes()
                    result = self.run_cli(root, tool)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, '')
                    self.assertEqual({p.name:p.read_bytes() for p in (root / 'out').iterdir()}, expected)

    def test_count_mismatch_creates_no_output_directory(self):
        for tool in ['elf_index', 'fde_extents']:
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.stage(root, '{"fde_count_eh_frame_hdr":4}')
                result = self.run_cli(root, tool)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Parsed unwind count differs', result.stderr)
                self.assertFalse((root / 'out').exists())

    def test_replaced_capture_is_rejected_before_output(self):
        for tool in ['elf_index', 'fde_extents']:
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.stage(root, '{"fde_count_eh_frame_hdr":3}')
                # Deterministically replace bytes just after the real checker
                # succeeds. The replacement remains a parseable three-FDE ELF.
                helper = root / 'tools/artifacts.py'
                with helper.open('a') as stream:
                    stream.write("\n_original_check = check\n"
                                 "def check(path, item):\n"
                                 "    _original_check(path, item)\n"
                                 "    data = bytearray(Path(path).read_bytes())\n"
                                 "    data[0x400] ^= 1\n"
                                 "    Path(path).write_bytes(data)\n")
                result = self.run_cli(root, tool)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Artifact size/SHA-256 mismatch', result.stderr)
                self.assertFalse((root / 'out').exists())

    def test_matching_inventory_publishes_actual_three_entry_packet(self):
        for tool, prefix, field in [('elf_index','node-94-unwind','unwind_entries'),
                                    ('fde_extents','node-94-fde','unwind_table_entries')]:
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.stage(root, '{"fde_count_eh_frame_hdr":3}')
                result = self.run_cli(root, tool)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads(result.stdout)
                self.assertEqual(summary[field], 3)
                self.assertEqual(json.loads((root/'out'/(prefix+'.json')).read_text()), summary)
                self.assertEqual(len((root/'out'/(prefix+'.tsv')).read_text().splitlines()), 4)
