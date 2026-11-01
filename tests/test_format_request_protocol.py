"""Controls for the pre-source authority and actual transcript comparator."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import format_request_protocol as protocol


class FormatterAuthorityTests(unittest.TestCase):
    def test_complete_frozen_authority_and_comparator_controls(self):
        inputs, raw, expected = protocol.fixtures()
        self.assertEqual(len(inputs.splitlines()), 1066)
        self.assertEqual(protocol.compare(raw, expected), [])
        changed = [json.loads(line) for line in raw.splitlines()]
        changed[2]["events"][0]["bytes"] = "ff"
        self.assertEqual(protocol.compare(b"\n".join(json.dumps(row).encode() for row in changed), expected), [changed[2]["id"]])
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            protocol.compare(b"\n".join(raw.splitlines()[:-1]), expected)

    def test_independent_plan_generator_reproduces_frozen_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("generate_formatter.py", "formatter448-proof.md"):
                shutil.copyfile(protocol.PACKET / "oracle" / name, root / name)
            result = subprocess.run([sys.executable, "-B", str(root / "generate_formatter.py")],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("formatter448-authority.json", "formatter448-input.tsv", "formatter448-expected.jsonl"):
                self.assertEqual((root / name).read_bytes(), gzip.decompress((protocol.PACKET / "oracle" / (name + ".gz")).read_bytes()))
            self.assertEqual((root / "formatter448-freeze.json").read_bytes(), (protocol.PACKET / "oracle/formatter448-freeze.json").read_bytes())

    def test_changed_actual_oracle_container_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(protocol.PACKET / "oracle", root / "oracle")
            path = root / "oracle/formatter448-input.tsv.gz"
            altered = bytearray(gzip.decompress(path.read_bytes()))
            altered[0] ^= 1
            path.write_bytes(gzip.compress(altered, mtime=0))
            with patch.object(protocol, "PACKET", root):
                with self.assertRaisesRegex(ValueError, "oracle identity mismatch"):
                    protocol.fixtures()


if __name__ == "__main__":
    unittest.main()
