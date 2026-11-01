#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-counted-ptr-dispose-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Output files are written next to this script and are
byte-identical to the shipped excerpts when run against the
digest-pinned binary with the same binutils version (GNU binutils
2.42 here). The excerpts are whole functions (plus int3 padding to
the next FDE), never trimmed windows.
"""

import argparse
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the file
    # holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x514bb10", "0x514bb95"),
    "guard.objdump.txt": ("0x4f9ea60", "0x4f9eb10"),
}


def objdump(binary, args):
    result = subprocess.run(["objdump"] + args + [binary],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("objdump failed: %s" % result.stderr.strip())
    return result.stdout


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    for name, (start, stop) in sorted(RANGES.items()):
        text = objdump(args.binary, ["-d", "--start-address=%s" % start,
                                     "--stop-address=%s" % stop])
        path = os.path.join(PACKET_DIR, name)
        with open(path, "w") as f:
            f.write(text)
        print("wrote %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
