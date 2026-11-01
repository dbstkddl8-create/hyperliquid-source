#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-string-concat-two-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. Output files are written next to this script and are
byte-identical to the shipped excerpts when run against the
digest-pinned binary with the same binutils version (GNU binutils
2.42 here). The window excerpt is the whole function plus its int3
padding to the next FDE; the callers file holds one window per
direct call site (40 bytes before the site through the call itself),
never a trimmed selection of the function body.
"""

import argparse
import json
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

RANGES = {
    # name: (start, stop) -- stop is the next FDE start, so the file
    # holds the whole function plus its int3 padding.
    "window.objdump.txt": ("0x514bbb0", "0x514bc60"),
    "landing.objdump.txt": ("0x514bb95", "0x514bbb0"),
    "plt.objdump.txt": None,  # built from the five PLT stubs below.
}

PLT_STUBS = [("0x5660610", "0x5660620"), ("0x5660600", "0x5660610"),
             ("0x56604a0", "0x56604b0"), ("0x5660470", "0x5660480"),
             ("0x5660110", "0x5660120")]


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
    for name, span in sorted(RANGES.items()):
        if span is None:
            continue
        start, stop = span
        text = objdump(args.binary, ["-d", "--start-address=%s" % start,
                                     "--stop-address=%s" % stop])
        path = os.path.join(PACKET_DIR, name)
        with open(path, "w") as f:
            f.write(text)
        print("wrote %s" % path)
    text = ""
    for start, stop in PLT_STUBS:
        text += objdump(args.binary, ["-d", "--start-address=%s" % start,
                                      "--stop-address=%s" % stop])
    path = os.path.join(PACKET_DIR, "plt.objdump.txt")
    with open(path, "w") as f:
        f.write(text)
    print("wrote %s" % path)
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        records = json.load(f)
    parts = []
    for site in records["censuses"]["concat_direct_callers"]:
        addr = int(site, 16)
        parts.append("# call site %#x\n" % addr)
        parts.append(objdump(args.binary,
                             ["-d", "--start-address=%s" % hex(addr - 0x40),
                              "--stop-address=%s" % hex(addr + 5)]))
    path = os.path.join(PACKET_DIR, "callers.objdump.txt")
    with open(path, "w") as f:
        f.write("".join(parts))
    print("wrote %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
