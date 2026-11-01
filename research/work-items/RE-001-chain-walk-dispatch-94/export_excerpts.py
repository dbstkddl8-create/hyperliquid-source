#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-chain-walk-dispatch-94/export_excerpts.py \
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
    "window.objdump.txt": ("0x514ba10", "0x514bb10"),
    "helper.objdump.txt": ("0x52f5290", "0x52f5430"),
    "sentinel.objdump.txt": ("0x4f8da10", "0x4f8da60"),
    "caller.objdump.txt": ("0x514e550", "0x514e7e0"),
}

PLT_STUBS = (
    # (stub address, stub size) for every PLT entry the packet cites.
    ("0x5660150", 16),  # memcmp
    ("0x5660100", 16),  # memcpy
    ("0x56604d0", 16),  # basic_string _M_create
    ("0x5660440", 16),  # operator delete (sized)
    ("0x5660430", 16),  # __stack_chk_fail
)


def objdump(binary, args):
    result = subprocess.run(["objdump"] + args + [binary],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("objdump failed: %s" % result.stderr.strip())
    return result.stdout


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    for name, (start, stop) in RANGES.items():
        text = objdump(args.binary, [
            "-d",
            "--start-address=%s" % start,
            "--stop-address=%s" % stop])
        with open(os.path.join(PACKET_DIR, name), "w") as f:
            f.write(text)
    plt_text = ""
    for stub, size in PLT_STUBS:
        start = int(stub, 16)
        plt_text += objdump(args.binary, [
            "-d",
            "--start-address=%s" % stub,
            "--stop-address=%#x" % (start + size)])
    with open(os.path.join(PACKET_DIR, "plt.objdump.txt"), "w") as f:
        f.write(plt_text)
    print("wrote %d excerpts" % (len(RANGES) + 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
