#!/usr/bin/env python3
"""Regenerate this packet's objdump excerpts from a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-string-ctor-cstr-94/export_excerpts.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. The caller list comes from records.json, so the
callers excerpt always matches the recorded census. Output files
are written next to this script and are byte-identical to the
shipped excerpts when run against the digest-pinned binary with
the same binutils version (GNU binutils 2.42 here).
"""

import argparse
import json
import os
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

PLT_STUBS = (0x5660120, 0x56604D0, 0x5660100, 0x5660430, 0x56604E0)


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
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        rec = json.load(f)
    func = rec["function"]
    with open(os.path.join(PACKET_DIR, "window.objdump.txt"), "w") as f:
        f.write(objdump(args.binary, [
            "-d",
            "--start-address=%s" % func["start_va"],
            "--stop-address=%s" % func["next_fde_start"]]))
    plt_text = ""
    for addr in PLT_STUBS:
        plt_text += objdump(args.binary, [
            "-d",
            "--start-address=%#x" % addr,
            "--stop-address=%#x" % (addr + 16)])
    with open(os.path.join(PACKET_DIR, "plt.objdump.txt"), "w") as f:
        f.write(plt_text)
    with open(os.path.join(PACKET_DIR, "rodata.objdump.txt"), "w") as f:
        f.write(objdump(args.binary, [
            "-s", "--start-address=0x7e0c00", "--stop-address=0x7e0c50"]))
    callers_text = ""
    for site in rec["callers_e8"]:
        addr = int(site, 16)
        callers_text += objdump(args.binary, [
            "-d",
            "--start-address=%#x" % addr,
            "--stop-address=%#x" % (addr + 0x20)])
    with open(os.path.join(PACKET_DIR, "callers.objdump.txt"), "w") as f:
        f.write(callers_text)
    print("excerpts written to %s" % PACKET_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
