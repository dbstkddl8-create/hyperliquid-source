#!/usr/bin/env python3
"""Build own Rust and compare complete observations to a pre-source plan oracle.

No target instruction evaluator, captured execution, network, or hidden renderer.
The production stdin is only the separately frozen raw input file.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-format-request-controller-94"
COMPONENT = ROOT / "src/node94-format-request-protocol"
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
BODY_SHA = "1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561"
RUSTC_SHA = "ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d"
PROVIDER_AUDIT_SHA = "56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6"
BASE = "3324e50333042b391312515e542279ca21f63dc8"

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def state() -> dict:
    def git(*arguments: str) -> str:
        return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()
    paths = [COMPONENT / name for name in ("lib.rs", "input_only.rs", "independent_tests.rs")]
    paths += [Path(__file__), ROOT / "tests/test_format_request_protocol.py"]
    paths += sorted((PACKET / "oracle").rglob("*"))
    paths = [path for path in paths if path.is_file()]
    return {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain=v1"),
            "pins": git("ls-tree", "HEAD", "references/can1357-hl", "upstream/"),
            "sources": {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in paths}}

def admit_target(path: Path) -> dict:
    snapshot = path.read_bytes()
    if len(snapshot) != 91774280 or digest(snapshot) != TARGET_SHA:
        raise ValueError("full target identity mismatch")
    body = snapshot[22482320:22482320 + 448]
    if digest(body) != BODY_SHA:
        raise ValueError("complete 448-byte body mismatch")
    # Complete authenticated bytes are retained once; no instruction semantics
    # are executed here. The native proof separately binds FDE/PT_LOAD/rows.
    return {"bytes": len(snapshot), "sha256": TARGET_SHA,
            "body_file_offset": 22482320, "body_bytes": len(body), "body_sha256": digest(body)}

def admit_provider(rustc: Path) -> dict:
    prefix = rustc.parent.parent
    audit_raw = (PACKET / "provider/PROVIDER-AUDIT.json").read_bytes()
    if digest(audit_raw) != PROVIDER_AUDIT_SHA:
        raise ValueError("installed research provider audit mismatch")
    audit = json.loads(audit_raw)
    if len(audit["payloads"]) != 103 or audit["payload_count"] != 103:
        raise ValueError("provider payload denominator mismatch")
    for payload in audit["payloads"]:
        relative = Path(payload["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid provider relative path")
        data = (prefix / relative).read_bytes()
        if len(data) != payload["bytes"] or digest(data) != payload["sha256"]:
            raise ValueError("provider payload mismatch: " + str(relative))
    for name, expected in audit["installed_manifest_sha256"].items():
        if digest((prefix / "lib/rustlib" / name).read_bytes()) != expected:
            raise ValueError("installed provider manifest mismatch")
    if digest(rustc.read_bytes()) != RUSTC_SHA:
        raise ValueError("research compiler identity mismatch")
    return {"payloads_checked": 103, "audit_sha256": digest(audit_raw), "rustc_sha256": RUSTC_SHA}

def fixtures() -> tuple[bytes, bytes, list[dict]]:
    freeze = json.loads((PACKET / "oracle/formatter448-freeze.json").read_text())
    loaded = {}
    for name in ("formatter448-authority.json", "formatter448-input.tsv", "formatter448-expected.jsonl"):
        raw = gzip.decompress((PACKET / "oracle" / (name + ".gz")).read_bytes())
        if digest(raw) != freeze[name + "_sha256"]:
            raise ValueError("frozen oracle identity mismatch: " + name)
        loaded[name] = raw
    for name in ("generate_formatter.py", "formatter448-proof.md"):
        if digest((PACKET / "oracle" / name).read_bytes()) != freeze[name + "_sha256"]:
            raise ValueError("pre-source authority mismatch: " + name)
    expected = [json.loads(line) for line in loaded["formatter448-expected.jsonl"].splitlines()]
    if len(expected) != 1066 or len({row["id"] for row in expected}) != 1066:
        raise ValueError("oracle denominator/unique IDs mismatch")
    return loaded["formatter448-input.tsv"], loaded["formatter448-expected.jsonl"], expected

def compare(actual: bytes, expected: list[dict]) -> list[str]:
    rows = [json.loads(line) for line in actual.splitlines()]
    if len(rows) != len(expected):
        raise ValueError("complete transcript count mismatch")
    return [wanted["id"] for found, wanted in zip(rows, expected) if found != wanted]

def run(output: Path, rustc: Path, target: Path, controls: bool) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output must be a new owned path")
    provider_identity = admit_provider(rustc)
    target_identity = admit_target(target)
    inputs, expected_bytes, expected = fixtures()
    before = state()
    output.mkdir(parents=True)
    write_json(output / "before.json", before)
    records = []

    def command(label: str, argv: list[str], stdin: bytes | None = None, expected_exit: int = 0) -> subprocess.CompletedProcess:
        started = time.monotonic()
        result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT, check=False)
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            (output / (label + "." + suffix + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
        records.append({"label": label, "argv": argv, "exit": result.returncode,
                        "seconds": time.monotonic() - started,
                        "stdin_sha256": digest(stdin) if stdin is not None else None,
                        "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
        write_json(output / "commands.json", records)
        if result.returncode != expected_exit:
            raise RuntimeError(label + " failed; raw stdout/stderr retained")
        return result

    command("base-production-absent", ["git", "cat-file", "-e", BASE + ":src/node94-format-request-protocol/lib.rs"], expected_exit=128)
    provider = command("rustc-version", [str(rustc), "-vV"]).stdout.decode()
    if "release: 1.94.1\n" not in provider or "host: x86_64-unknown-linux-gnu\n" not in provider:
        raise ValueError("research compiler release/host mismatch")
    linker = shutil.which("cc")
    if linker is None:
        raise ValueError("native cc linker unavailable")
    command("linker-version", [linker, "--version"])
    link_program = command("linker-program", [linker, "-print-prog-name=ld"]).stdout.decode().strip()
    link_path = shutil.which(link_program)
    if link_path is None:
        raise ValueError("reported linker program unavailable")
    command("ld-version", [link_path, "--version"])
    linker_identity = {"cc": linker, "cc_sha256": digest(Path(linker).resolve().read_bytes()),
                       "ld": link_path, "ld_sha256": digest(Path(link_path).resolve().read_bytes())}
    summary = {"target": target_identity, "provider": provider,
               "provider_identity": provider_identity, "linker": linker_identity,
               "input_sha256": digest(inputs), "expected_sha256": digest(expected_bytes),
               "cases": len(expected), "native_domain_cases": sum(row["status"] != "refused" for row in expected),
               "chosen_refusals": sum(row["status"] == "refused" for row in expected),
               "profiles": [], "mutants": [], "full_current_suite": "NOT_RUN: expanded evaluator families not authorized"}
    common = [str(rustc), "--edition=2021", "-D", "warnings", "-C", "overflow-checks=on", "-C", "linker=" + linker]
    production = COMPONENT / "lib.rs"
    for level in (0, 3):
        directory = output / ("opt" + str(level)); directory.mkdir()
        library = directory / "libnode94_format_request_protocol.rlib"
        compile_library = common + ["--crate-name", "node94_format_request_protocol", "--crate-type=rlib", "-C", "opt-level=" + str(level), str(production), "-o", str(library)]
        command(f"opt{level}-library", compile_library)
        external = ["--extern", "node94_format_request_protocol=" + str(library), "-L", "dependency=" + str(directory)]
        driver = directory / "input-only"
        command(f"opt{level}-driver", common + ["-C", "opt-level=" + str(level), str(COMPONENT / "input_only.rs"), *external, "-o", str(driver)])
        actual = command(f"opt{level}-observations", [str(driver)], inputs).stdout
        mismatches = compare(actual, expected)
        if mismatches:
            write_json(output / "mismatches.json", mismatches)
            raise ValueError("production observations differ from pre-source oracle")
        tests = directory / "independent-tests"
        command(f"opt{level}-tests-build", common + ["--test", "-C", "opt-level=" + str(level), str(COMPONENT / "independent_tests.rs"), *external, "-o", str(tests)])
        command(f"opt{level}-tests-run", [str(tests), "--nocapture"])
        rebuild = directory / "rebuild.rlib"
        command(f"opt{level}-rebuild", compile_library[:-1] + [str(rebuild)])
        if library.read_bytes() != rebuild.read_bytes():
            raise ValueError("identical own-library recipe produced different raw bytes")
        summary["profiles"].append({"opt_level": level, "matched_transcripts": len(expected), "mismatches": mismatches,
                                    "rlib_sha256": digest(library.read_bytes()), "raw_rebuild_equal": True,
                                    "driver_sha256": digest(driver.read_bytes()), "independent_test_methods": 3})

    if controls:
        original = production.read_text()
        mutations = {
            "direct-canonicalized": ("return Ok(requests.write(writer.method.get(), writer.destination, bytes));", "return Ok(u8::from(requests.write(writer.method.get(), writer.destination, bytes) != 0));"),
            "index-not-rebased": ("next_index = index.wrapping_add(1);", "next_index = next_index.wrapping_add(1);"),
            "quantity-from-first-word": ("?.second.get() as u16", "?.data.get() as u16"),
            "outer-method-reloaded": ("requests.write(cached_method, writer.destination, literal)", "requests.write({ let _ = cached_method; writer.method.get() }, writer.destination, literal)"),
        }
        for name, (old, new) in mutations.items():
            if old not in original:
                raise ValueError("semantic mutant marker absent")
            directory = output / name; directory.mkdir()
            source = directory / "lib.rs"; source.write_text(original.replace(old, new))
            library = directory / "libnode94_format_request_protocol.rlib"
            command(name + "-library", common + ["--crate-name", "node94_format_request_protocol", "--crate-type=rlib", "-C", "opt-level=3", str(source), "-o", str(library)])
            driver = directory / "input-only"
            command(name + "-driver", common + [str(COMPONENT / "input_only.rs"), "--extern", "node94_format_request_protocol=" + str(library), "-o", str(driver)])
            mismatches = compare(command(name + "-observations", [str(driver)], inputs).stdout, expected)
            if not mismatches:
                raise ValueError("compiled semantic mutant escaped comparator: " + name)
            summary["mutants"].append({"name": name, "source_sha256": digest(source.read_bytes()),
                                        "mismatches": len(mismatches), "mismatch_ids": mismatches})
        counterfactual = json.loads(expected_bytes.splitlines()[0])
        counterfactual["status"] = 255
        modified = b"\n".join([json.dumps(counterfactual).encode(), *expected_bytes.splitlines()[1:]]) + b"\n"
        if compare(modified, expected) != [expected[0]["id"]]:
            raise ValueError("actual comparator did not catch changed observation")
        summary["comparator_corruption_rejected"] = True
    after = state()
    write_json(output / "after.json", after)
    if before != after:
        raise ValueError("source/head/tree/pin/status changed during build/check")
    if target_identity != admit_target(target) or provider_identity != admit_provider(rustc):
        raise ValueError("target/compiler identity changed during build/check")
    if (digest(Path(linker).resolve().read_bytes()) != linker_identity["cc_sha256"]
            or digest(Path(link_path).resolve().read_bytes()) != linker_identity["ld_sha256"]):
        raise ValueError("linker identity changed during build/check")
    summary["source_state_unchanged"] = True
    write_json(output / "result.json", summary)
    return summary

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", required=True, type=Path)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()
    result = run(args.output.resolve(), args.rustc.resolve(), args.target.resolve(), args.controls)
    print(json.dumps({"cases": result["cases"], "profiles": result["profiles"],
                      "mutants": [{k: v for k, v in row.items() if k != "mismatch_ids"} for row in result["mutants"]]}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
