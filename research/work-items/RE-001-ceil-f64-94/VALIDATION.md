# Validation record

Run date: 2026-11-02 Asia/Seoul. Source base:
`d3af75257a396c85d20857f421c370ddb8cb40e5`. Host: macOS arm64;
Python 3.14.3, GNU binutils 2.47, Apple LLVM 17.0.0.

Commands run from the repository root. GNU binutils and the installed rustup
directory were prepended to PATH for the repository checks. No shell profile
was changed.

| Command / check | Observed outcome |
| --- | --- |
| `./scripts/setup.sh` | Completed; pinned submodules, LFS inputs, Rust 1.94.1/1.95.0, artifact digests and detached signatures verified |
| `make doctor verify catalogue-check` | Exit 0; analysis ready, all artifact/import/pin checks pass, generated catalogues unchanged |
| `python3 -B research/work-items/RE-001-ceil-f64-94/verify.py` | Exit 0; full target identity, complete code/FDE/data/slot evidence and all controls pass |
| Same verifier with `python3 -O -B` | Exit 0; identical output, checks do not depend on Python assertions |
| Verifier with `--write` to a new ignored file | Regenerated JSON byte-identical to `evidence.json` |
| `python3 -m unittest discover -s tests -p 'test_fde_extents.py' -v` | 18 tests pass |
| GNU and Apple LLVM leaf disassembly | Same 30 instruction boundaries, byte strings and mnemonics; both raw listings retained |
| Numerical equation vs exact rational oracle | 33,066/33,066 cases agree; hashes and counts retained in `evidence.json` |
| Semantic controls | Four incorrect rules detected, with 405 / 8,226 / 9 / 10 mismatches |
| Structural/content corruption controls | Code, constant, relocation and FDE mutations all rejected independently of the full-file digest gate |
| `make test` | Full 957-file suite started; not yet complete at this record's preparation. No full-suite pass is claimed. |

The broad suite uses the repository's unchanged serial isolated runner. Its
result does not supply evidence of target equivalence. The focused checks
validate this packet's declared static scope; there is no reconstructed Rust
component or executable-target comparison to test. Hosted CI and container
builds were not run in this local experiment.
