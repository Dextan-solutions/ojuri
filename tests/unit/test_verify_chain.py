"""Unit tests for scripts/verify_chain.py.

Tests cover: valid chain returns 0, missing file returns 2, tampered records
return 1 with specific error messages, format mismatches caught.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = REPO_ROOT / "scripts" / "verify_chain.py"

ZERO_HASH = "sha256:" + ("0" * 64)


def run_verifier(log_path: Path, verbose: bool = False) -> tuple[int, str]:
    """Run verify_chain.py as a subprocess. Returns (exit_code, combined_output)."""
    cmd = [sys.executable, str(VERIFY_SCRIPT), str(log_path)]
    if verbose:
        cmd.append("-v")
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def make_valid_log(log_path: Path, n_records: int = 3) -> None:
    """Generate a valid chain using the SAME canonicalisation as the verifier."""
    import hashlib

    def canonical(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def sha256_hex(data):
        return "sha256:" + hashlib.sha256(data).hexdigest()

    previous = ZERO_HASH
    lines = []
    for i in range(1, n_records + 1):
        shadow = {
            "input_hash": sha256_hex(canonical({"x": i})),
            "output_hash": sha256_hex(canonical({"y": i})),
            "previous_record_hash": previous,
            "sequence": i,
            "timestamp_utc": f"2026-05-16T10:00:0{i}+00:00",
            "tool_name": "test_tool",
        }
        self_hash = sha256_hex(canonical(shadow))
        full = dict(shadow)
        full["this_record_hash"] = self_hash
        lines.append(canonical(full) + b"\n")
        previous = self_hash

    with log_path.open("wb") as f:
        for line in lines:
            f.write(line)


def test_valid_log_returns_exit_zero() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.log"
        make_valid_log(log, n_records=3)
        code, output = run_verifier(log)
        assert code == 0, f"expected 0, got {code}\noutput:\n{output}"
        assert "CHAIN VALID" in output, f"expected CHAIN VALID in output:\n{output}"
        assert "Records verified: 3" in output


def test_missing_file_returns_exit_two() -> None:
    code, output = run_verifier(Path("/nonexistent/path/audit.log"))
    assert code == 2, f"expected 2, got {code}"


def test_tampered_self_hash_detected() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.log"
        make_valid_log(log, n_records=2)

        # Tamper with record 1's this_record_hash
        with log.open("rb") as f:
            lines = [l for l in f if l.strip()]
        rec = json.loads(lines[0])
        rec["this_record_hash"] = "sha256:" + ("f" * 64)
        lines[0] = (json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        with log.open("wb") as f:
            for l in lines:
                f.write(l)

        code, output = run_verifier(log)
        assert code == 1, f"expected 1, got {code}\noutput:\n{output}"
        assert "this_record_hash mismatch" in output


def test_broken_chain_link_detected() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.log"
        make_valid_log(log, n_records=3)

        # Tamper with record 2's previous_record_hash so chain breaks
        with log.open("rb") as f:
            lines = [l for l in f if l.strip()]
        rec = json.loads(lines[1])
        rec["previous_record_hash"] = "sha256:" + ("a" * 64)
        lines[1] = (json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        with log.open("wb") as f:
            for l in lines:
                f.write(l)

        code, output = run_verifier(log)
        assert code == 1
        # Either chain break OR self-hash failure (changing previous_record_hash invalidates this_record_hash too)
        assert "chain break" in output or "this_record_hash mismatch" in output


def test_skipped_sequence_detected() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.log"
        make_valid_log(log, n_records=3)

        # Delete record 2 entirely
        with log.open("rb") as f:
            lines = [l for l in f if l.strip()]
        with log.open("wb") as f:
            f.write(lines[0])
            f.write(lines[2])  # skip middle

        code, output = run_verifier(log)
        assert code == 1
        assert "sequence mismatch" in output or "chain break" in output


def test_empty_log_is_valid() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "audit.log"
        log.touch()
        code, output = run_verifier(log)
        assert code == 0
        assert "Records verified: 0" in output


if __name__ == "__main__":
    test_valid_log_returns_exit_zero()
    test_missing_file_returns_exit_two()
    test_tampered_self_hash_detected()
    test_broken_chain_link_detected()
    test_skipped_sequence_detected()
    test_empty_log_is_valid()
    print("All verify_chain tests passed.")
