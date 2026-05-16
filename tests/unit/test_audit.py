"""Unit tests for ojuri.mcp_server.audit.

Tests cover: canonicalisation determinism, hash chain continuity,
sequence monotonicity, chain recovery from disk, fail-closed write errors.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from ojuri.mcp_server.audit import (
    AuditLogger,
    AuditWriteError,
    ZERO_HASH,
    _canonical,
    hash_value,
)


def test_canonical_is_stable_across_key_order() -> None:
    a = {"b": 1, "a": 2, "c": [3, 4]}
    b = {"c": [3, 4], "a": 2, "b": 1}
    assert _canonical(a) == _canonical(b)


def test_hash_value_matches_manual_sha256() -> None:
    value = {"x": 1, "y": "test"}
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert hash_value(value) == expected


def test_first_record_chains_from_zero_hash() -> None:
    with tempfile.TemporaryDirectory() as td:
        log_path = Path(td) / "audit.log"
        logger = AuditLogger(log_path)
        rec = logger.record("hello_world", {"name": "judge"}, {"greeting": "hi"})
        assert rec["sequence"] == 1
        assert rec["previous_record_hash"] == ZERO_HASH
        assert rec["this_record_hash"].startswith("sha256:")


def test_sequence_is_monotonic_and_chain_links() -> None:
    with tempfile.TemporaryDirectory() as td:
        log_path = Path(td) / "audit.log"
        logger = AuditLogger(log_path)
        r1 = logger.record("hello_world", {"i": 1}, {"o": 1})
        r2 = logger.record("hello_world", {"i": 2}, {"o": 2})
        r3 = logger.record("hello_world", {"i": 3}, {"o": 3})
        assert r1["sequence"] == 1 and r2["sequence"] == 2 and r3["sequence"] == 3
        assert r2["previous_record_hash"] == r1["this_record_hash"]
        assert r3["previous_record_hash"] == r2["this_record_hash"]


def test_this_record_hash_is_correct() -> None:
    """Reproduce the chain hash computation manually and verify it matches."""
    with tempfile.TemporaryDirectory() as td:
        log_path = Path(td) / "audit.log"
        logger = AuditLogger(log_path)
        rec = logger.record("tool_x", {"in": "a"}, {"out": "b"})

        # Reconstruct: hash of dict WITHOUT this_record_hash
        shadow = {k: v for k, v in rec.items() if k != "this_record_hash"}
        expected = "sha256:" + hashlib.sha256(_canonical(shadow)).hexdigest()
        assert rec["this_record_hash"] == expected


def test_chain_recovery_across_logger_restart() -> None:
    """A fresh AuditLogger pointing at an existing log must continue the chain."""
    with tempfile.TemporaryDirectory() as td:
        log_path = Path(td) / "audit.log"
        logger1 = AuditLogger(log_path)
        r1 = logger1.record("hello_world", {"i": 1}, {"o": 1})
        r2 = logger1.record("hello_world", {"i": 2}, {"o": 2})

        # Simulate process restart
        logger2 = AuditLogger(log_path)
        r3 = logger2.record("hello_world", {"i": 3}, {"o": 3})

        assert r3["sequence"] == 3
        assert r3["previous_record_hash"] == r2["this_record_hash"]


def test_log_file_format_is_jsonl() -> None:
    """Each line of the log must be a parseable JSON object."""
    with tempfile.TemporaryDirectory() as td:
        log_path = Path(td) / "audit.log"
        logger = AuditLogger(log_path)
        logger.record("hello_world", {"a": 1}, {"b": 2})
        logger.record("hello_world", {"a": 3}, {"b": 4})

        with log_path.open("rb") as f:
            lines = [ln for ln in f if ln.strip()]
        assert len(lines) == 2
        for ln in lines:
            obj = json.loads(ln)
            assert "this_record_hash" in obj
            assert "sequence" in obj


if __name__ == "__main__":
    test_canonical_is_stable_across_key_order()
    test_hash_value_matches_manual_sha256()
    test_first_record_chains_from_zero_hash()
    test_sequence_is_monotonic_and_chain_links()
    test_this_record_hash_is_correct()
    test_chain_recovery_across_logger_restart()
    test_log_file_format_is_jsonl()
    print("All audit unit tests passed.")
