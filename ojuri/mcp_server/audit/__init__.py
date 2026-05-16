"""Hash-chained audit logger for MCP tool invocations.

Every tool call writes a JSONL record to an append-only log. Each record's
this_record_hash incorporates the previous record's this_record_hash, forming
a tamper-evident chain.

Configuration:
  OJURI_AUDIT_LOG  Path to the audit log file. Defaults to ~/ojuri/analysis/audit.log.

Hashing:
  Canonical form  json.dumps(obj, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
  Hash function   SHA-256, presented as "sha256:<hex>"

Failure semantics:
  Fail-closed. If write fails, raise AuditWriteError; callers must propagate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger("ojuri.audit")

ZERO_HASH = "sha256:" + ("0" * 64)


class AuditWriteError(RuntimeError):
    """Raised when the audit logger cannot durably record an event."""


def _canonical(obj: Any) -> bytes:
    """Canonicalise an object for hashing. Stable byte representation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_value(value: Any) -> str:
    """Hash an arbitrary JSON-serialisable value. Exposed for callers that
    want to hash input/output payloads before passing them to record()."""
    return _sha256(_canonical(value))


class AuditLogger:
    """Append-only hash-chained audit logger. Thread-safe; one instance per process."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self._lock = Lock()
        self._sequence = 0
        self._last_hash = ZERO_HASH
        self._ensure_log_dir()
        self._recover_chain_state()

    def _ensure_log_dir(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _recover_chain_state(self) -> None:
        """If the log exists with prior records, restore sequence + last_hash
        by reading the final line. New process must continue the existing chain."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            logger.info("Audit log empty or missing; starting fresh chain at %s", self.log_path)
            return

        # Read final line. Log is JSONL, append-only. Open in binary to avoid
        # surprises with line endings.
        last_line: bytes | None = None
        with self.log_path.open("rb") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if last_line is None:
            return

        try:
            rec = json.loads(last_line.decode("utf-8"))
            self._sequence = int(rec["sequence"])
            self._last_hash = rec["this_record_hash"]
            logger.info(
                "Recovered audit chain state: sequence=%d, last_hash=%s",
                self._sequence, self._last_hash[:24] + "...",
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise AuditWriteError(
                f"Audit log {self.log_path} has unparseable final record: {e}"
            ) from e

    def record(self, tool_name: str, input_payload: Any, output_payload: Any) -> dict:
        """Write one audit record. Returns the record dict (for tests/verification)."""
        with self._lock:
            self._sequence += 1
            input_hash = hash_value(input_payload)
            output_hash = hash_value(output_payload)
            timestamp_utc = datetime.now(timezone.utc).isoformat()

            # Build record WITHOUT this_record_hash, hash it, then add the hash.
            record_without_self_hash = {
                "input_hash": input_hash,
                "output_hash": output_hash,
                "previous_record_hash": self._last_hash,
                "sequence": self._sequence,
                "timestamp_utc": timestamp_utc,
                "tool_name": tool_name,
            }
            self_hash = _sha256(_canonical(record_without_self_hash))
            full_record = dict(record_without_self_hash)
            full_record["this_record_hash"] = self_hash

            # Serialise (canonical, so verifier can reproduce) and append.
            line = _canonical(full_record) + b"\n"
            try:
                with self.log_path.open("ab") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                # Roll back in-memory state so we don't claim a record that didn't land.
                self._sequence -= 1
                raise AuditWriteError(f"Failed to write audit record: {e}") from e

            self._last_hash = self_hash
            logger.info(
                "Audit record %d written: tool=%s hash=%s",
                self._sequence, tool_name, self_hash[:24] + "...",
            )
            return full_record


_active_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the active audit logger. Raises if init_audit_logger hasn't been called."""
    if _active_logger is None:
        raise RuntimeError("Audit logger not initialised. Call init_audit_logger() at server startup.")
    return _active_logger


def init_audit_logger(log_path: Path | None = None) -> AuditLogger:
    """Initialise the singleton audit logger. Called once at server startup."""
    global _active_logger
    if log_path is None:
        env = os.environ.get("OJURI_AUDIT_LOG")
        if env:
            log_path = Path(env).expanduser().resolve()
        else:
            log_path = Path.home() / "ojuri" / "analysis" / "audit.log"
    _active_logger = AuditLogger(log_path)
    logger.info("Audit logger initialised at %s", log_path)
    return _active_logger
