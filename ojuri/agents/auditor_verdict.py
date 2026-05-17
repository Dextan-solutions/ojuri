"""Auditor verdict records for Ojuri's dual-agent loop.

The Auditor reads the cryptographically-chained audit log plus the
Investigator's FindingsReport and emits one `FindingVerdict` per finding.
It never calls an MCP primitive (enforced by subprocess isolation in
ojuri.agents.loop); it only checks citations against the audit log.

Encoding rules mirror `finding.py`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ojuri.agents.finding import FINDING_ID_PATTERN

# "sha256:" (7) + 64 hex chars = 71 chars total.
AUDIT_LOG_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"


class VerdictReason(BaseModel):
    """A structured, machine-checkable reason a finding was not VERIFIED."""

    model_config = ConfigDict(extra="forbid")

    code: Literal[
        "missing_citation",
        "citation_mismatch",
        "claim_beyond_evidence",
        "contradictory_tools",
        "incoherent_reasoning",
        "missing_tool_call",
    ]
    detail: str = Field(..., min_length=1, max_length=500)
    audit_entries_examined: list[int] = Field(default_factory=list)


class FindingVerdict(BaseModel):
    """The Auditor's verdict on one Finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN)
    verdict: Literal["VERIFIED", "DISPUTED", "INSUFFICIENT"]
    reasons: list[VerdictReason] = Field(default_factory=list)
    iteration: int = Field(..., ge=1)

    @model_validator(mode="after")
    def _non_verified_requires_reasons(self) -> "FindingVerdict":
        if self.verdict != "VERIFIED" and not self.reasons:
            raise ValueError(
                f"verdict {self.verdict!r} requires at least one reason"
            )
        return self


class AuditReport(BaseModel):
    """The Auditor's full output for one iteration."""

    model_config = ConfigDict(extra="forbid")

    iteration: int = Field(..., ge=1)
    timestamp_utc: str = Field(..., min_length=1, description="ISO-8601 UTC timestamp.")
    verdicts: list[FindingVerdict] = Field(default_factory=list)
    overall: Literal["all_verified", "some_disputed", "insufficient_evidence"]
    audit_log_hash: str = Field(
        ...,
        pattern=AUDIT_LOG_HASH_PATTERN,
        description='SHA-256 of audit.log, "sha256:<64 hex>" (71 chars).',
    )

    @model_validator(mode="after")
    def _hash_is_71_chars(self) -> "AuditReport":
        if len(self.audit_log_hash) != 71 or not re.match(
            AUDIT_LOG_HASH_PATTERN, self.audit_log_hash
        ):
            raise ValueError(
                "audit_log_hash must be 'sha256:<64 hex>' (71 chars total)"
            )
        return self


def model_validate_json(raw: str | bytes) -> AuditReport:
    """Top-level helper: parse raw JSON into a validated AuditReport."""
    return AuditReport.model_validate_json(raw)


def canonical_json(report: AuditReport) -> bytes:
    """Canonical byte encoding for hashing. Matches ojuri.mcp_server.audit."""
    return json.dumps(
        report.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def write_audit_report(report: AuditReport, path: Path) -> None:
    """Write an AuditReport as human-readable, byte-stable JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        report.model_dump(mode="json"),
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
    path.write_text(text + "\n", encoding="utf-8")


def read_audit_report(path: Path) -> AuditReport:
    """Read and validate an AuditReport from disk."""
    return AuditReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
