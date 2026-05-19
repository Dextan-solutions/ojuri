"""Structured Finding records for Ojuri's Investigator agent (Format 2).

Every claim the Investigator makes is a `Finding` carrying one or more
`FindingCitation`s that point at specific audit-log sequence numbers. The
Auditor (see `auditor_verdict.py`) reads these and verdicts each one.

Encoding rules:
  * Human-readable storage  -> JSON, sort_keys=True, indent=2 (stable on disk).
  * Canonical (for hashing) -> JSON, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False. This mirrors ojuri.mcp_server.audit so a Finding can
    be hashed with the same canonicalisation as the audit log.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Shared id pattern: F- followed by exactly three digits, e.g. F-001.
FINDING_ID_PATTERN = r"^F-\d{3}$"


class FindingCitation(BaseModel):
    """A pointer from a claim to a specific audit-log entry."""

    model_config = ConfigDict(extra="forbid")

    audit_sequence: int = Field(..., ge=1, description="Audit-log sequence number cited.")
    tool_name: str = Field(..., min_length=1, description="MCP tool that produced the entry.")
    relevant_output_path: str = Field(
        ...,
        min_length=1,
        description='Path into the tool output, e.g. "entries[3].file_name".',
    )
    # Empirically bumped 200 -> 500 after run6: real registry-output JSON
    # (e.g. a full SecurityHealth Run entry) exceeded 200 chars and crashed
    # the orchestrator while parsing iter2 findings.
    excerpt: str = Field(
        ...,
        max_length=500,
        description="Verbatim excerpt of the cited value (<=500 chars).",
    )


class FindingClaim(BaseModel):
    """The assertion itself, independent of its supporting citations."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., pattern=FINDING_ID_PATTERN, description='Stable id, "F-NNN".')
    # Empirically bumped 200 -> 500 after run6: nuanced summaries need room
    # (same iter2 parse crash as FindingCitation.excerpt).
    summary: str = Field(..., min_length=1, max_length=500, description="One-line claim.")
    detail: str = Field(..., min_length=1, max_length=2000, description="Reasoning narrative.")
    confidence: Literal["high", "medium", "low"] = Field(
        ..., description="Investigator's confidence in this claim."
    )


class Finding(BaseModel):
    """A single claim plus its evidentiary citations and provenance."""

    model_config = ConfigDict(extra="forbid")

    claim: FindingClaim
    citations: list[FindingCitation] = Field(
        ..., min_length=1, description="At least one citation is required."
    )
    iteration_produced: int = Field(
        ..., ge=1, description="Iteration in which this finding was produced/revised."
    )
    prior_disputed: list[str] = Field(
        default_factory=list,
        description="Verdict/finding ids this revision addresses (iter > 1).",
    )


class FindingsReport(BaseModel):
    """The Investigator's full output for one iteration."""

    model_config = ConfigDict(extra="forbid")

    case_question: str = Field(..., min_length=1, max_length=500)
    iteration: int = Field(..., ge=1)
    timestamp_utc: str = Field(..., min_length=1, description="ISO-8601 UTC timestamp.")
    findings: list[Finding] = Field(default_factory=list)
    final: bool = Field(default=False, description="True only on the copied final report.")


def model_validate_json(raw: str | bytes) -> FindingsReport:
    """Top-level helper: parse raw JSON into a validated FindingsReport."""
    return FindingsReport.model_validate_json(raw)


def canonical_json(report: FindingsReport) -> bytes:
    """Canonical byte encoding for hashing. Matches ojuri.mcp_server.audit."""
    return json.dumps(
        report.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def write_findings_report(report: FindingsReport, path: Path) -> None:
    """Write a FindingsReport as human-readable, byte-stable JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        report.model_dump(mode="json"),
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
    path.write_text(text + "\n", encoding="utf-8")


def read_findings_report(path: Path) -> FindingsReport:
    """Read and validate a FindingsReport from disk."""
    return FindingsReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
