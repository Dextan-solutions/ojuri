"""Unit tests for ojuri.agents.finding.

Covers required fields, citation minimum, finding-id pattern, confidence
enum, round-trip stability, and canonical-JSON byte stability.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from ojuri.agents.finding import (
    Finding,
    FindingCitation,
    FindingClaim,
    FindingsReport,
    canonical_json,
    read_findings_report,
    write_findings_report,
)


def _citation() -> FindingCitation:
    return FindingCitation(
        audit_sequence=3,
        tool_name="get_registry_autostarts",
        relevant_output_path="entries[0].program_path",
        excerpt="C:\\Windows\\Temp\\evil.exe",
    )


def _finding(fid: str = "F-001") -> Finding:
    return Finding(
        claim=FindingClaim(
            finding_id=fid,
            summary="Suspicious Run-key persistence found.",
            detail="The SOFTWARE hive Run key references a binary in Temp.",
            confidence="high",
        ),
        citations=[_citation()],
        iteration_produced=1,
    )


def _report() -> FindingsReport:
    return FindingsReport(
        case_question="What persistence is configured?",
        iteration=1,
        timestamp_utc="2026-05-17T00:00:00+00:00",
        findings=[_finding()],
    )


def test_finding_with_all_required_fields_accepted() -> None:
    f = _finding()
    assert f.claim.finding_id == "F-001"
    assert f.citations[0].audit_sequence == 3
    assert f.iteration_produced == 1
    assert f.prior_disputed == []


def test_finding_with_empty_citations_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(
            claim=FindingClaim(
                finding_id="F-002",
                summary="x",
                detail="y",
                confidence="low",
            ),
            citations=[],
            iteration_produced=1,
        )


def test_finding_id_pattern_enforced() -> None:
    for bad in ("F-1", "F-0001", "X-001", "f-001", "001", "F001"):
        with pytest.raises(ValidationError):
            FindingClaim(finding_id=bad, summary="s", detail="d", confidence="high")
    # The canonical form is accepted.
    FindingClaim(finding_id="F-042", summary="s", detail="d", confidence="high")


def test_confidence_values_constrained() -> None:
    for good in ("high", "medium", "low"):
        FindingClaim(finding_id="F-003", summary="s", detail="d", confidence=good)
    with pytest.raises(ValidationError):
        FindingClaim(
            finding_id="F-003", summary="s", detail="d", confidence="certain"
        )


def test_excerpt_500_chars_accepted() -> None:
    FindingCitation(
        audit_sequence=1,
        tool_name="get_registry_autostarts",
        relevant_output_path="entries[0].raw",
        excerpt="x" * 500,
    )


def test_excerpt_501_chars_rejected() -> None:
    with pytest.raises(ValidationError):
        FindingCitation(
            audit_sequence=1,
            tool_name="get_registry_autostarts",
            relevant_output_path="entries[0].raw",
            excerpt="x" * 501,
        )


def test_summary_500_chars_accepted() -> None:
    FindingClaim(
        finding_id="F-001", summary="s" * 500, detail="d", confidence="high"
    )


def test_summary_501_chars_rejected() -> None:
    with pytest.raises(ValidationError):
        FindingClaim(
            finding_id="F-001", summary="s" * 501, detail="d", confidence="high"
        )


def test_findings_report_round_trip() -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "findings_iter1.json"
        original = _report()
        write_findings_report(original, path)
        loaded = read_findings_report(path)
        assert loaded.model_dump() == original.model_dump()


def test_findings_report_canonical_json() -> None:
    r1 = _report()
    # Same data, fields constructed in a different order must hash identically.
    r2 = FindingsReport(
        iteration=1,
        findings=[_finding()],
        timestamp_utc="2026-05-17T00:00:00+00:00",
        case_question="What persistence is configured?",
    )
    assert canonical_json(r1) == canonical_json(r2)
    # Canonical form is sorted and compact.
    decoded = json.loads(canonical_json(r1))
    assert list(decoded.keys()) == sorted(decoded.keys())
    assert b", " not in canonical_json(r1)  # compact separators


if __name__ == "__main__":
    test_finding_with_all_required_fields_accepted()
    test_finding_with_empty_citations_rejected()
    test_finding_id_pattern_enforced()
    test_confidence_values_constrained()
    test_excerpt_500_chars_accepted()
    test_excerpt_501_chars_rejected()
    test_summary_500_chars_accepted()
    test_summary_501_chars_rejected()
    test_findings_report_round_trip()
    test_findings_report_canonical_json()
    print("All finding-schema unit tests passed.")
