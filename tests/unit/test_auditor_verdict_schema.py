"""Unit tests for ojuri.agents.auditor_verdict.

Covers the non-VERIFIED-requires-reasons validator, mixed verdicts,
reason-code enum, and the audit_log_hash 71-char sha256 format.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from ojuri.agents.auditor_verdict import (
    AuditReport,
    FindingVerdict,
    VerdictReason,
    read_audit_report,
    write_audit_report,
)

GOOD_HASH = "sha256:" + ("a" * 64)  # 71 chars total


def _reason(code: str = "citation_mismatch") -> VerdictReason:
    return VerdictReason(
        code=code,
        detail="Cited sequence 4 holds prefetch, not registry data.",
        audit_entries_examined=[4],
    )


def test_disputed_verdict_requires_reasons() -> None:
    with pytest.raises(ValidationError):
        FindingVerdict(finding_id="F-001", verdict="DISPUTED", reasons=[], iteration=1)
    with pytest.raises(ValidationError):
        FindingVerdict(
            finding_id="F-001", verdict="INSUFFICIENT", reasons=[], iteration=1
        )
    # With a reason it is valid.
    v = FindingVerdict(
        finding_id="F-001", verdict="DISPUTED", reasons=[_reason()], iteration=1
    )
    assert v.verdict == "DISPUTED"


def test_verified_verdict_with_no_reasons_accepted() -> None:
    v = FindingVerdict(finding_id="F-009", verdict="VERIFIED", iteration=2)
    assert v.reasons == []


def test_audit_report_with_mixed_verdicts() -> None:
    report = AuditReport(
        iteration=1,
        timestamp_utc="2026-05-17T00:00:00+00:00",
        verdicts=[
            FindingVerdict(finding_id="F-001", verdict="VERIFIED", iteration=1),
            FindingVerdict(
                finding_id="F-002",
                verdict="DISPUTED",
                reasons=[_reason()],
                iteration=1,
            ),
        ],
        overall="some_disputed",
        audit_log_hash=GOOD_HASH,
    )
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "verdicts_iter1.json"
        write_audit_report(report, path)
        loaded = read_audit_report(path)
        assert loaded.model_dump() == report.model_dump()


def test_verdict_reason_code_constrained() -> None:
    valid = [
        "missing_citation",
        "citation_mismatch",
        "claim_beyond_evidence",
        "contradictory_tools",
        "incoherent_reasoning",
        "missing_tool_call",
    ]
    for code in valid:
        _reason(code)
    with pytest.raises(ValidationError):
        _reason("not_a_real_code")


def test_audit_log_hash_format_enforced() -> None:
    base = dict(
        iteration=1,
        timestamp_utc="2026-05-17T00:00:00+00:00",
        verdicts=[FindingVerdict(finding_id="F-001", verdict="VERIFIED", iteration=1)],
        overall="all_verified",
    )
    AuditReport(**base, audit_log_hash=GOOD_HASH)  # 71 chars OK
    for bad in (
        "sha256:" + "a" * 63,  # too short
        "sha256:" + "a" * 65,  # too long
        "md5:" + "a" * 64,  # wrong algo
        "a" * 64,  # missing prefix
        "sha256:" + "g" * 64,  # non-hex
    ):
        with pytest.raises(ValidationError):
            AuditReport(**base, audit_log_hash=bad)


if __name__ == "__main__":
    test_disputed_verdict_requires_reasons()
    test_verified_verdict_with_no_reasons_accepted()
    test_audit_report_with_mixed_verdicts()
    test_verdict_reason_code_constrained()
    test_audit_log_hash_format_enforced()
    print("All auditor-verdict-schema unit tests passed.")
