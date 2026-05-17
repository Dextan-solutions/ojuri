"""Integration tests for ojuri.agents.loop with MOCKED subprocesses.

These tests never invoke real Claude Code. asyncio.create_subprocess_exec
is monkeypatched with a fake process that writes canned FindingsReport /
AuditReport JSON to the exact path embedded in each agent prompt.

Scenarios:
  1. single-iteration success                -> exit 0, findings.json final
  2. self-correction over two iterations      -> exit 0 after iteration 2
  3. max-iterations inconclusive (always DISPUTED) -> exit 2
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from ojuri.agents import loop
from ojuri.agents.auditor_verdict import (
    AuditReport,
    FindingVerdict,
    VerdictReason,
    canonical_json as audit_canon,
)
from ojuri.agents.finding import (
    Finding,
    FindingCitation,
    FindingClaim,
    FindingsReport,
    canonical_json as find_canon,
)

GOOD_HASH = "sha256:" + ("b" * 64)


# --------------------------------------------------------------------------- #
# Canned-report builders
# --------------------------------------------------------------------------- #
def make_findings(iteration: int, prior_disputed: list[str] | None = None) -> str:
    report = FindingsReport(
        case_question="What persistence is configured?",
        iteration=iteration,
        timestamp_utc="2026-05-17T00:00:00+00:00",
        findings=[
            Finding(
                claim=FindingClaim(
                    finding_id="F-001",
                    summary="Run-key persistence to a Temp binary.",
                    detail="SOFTWARE hive Run key references C:\\Windows\\Temp\\evil.exe.",
                    confidence="high",
                ),
                citations=[
                    FindingCitation(
                        audit_sequence=1,
                        tool_name="get_registry_autostarts",
                        relevant_output_path="entries[0].program_path",
                        excerpt="C:\\Windows\\Temp\\evil.exe",
                    )
                ],
                iteration_produced=iteration,
                prior_disputed=prior_disputed or [],
            )
        ],
    )
    return json.dumps(json.loads(find_canon(report).decode()), indent=2)


def make_verdicts(iteration: int, verdict: str) -> str:
    if verdict == "VERIFIED":
        fv = FindingVerdict(finding_id="F-001", verdict="VERIFIED", iteration=iteration)
        overall = "all_verified"
    else:
        fv = FindingVerdict(
            finding_id="F-001",
            verdict="DISPUTED",
            reasons=[
                VerdictReason(
                    code="citation_mismatch",
                    detail="Cited entry 1 holds prefetch data, not a Run key.",
                    audit_entries_examined=[1],
                )
            ],
            iteration=iteration,
        )
        overall = "some_disputed"
    report = AuditReport(
        iteration=iteration,
        timestamp_utc="2026-05-17T00:00:00+00:00",
        verdicts=[fv],
        overall=overall,
        audit_log_hash=GOOD_HASH,
    )
    return json.dumps(json.loads(audit_canon(report).decode()), indent=2)


# --------------------------------------------------------------------------- #
# Fake subprocess
# --------------------------------------------------------------------------- #
class FakeProc:
    def __init__(self, stdout: bytes = b'{"type":"result","result":"ok"}') -> None:
        self._stdout = stdout
        self.returncode = 0

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""

    async def wait(self) -> int:
        return 0

    def kill(self) -> None:  # pragma: no cover - timeout path not exercised here
        self.returncode = -9


def _target_path(prompt: str, marker: str) -> Path:
    for line in prompt.splitlines():
        if marker in line:
            return Path(line.split(marker, 1)[1].strip())
    raise AssertionError(f"marker {marker!r} not found in prompt")


def make_fake_exec(script: list[tuple[str, str]]):
    """script is an ordered list of (role, json_text); role in {inv, aud}."""
    state = {"i": 0}

    async def fake_exec(*args, **kwargs):
        argv = list(args)
        # pre_flight calls python verify_chain.py; not exercised (no audit.log).
        if argv and argv[0] != "claude":
            return FakeProc(b"")
        prompt = argv[2]
        role, payload = script[state["i"]]
        state["i"] += 1
        if role == "inv":
            path = _target_path(prompt, "WRITE YOUR FINDINGS REPORT TO THIS EXACT PATH:")
        else:
            path = _target_path(prompt, "WRITE YOUR AUDIT REPORT TO THIS EXACT PATH:")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        return FakeProc()

    return fake_exec


def _run(monkeypatch, tmp_path: Path, argv: list[str], script) -> int:
    monkeypatch.setattr("asyncio.create_subprocess_exec", make_fake_exec(script))
    monkeypatch.setattr(sys, "argv", argv)
    return asyncio.run(loop.main())


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
def test_loop_single_iteration_success(monkeypatch, tmp_path) -> None:
    out = tmp_path / "case_001"
    argv = [
        "ojuri.agents.loop",
        "--question",
        "What persistence is configured?",
        "--evidence-id",
        "case_001",
        "--output",
        str(out),
        "--max-iterations",
        "3",
    ]
    script = [
        ("inv", make_findings(1)),
        ("aud", make_verdicts(1, "VERIFIED")),
    ]
    code = _run(monkeypatch, tmp_path, argv, script)
    assert code == 0, f"expected success exit 0, got {code}"

    final = json.loads((out / "findings.json").read_text())
    assert final["final"] is True
    status = json.loads((out / "status.json").read_text())
    assert status["status"] == "success"


def test_loop_self_correction_two_iterations(monkeypatch, tmp_path) -> None:
    out = tmp_path / "case_002"
    argv = [
        "ojuri.agents.loop",
        "--question",
        "What persistence is configured?",
        "--evidence-id",
        "case_002",
        "--output",
        str(out),
        "--max-iterations",
        "3",
    ]
    script = [
        ("inv", make_findings(1)),
        ("aud", make_verdicts(1, "DISPUTED")),
        ("inv", make_findings(2, prior_disputed=["F-001"])),
        ("aud", make_verdicts(2, "VERIFIED")),
    ]
    code = _run(monkeypatch, tmp_path, argv, script)
    assert code == 0, f"expected success exit 0 after iter 2, got {code}"

    assert (out / "findings_iter1.json").exists()
    assert (out / "findings_iter2.json").exists()
    final = json.loads((out / "findings.json").read_text())
    assert final["final"] is True
    assert final["iteration"] == 2
    assert final["findings"][0]["prior_disputed"] == ["F-001"]


def test_loop_max_iterations_inconclusive(monkeypatch, tmp_path) -> None:
    out = tmp_path / "case_003"
    argv = [
        "ojuri.agents.loop",
        "--question",
        "What persistence is configured?",
        "--evidence-id",
        "case_003",
        "--output",
        str(out),
        "--max-iterations",
        "3",
    ]
    script = [
        ("inv", make_findings(1)),
        ("aud", make_verdicts(1, "DISPUTED")),
        ("inv", make_findings(2)),
        ("aud", make_verdicts(2, "DISPUTED")),
        ("inv", make_findings(3)),
        ("aud", make_verdicts(3, "DISPUTED")),
    ]
    code = _run(monkeypatch, tmp_path, argv, script)
    assert code == 2, f"expected inconclusive exit 2, got {code}"

    status = json.loads((out / "status.json").read_text())
    assert status["status"] == "inconclusive"
    final = json.loads((out / "findings.json").read_text())
    assert final["final"] is True


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v"]))
