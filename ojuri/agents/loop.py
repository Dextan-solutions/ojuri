"""Ojuri dual-agent orchestrator loop.

Coordinates the Investigator (calls MCP primitives, produces a FindingsReport)
and the Auditor (reads the audit log only, verdicts each finding) across
bounded self-correction iterations until the Auditor verdicts everything
VERIFIED or the iteration budget is exhausted.

Architecture:
  * Investigator runs `claude -p` from the repository root, where .mcp.json
    grants Ojuri MCP tool access.
  * Auditor runs `claude -p` from an EMPTY working directory with NO
    .mcp.json and --strict-mcp-config, so it has zero MCP tools. The
    no-tool-access constraint is architecturally enforced, not prompted.
  * The Investigator tool list is DYNAMIC: it is derived from the running
    server module's list_tools(), so adding a primitive updates the prompt.
  * Both agents are launched with --allowedTools for a surgical permission
    grant (claude -p defaults to DENYING tool calls — there is no human to
    approve them). The Investigator may call the 4 Ojuri MCP primitives
    (list_evidence_artefacts, get_registry_autostarts, get_prefetch_entries,
    get_mft_timeline) plus Write. The Auditor may only call Read and Write,
    and additionally runs with --strict-mcp-config so no MCP tools are even
    loaded. This prevents prompt-injection escalation into arbitrary tools.

Usage:
    python -m ojuri.agents.loop \\
        --question "What persistence is configured?" \\
        --evidence-id case_001 \\
        --output analysis/case_001/ \\
        --evidence-root /evidence/case_001 \\
        [--max-iterations 3]

The orchestrator no longer accepts per-artefact paths. The Investigator
discovers them itself by calling list_evidence_artefacts(evidence_root) as
its mandatory first MCP call.

Exit codes:
    0  success           all verdicts VERIFIED in the final iteration
    2  inconclusive       max iterations reached with DISPUTED/INSUFFICIENT
    3  audit log invalid  pre-flight chain verifier failed
    4  investigator timeout
    5  auditor timeout
    6  configuration error (e.g. unparseable agent output / missing server)
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess  # noqa: F401  (referenced in docs/tests; spawn via asyncio)
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ojuri.agents.auditor_verdict import AuditReport, read_audit_report
from ojuri.agents.finding import (
    FindingsReport,
    read_findings_report,
    write_findings_report,
)

MAX_ITERATIONS_HARD_CAP = 10
DEFAULT_MAX_ITERATIONS = 3
INVESTIGATOR_TIMEOUT_SEC = 1800  # 30 min
AUDITOR_TIMEOUT_SEC = 600  # 10 min

REPO_ROOT = Path(__file__).resolve().parents[2]
INVESTIGATOR_TEMPLATE = (
    REPO_ROOT / "ojuri" / "agents" / "investigator" / "system_prompt.md"
)
AUDITOR_TEMPLATE = REPO_ROOT / "ojuri" / "agents" / "auditor" / "system_prompt.md"
VERIFY_CHAIN = REPO_ROOT / "scripts" / "verify_chain.py"

# Exit codes (also documented in the module docstring).
EXIT_SUCCESS = 0
EXIT_INCONCLUSIVE = 2
EXIT_AUDIT_INVALID = 3
EXIT_INVESTIGATOR_TIMEOUT = 4
EXIT_AUDITOR_TIMEOUT = 5
EXIT_CONFIG_ERROR = 6


class AgentError(Exception):
    """Carries an orchestrator exit code for a non-recoverable agent failure."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI args and environment.

    --max-iterations (CLI) overrides OJURI_MAX_ITERATIONS (env), which
    overrides DEFAULT_MAX_ITERATIONS. The result is hard-capped at
    MAX_ITERATIONS_HARD_CAP regardless of input.
    """
    parser = argparse.ArgumentParser(
        prog="ojuri.agents.loop",
        description="Investigator/Auditor bounded self-correction loop.",
    )
    parser.add_argument("--question", required=True, help="Analyst case question.")
    parser.add_argument("--evidence-id", required=True, help="Evidence/case id.")
    parser.add_argument("--output", required=True, help="Output directory.")
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help=f"Max iterations (default {DEFAULT_MAX_ITERATIONS}, hard cap "
        f"{MAX_ITERATIONS_HARD_CAP}).",
    )
    parser.add_argument(
        "--evidence-root",
        required=True,
        help=(
            "Absolute path to the mounted evidence root (under /evidence/ or "
            "/var/lib/ojuri/raw/). The Investigator discovers artefact paths "
            "from this via list_evidence_artefacts."
        ),
    )
    args = parser.parse_args(argv)

    # Resolve max iterations: CLI > env > default, then hard-cap.
    if args.max_iterations is not None:
        resolved = args.max_iterations
    else:
        env_val = os.environ.get("OJURI_MAX_ITERATIONS")
        resolved = int(env_val) if env_val else DEFAULT_MAX_ITERATIONS
    if resolved < 1:
        resolved = 1
    if resolved > MAX_ITERATIONS_HARD_CAP:
        resolved = MAX_ITERATIONS_HARD_CAP
    args.max_iterations = resolved

    # Validate --output directory is creatable.
    out = Path(args.output).expanduser().resolve()
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        parser.error(f"--output directory not creatable: {e}")
    args.output = str(out)

    # Validate --evidence-root: same whitelist as the discovery primitive,
    # plus it must exist as a directory.
    from ojuri.mcp_server.primitives.list_evidence_artefacts import (
        ALLOWED_EVIDENCE_PREFIXES,
        _path_is_whitelisted,
    )

    ev = args.evidence_root
    if not ev.startswith("/"):
        parser.error(f"--evidence-root must be an absolute path: {ev!r}")
    if ".." in ev or any(c in ev for c in (";", "|", "&", "`", "$", "(", ")", "\n", "\r")):
        parser.error(f"--evidence-root contains unsafe characters: {ev!r}")
    if not _path_is_whitelisted(ev):
        parser.error(
            f"--evidence-root must be under "
            f"{' or '.join(ALLOWED_EVIDENCE_PREFIXES)}: {ev!r}"
        )
    if not Path(ev).is_dir():
        parser.error(f"--evidence-root is not an existing directory: {ev!r}")

    return args


# --------------------------------------------------------------------------- #
# Pre-flight: independent audit-chain verification
# --------------------------------------------------------------------------- #
async def pre_flight(audit_log_path: Path) -> bool:
    """Verify the audit chain via scripts/verify_chain.py.

    On the first run the audit log does not exist yet (no MCP calls have
    been made); there is no chain to verify, so this returns True.
    Returns False if the verifier exits non-zero.
    """
    audit_log_path = Path(audit_log_path)
    if not audit_log_path.exists() or audit_log_path.stat().st_size == 0:
        print(f"[pre-flight] No prior audit log at {audit_log_path}; nothing to verify.")
        return True

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(VERIFY_CHAIN),
        str(audit_log_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    ok = proc.returncode == 0
    print(f"[pre-flight] verify_chain.py exit={proc.returncode}")
    if not ok:
        sys.stderr.write(stdout.decode("utf-8", "replace"))
        sys.stderr.write(stderr.decode("utf-8", "replace"))
    return ok


# --------------------------------------------------------------------------- #
# Dynamic tool list (Design Decision 1)
# --------------------------------------------------------------------------- #
async def get_tool_list() -> list[str]:
    """Return formatted MCP tool descriptions from the server module.

    Implementation: introspect the running server module's list_tools()
    handler. This keeps the Investigator prompt's tool list DYNAMIC —
    adding a primitive in server.py automatically updates the prompt.
    (Future: dynamic introspection via a live MCP stdio session.)
    """
    try:
        from ojuri.mcp_server import server as mcp_server

        tools = await mcp_server.list_tools()
    except Exception as e:  # pragma: no cover - defensive
        raise AgentError(
            EXIT_CONFIG_ERROR, f"cannot introspect MCP server tools: {e}"
        ) from e

    lines: list[str] = []
    for tool in tools:
        schema = tool.inputSchema or {}
        params = list((schema.get("properties") or {}).keys())
        first_sentence = (tool.description or "").strip().split(". ")[0].strip()
        lines.append(f"- {tool.name}({', '.join(params)}) — {first_sentence}.")
    return lines


# --------------------------------------------------------------------------- #
# Prompt construction
# --------------------------------------------------------------------------- #
async def build_investigator_prompt(
    template_path: Path,
    iteration: int,
    max_iterations: int,
    tool_list: list[str],
    case_question: str,
    evidence_paths: dict,
    prior_findings_path: Path | None,
    prior_verdicts_path: Path | None,
    findings_out_path: Path | None = None,
) -> str:
    """Load the template, substitute placeholders, append a run addendum."""
    template = Path(template_path).read_text(encoding="utf-8")
    body = (
        template.replace("{TOOL_LIST}", "\n".join(tool_list))
        .replace("{ITERATION}", str(iteration))
        .replace("{MAX_ITERATIONS}", str(max_iterations))
    )

    addendum = [
        "",
        "---",
        "## THIS RUN",
        "",
        f"CASE QUESTION: {case_question}",
        f"EVIDENCE PATHS: {json.dumps(evidence_paths, sort_keys=True)}",
    ]
    if iteration > 1:
        addendum.append(
            f"PRIOR FINDINGS: see {prior_findings_path}. "
            f"PRIOR VERDICTS: see {prior_verdicts_path}. "
            "Address every DISPUTED/INSUFFICIENT verdict."
        )
    if findings_out_path is not None:
        addendum.append(
            f"WRITE YOUR FINDINGS REPORT TO THIS EXACT PATH: {findings_out_path}"
        )
    return body + "\n".join(addendum) + "\n"


async def build_auditor_prompt(
    template_path: Path,
    iteration: int,
    audit_log_path: Path,
    findings_path: Path,
    verdicts_out_path: Path,
) -> str:
    """Load the Auditor template and append the concrete file paths."""
    template = Path(template_path).read_text(encoding="utf-8")
    body = template.replace("{ITERATION}", str(iteration))
    addendum = [
        "",
        "---",
        "## THIS RUN",
        "",
        f"AUDIT LOG (read): {audit_log_path}",
        f"INVESTIGATOR FINDINGS (read): {findings_path}",
        f"WRITE YOUR AUDIT REPORT TO THIS EXACT PATH: {verdicts_out_path}",
    ]
    return body + "\n".join(addendum) + "\n"


# --------------------------------------------------------------------------- #
# Subprocess helpers
# --------------------------------------------------------------------------- #
def _extract_report_json(stdout: bytes) -> str | None:
    """Best-effort: pull a JSON object out of `claude --output-format json`.

    The envelope looks like {"type":"result","result":"<text>", ...}; the
    report JSON is usually inside `result`. Fall back to the first balanced
    {...} span anywhere in stdout.
    """
    text = stdout.decode("utf-8", "replace").strip()
    if not text:
        return None
    candidates: list[str] = []
    try:
        env = json.loads(text)
        if isinstance(env, dict) and isinstance(env.get("result"), str):
            candidates.append(env["result"])
        elif isinstance(env, dict):
            candidates.append(text)
    except json.JSONDecodeError:
        candidates.append(text)
    for cand in candidates:
        start = cand.find("{")
        end = cand.rfind("}")
        if start != -1 and end > start:
            return cand[start : end + 1]
    return None


async def _run_claude(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    timeout_code: int,
    label: str,
) -> bytes:
    """Spawn `claude`, enforce a timeout, return stdout bytes."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(cwd),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError as e:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        raise AgentError(
            timeout_code, f"{label} exceeded {timeout}s timeout"
        ) from e
    if proc.returncode not in (0, None):
        sys.stderr.write(stderr.decode("utf-8", "replace"))
    return stdout or b""


async def run_investigator(prompt: str, output_dir: Path, iteration: int) -> Path:
    """Run the Investigator from the repo root (has .mcp.json for MCP tools)."""
    output_dir = Path(output_dir)
    findings_path = output_dir / f"findings_iter{iteration}.json"

    env = dict(os.environ)
    # Route MCP audit records to this run's audit log so pre-flight and the
    # Auditor see the same chain.
    env["OJURI_AUDIT_LOG"] = str(output_dir / "audit.log")

    cmd = [
        "claude",
        "-p",
        prompt,
        "--output-format",
        "json",
        # Surgical permission grant: the Investigator may call exactly the 4
        # Ojuri MCP primitives plus Write (to record findings_iterN.json).
        # claude -p defaults to DENYING tool calls (no human to approve), so
        # the allowed list is mandatory, not optional hardening.
        "--allowedTools",
        "mcp__ojuri__list_evidence_artefacts",
        "mcp__ojuri__get_registry_autostarts",
        "mcp__ojuri__get_user_autostarts",
        "mcp__ojuri__get_prefetch_entries",
        "mcp__ojuri__get_mft_timeline",
        "Write",
    ]
    stdout = await _run_claude(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        timeout=INVESTIGATOR_TIMEOUT_SEC,
        timeout_code=EXIT_INVESTIGATOR_TIMEOUT,
        label="investigator",
    )

    if findings_path.exists():
        return findings_path

    # Fallback: parse the structured stdout for the report JSON.
    extracted = _extract_report_json(stdout)
    if extracted is None:
        raise AgentError(
            EXIT_CONFIG_ERROR,
            f"investigator produced no findings file and no parseable "
            f"JSON on stdout (iteration {iteration})",
        )
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    findings_path.write_text(extracted, encoding="utf-8")
    return findings_path


async def run_auditor(
    prompt: str, output_dir: Path, iteration: int, audit_log_path: Path
) -> Path:
    """Run the Auditor from an EMPTY dir with NO .mcp.json (no MCP tools).

    --strict-mcp-config plus an empty cwd means zero MCP servers are loaded
    regardless of any discoverable configuration: architectural enforcement
    of the Auditor's no-tool-access constraint.
    """
    output_dir = Path(output_dir)
    verdicts_path = output_dir / f"verdicts_iter{iteration}.json"

    sandbox = Path(f"/tmp/ojuri_auditor_{os.getpid()}_{iteration}")
    sandbox.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    cmd = [
        "claude",
        "-p",
        prompt,
        "--output-format",
        "json",
        # Surgical permission grant: the Auditor may only Read (audit log /
        # findings) and Write (verdicts). No MCP tools in the allowed list;
        # --strict-mcp-config below also ensures none are even loaded.
        "--allowedTools",
        "Read",
        "Write",
        "--strict-mcp-config",  # zero MCP servers (none passed via --mcp-config)
        "--add-dir",
        str(Path(audit_log_path).parent),
        "--add-dir",
        str(output_dir),
        # Per-call output payloads (Option B, DECISIONS 2026-05-19): the Auditor
        # reads outputs/seq-N.json to verify payload-level citations. --add-dir
        # already covers subdirectories of the audit-log parent, but the outputs
        # dir is granted explicitly so the access is unambiguous in the audit
        # trail and unaffected if either parent path changes.
        "--add-dir",
        str(Path(audit_log_path).parent / "outputs"),
    ]
    stdout = await _run_claude(
        cmd,
        cwd=sandbox,
        env=env,
        timeout=AUDITOR_TIMEOUT_SEC,
        timeout_code=EXIT_AUDITOR_TIMEOUT,
        label="auditor",
    )

    if verdicts_path.exists():
        return verdicts_path

    extracted = _extract_report_json(stdout)
    if extracted is None:
        raise AgentError(
            EXIT_CONFIG_ERROR,
            f"auditor produced no verdicts file and no parseable JSON on "
            f"stdout (iteration {iteration})",
        )
    verdicts_path.parent.mkdir(parents=True, exist_ok=True)
    verdicts_path.write_text(extracted, encoding="utf-8")
    return verdicts_path


# --------------------------------------------------------------------------- #
# Termination & final report
# --------------------------------------------------------------------------- #
def decide_termination(
    verdicts: AuditReport, iteration: int, max_iterations: int
) -> tuple[bool, str]:
    """Decide whether to stop. Returns (should_terminate, reason)."""
    all_verified = bool(verdicts.verdicts) and all(
        v.verdict == "VERIFIED" for v in verdicts.verdicts
    )
    if all_verified:
        return True, "success"
    if iteration >= max_iterations:
        return True, "inconclusive"
    return False, "continue"


def write_final_report(
    output_dir: Path, last_findings_path: Path, status: str
) -> Path:
    """Copy the last findings to findings.json (final=True) + write status.json."""
    output_dir = Path(output_dir)
    report = read_findings_report(last_findings_path)
    report.final = True
    final_path = output_dir / "findings.json"
    write_findings_report(report, final_path)

    status_doc = {
        "status": status,
        "evidence_findings_count": len(report.findings),
        "iterations_run": report.iteration,
        "final_report": str(final_path),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    (output_dir / "status.json").write_text(
        json.dumps(status_doc, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return final_path


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
async def main() -> int:
    args = parse_args()
    output_dir = Path(args.output)
    audit_log_path = output_dir / "audit.log"

    evidence_paths: dict[str, Any] = {
        "evidence_id": args.evidence_id,
        "evidence_root": args.evidence_root,
    }

    print(
        f"[loop] evidence={args.evidence_id} max_iterations={args.max_iterations} "
        f"output={output_dir}"
    )

    try:
        if not await pre_flight(audit_log_path):
            print("[loop] pre-flight FAILED: audit chain invalid.")
            return EXIT_AUDIT_INVALID

        tool_list = await get_tool_list()
        print(f"[loop] {len(tool_list)} MCP tool(s) available to Investigator.")

        last_findings_path: Path | None = None
        reason = "inconclusive"

        for iteration in range(1, args.max_iterations + 1):
            print(f"\n[loop] ===== iteration {iteration}/{args.max_iterations} =====")
            findings_out = output_dir / f"findings_iter{iteration}.json"
            prior_findings = (
                output_dir / f"findings_iter{iteration - 1}.json"
                if iteration > 1
                else None
            )
            prior_verdicts = (
                output_dir / f"verdicts_iter{iteration - 1}.json"
                if iteration > 1
                else None
            )

            inv_prompt = await build_investigator_prompt(
                INVESTIGATOR_TEMPLATE,
                iteration,
                args.max_iterations,
                tool_list,
                args.question,
                evidence_paths,
                prior_findings,
                prior_verdicts,
                findings_out,
            )
            findings_path = await run_investigator(
                inv_prompt, output_dir, iteration
            )
            findings: FindingsReport = read_findings_report(findings_path)
            last_findings_path = findings_path

            if not findings.findings:
                print(
                    "[loop] WARNING: Investigator produced zero findings; "
                    "treating run as inconclusive."
                )
                reason = "inconclusive"
                break

            aud_prompt = await build_auditor_prompt(
                AUDITOR_TEMPLATE,
                iteration,
                audit_log_path,
                findings_path,
                output_dir / f"verdicts_iter{iteration}.json",
            )
            verdicts_path = await run_auditor(
                aud_prompt, output_dir, iteration, audit_log_path
            )
            verdicts: AuditReport = read_audit_report(verdicts_path)

            should_terminate, reason = decide_termination(
                verdicts, iteration, args.max_iterations
            )
            verified = sum(
                1 for v in verdicts.verdicts if v.verdict == "VERIFIED"
            )
            print(
                f"[loop] iteration {iteration}: {verified}/"
                f"{len(verdicts.verdicts)} VERIFIED -> {reason}"
            )
            if should_terminate:
                break

        if last_findings_path is None:
            print("[loop] No findings were produced at all.")
            return EXIT_CONFIG_ERROR

        status = "success" if reason == "success" else "inconclusive"
        final_path = write_final_report(output_dir, last_findings_path, status)
        print(f"\n[loop] final report: {final_path} (status={status})")

        return EXIT_SUCCESS if reason == "success" else EXIT_INCONCLUSIVE

    except AgentError as e:
        print(f"[loop] FATAL: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
