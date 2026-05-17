# Ojuri Agent Design Document

**Version:** 0.1
**Status:** Implemented (Week 3 — dual-agent reasoning layer)
**Scope:** Investigator + Auditor + bounded self-correction loop, on top of the
existing MCP server (3 forensic primitives) and the hash-chained audit logger.

---

## 1. Purpose & Problem Statement

Ojuri's MCP server exposes typed, court-vetted forensic primitives
(`get_registry_autostarts`, `get_prefetch_entries`, `get_mft_timeline`) and
records every call into a tamper-evident, hash-chained audit log
(`ojuri.mcp_server.audit`, verified independently by `scripts/verify_chain.py`).

A single LLM analyst calling those primitives is useful but **not
forensically defensible on its own**: the model can over-claim, mis-cite,
or infer beyond what the tool output actually shows. Digital forensics work
that may end up in court needs *separation of duties* — the entity that
produces conclusions must not be the entity that attests they are supported.

This document specifies the **dual-agent reasoning layer**:

- An **Investigator** that analyses a case by calling Ojuri MCP primitives
  and produces structured, citation-bearing `Finding` records.
- An **Auditor** that **cannot call any primitive** and whose sole job is to
  verify each finding's citations against the cryptographic audit log.
- A **bounded self-correction loop** that iterates the two until every
  finding is `VERIFIED` or the iteration budget is exhausted.

The design goal is *defensibility by construction*: every conclusion is
traceable to a specific, hash-chained audit-log entry, and an independent
agent has attested to that traceability.

---

## 2. Architectural Selection

Four design axes were evaluated. The selected combination:

| Axis | Options considered | Selected |
|------|--------------------|----------|
| Topology | (1) single agent, (2) producer/critic prompt, (3) tool-mediated handoff, (4) **hybrid: two real agents + orchestrator** | **Option 4 (Hybrid)** |
| Auditor access | (A) Auditor shares tools, (B) **Auditor reads audit log only** | **Pattern B** |
| Finding format | (1) freeform prose, (2) **structured records with citations** | **Format 2** |
| Convergence | open-ended vs **bounded self-correction** | **Bounded** |

**Why Option 4 (Hybrid).** A single agent cannot provide separation of
duties. A pure prompt-level "critic" shares the same context and tools and
is trivially capturable by the producer's framing. Two *separately
launched* agents — coordinated by a deterministic Python orchestrator that
owns iteration, timeouts, and exit codes — give us real isolation while
keeping the control flow auditable and testable without invoking an LLM.

**Why Pattern B.** If the Auditor could call the same primitives, it would
be *re-investigating*, not *auditing*. Confining it to the audit log forces
the question that matters in court: *does the recorded evidence support the
claim?* — not *can a second model reach the same conclusion?*

**Why Format 2.** Free prose cannot be mechanically checked. Structured
`Finding`/`FindingCitation` records (Pydantic, `ojuri/agents/finding.py`)
make "claim → cited audit sequence → excerpt" machine-verifiable and make
the Auditor's verdict per-finding and per-reason-code.

**Why bounded self-correction.** Open-ended loops do not terminate
predictably and are unbillable. A hard-capped iteration budget with a
deterministic termination function guarantees the loop halts.

### Component diagram

```
                ┌───────────────────────────────────────────┐
                │            loop.py (orchestrator)          │
                │  parse_args · pre_flight · get_tool_list   │
                │  decide_termination · write_final_report   │
                └───────────────┬───────────────┬───────────┘
                                │               │
                 claude -p      │               │   claude -p
            cwd = repo root     │               │   cwd = EMPTY /tmp dir
            (.mcp.json present) │               │   --strict-mcp-config
                                ▼               ▼
                       ┌────────────────┐  ┌────────────────┐
                       │  Investigator  │  │    Auditor     │
                       │  MCP tools: YES │  │  MCP tools: NO │
                       └───────┬────────┘  └───────┬────────┘
                               │ writes            │ reads
                       findings_iterN.json   audit.log + findings_iterN.json
                               │ MCP calls         │ writes
                               ▼                   ▼
                     ┌──────────────────┐   verdicts_iterN.json
                     │ hash-chained     │
                     │ audit.log        │◄── verify_chain.py (pre-flight)
                     └──────────────────┘
```

---

## 3. Agent Specifications

### 3.1 Investigator — and the DYNAMIC tool list *(decision)*

The Investigator runs `claude -p "<prompt>"` with the working directory set
to the **repository root**, where `.mcp.json` grants access to the Ojuri MCP
server. Its system prompt lives at
`ojuri/agents/investigator/system_prompt.md`.

**The tool list is dynamic, not hardcoded.** The system prompt contains a
`{TOOL_LIST}` template variable. At launch the orchestrator's
`get_tool_list()` introspects the running server module's `list_tools()`
handler (`ojuri.mcp_server.server.list_tools`) and formats one line per
tool — name, input-schema parameter names, and the first sentence of the
tool description — then substitutes it into the prompt via
`build_investigator_prompt()`.

Consequence: **adding a new primitive to `server.py` automatically updates
the Investigator's prompt** on the next run. There is no second place to
edit, so the prompt cannot silently drift from the server's real
capabilities. A future enhancement is to replace static module
introspection with a live MCP stdio `list_tools` round-trip; the function
signature is already shaped for that.

The Investigator must, for every claim, emit a `Finding` with: a
`FindingClaim` (id `F-NNN`, summary, detail, confidence), **≥1**
`FindingCitation` (audit sequence number, tool name, output path, ≤200-char
excerpt), the iteration it was produced in, and an optional `prior_disputed`
list naming the verdicts it addresses.

### 3.2 Auditor — isolation via SUBPROCESS, not the Task tool *(decision)*

The Auditor's no-tool-access constraint is **architecturally enforced, not
prompt-instructed.** It is launched with `claude -p` where:

1. the working directory is a fresh **empty** directory
   (`/tmp/ojuri_auditor_<pid>_<iter>`) that contains **no `.mcp.json`**, and
2. the command passes **`--strict-mcp-config`** with no `--mcp-config`,
   which means *zero* MCP servers are loaded regardless of any
   discoverable configuration.

This is a deliberate change from an earlier sketch that used an in-process
"Task tool" sub-agent. A prompt-instructed or same-process critic can be
induced to "just check this one thing with a tool". Subprocess isolation
removes the capability entirely: the Auditor process has no MCP transport,
so there is nothing to misuse. The Auditor is granted **read-only**
filesystem reach to the audit log directory and the output directory via
`--add-dir`; that grants no MCP tools.

The Auditor reads exactly two files — `audit.log` and
`findings_iterN.json` — and writes exactly one — `verdicts_iterN.json` —
per `ojuri/agents/auditor_verdict.py`. It also computes the SHA-256 of
`audit.log` and records it as `audit_log_hash` for tamper detection at
review time. Its system prompt is at
`ojuri/agents/auditor/system_prompt.md`.

### 3.3 Verdicts

Per finding the Auditor returns one of:

- **VERIFIED** — citation exists, is accurate, is sufficient, and the
  reasoning is a defensible inference.
- **DISPUTED** — at least one check fails; a structured `VerdictReason`
  (`missing_citation`, `citation_mismatch`, `claim_beyond_evidence`,
  `contradictory_tools`, `incoherent_reasoning`, `missing_tool_call`) plus
  detail is mandatory (schema-enforced: non-VERIFIED requires reasons).
- **INSUFFICIENT** — tools were called but produced no evidence relevant
  to the claim.

---

## 4. The Self-Correction Loop & MAX_ITERATIONS *(decision)*

The orchestrator (`ojuri/agents/loop.py`, `main()`) runs:

```
parse_args → pre_flight → get_tool_list
for iteration in 1..max_iterations:
    build_investigator_prompt → run_investigator → read_findings_report
    (zero findings ⇒ inconclusive, break)
    build_auditor_prompt → run_auditor → read_audit_report
    should_terminate, reason = decide_termination(...)
    print status; break if should_terminate
write_final_report → exit code
```

**Iteration budget.** `MAX_ITERATIONS` resolution order:

1. CLI flag `--max-iterations` (highest precedence),
2. environment variable `OJURI_MAX_ITERATIONS`,
3. `DEFAULT_MAX_ITERATIONS = 3`.

The resolved value is then **hard-capped at `MAX_ITERATIONS_HARD_CAP = 10`
by the orchestrator**, regardless of what was requested, and floored at 1.
This guarantees termination even under a misconfigured environment.

**Termination function** (`decide_termination`) is pure and unit-testable:

| Condition | Result |
|-----------|--------|
| every verdict `VERIFIED` | `(True, "success")` |
| any `DISPUTED`/`INSUFFICIENT`, `iteration < max` | `(False, "continue")` |
| any `DISPUTED`/`INSUFFICIENT`, `iteration == max` | `(True, "inconclusive")` |

**Pre-flight.** Before iterating, `pre_flight()` runs
`scripts/verify_chain.py` against the run's `audit.log`. On the very first
run no log exists yet (no MCP calls have been made), so verification is
trivially satisfied. On subsequent runs a broken chain aborts the loop with
exit code 3 — Ojuri will not reason over an audit log it cannot prove
intact.

**Timeouts & exit codes.** Investigator 1800 s, Auditor 600 s, enforced via
`asyncio.wait_for`; the child is killed on overrun.

| Code | Meaning |
|------|---------|
| 0 | success — all verdicts VERIFIED in the final iteration |
| 2 | inconclusive — budget exhausted with DISPUTED/INSUFFICIENT |
| 3 | audit log invalid (pre-flight verifier failed) |
| 4 | investigator timeout |
| 5 | auditor timeout |
| 6 | configuration error (unparseable agent output / missing server) |

---

## 5. Confidence Downgrade — Option A *(decision)*

When the Auditor disputes a finding, the Investigator has **three** ways to
respond on the next iteration, not two:

1. call additional MCP primitives to gather the missing evidence,
2. revise the claim to match what the evidence actually supports, **or**
3. **downgrade the finding's `confidence` to `low`** with a detailed
   explanation in the `detail` field (**Option A**).

The Investigator may **never delete a finding** to escape scrutiny —
findings are revised, downgraded, or replaced, never silently dropped.

Crucially, **a downgraded finding is still audited.** Lowering confidence is
not a way to bypass the Auditor; the Auditor still issues a verdict on the
low-confidence claim, and the final report surfaces the confidence level of
every finding. This models real forensic practice: an analyst is allowed to
say "this is weak but worth recording" — provided they say so explicitly and
it is still checked. Option A keeps weak-but-real signals in the record
instead of forcing a binary keep/escalate choice that would otherwise
pressure the Investigator into over-claiming.

---

## 6. Data Contracts

All schemas are Pydantic v2, `extra="forbid"`, with canonical JSON encoding
(`sort_keys=True`, compact separators, `ensure_ascii=False`) that **matches
`ojuri.mcp_server.audit`** so any report can be hashed with the same
canonicalisation as the audit log. Human-readable on-disk form is the same
JSON with `indent=2` and a trailing newline (byte-stable, sorted keys).

**`ojuri/agents/finding.py`**

- `FindingCitation(audit_sequence ≥1, tool_name, relevant_output_path,
  excerpt ≤200)`
- `FindingClaim(finding_id =~ ^F-\d{3}$, summary 1–200, detail 1–2000,
  confidence ∈ {high,medium,low})`
- `Finding(claim, citations ≥1, iteration_produced ≥1, prior_disputed=[])`
- `FindingsReport(case_question 1–500, iteration ≥1, timestamp_utc,
  findings, final=False)`
- helpers: `model_validate_json`, `canonical_json`,
  `write_findings_report`, `read_findings_report`

**`ojuri/agents/auditor_verdict.py`**

- `VerdictReason(code ∈ 6-value enum, detail 1–500,
  audit_entries_examined=[])`
- `FindingVerdict(finding_id, verdict ∈ {VERIFIED,DISPUTED,INSUFFICIENT},
  reasons=[], iteration ≥1)` — validator: non-VERIFIED ⇒ reasons non-empty
- `AuditReport(iteration ≥1, timestamp_utc, verdicts, overall ∈
  {all_verified,some_disputed,insufficient_evidence}, audit_log_hash)` —
  validator: `audit_log_hash` is exactly `sha256:<64-hex>` (71 chars)
- helpers: `model_validate_json`, `canonical_json`, `write_audit_report`,
  `read_audit_report`

---

## 7. Operational Notes & Testing

**Setup.** `scripts/setup_agents.sh` installs the prompts into Claude Code
config locations: the Investigator prompt becomes `.claude/CLAUDE.md`; the
Auditor prompt is placed at `.claude/agents/auditor.md`.

**Invocation.**

```bash
python -m ojuri.agents.loop \
    --question "What persistence is configured?" \
    --evidence-id case_001 \
    --output analysis/case_001/ \
    [--max-iterations 3] \
    [--ntuser-hive PATH] [--prefetch-dir PATH] [--mft-file PATH]
```

The orchestrator routes MCP audit records for the run to
`<output>/audit.log` (via `OJURI_AUDIT_LOG` in the Investigator's
environment) so the pre-flight verifier and the Auditor observe the same
chain. The final artefacts are `findings.json` (`final=True`) and
`status.json`.

**Claude Code CLI assumptions — verified against `claude --help`
(v2.1.143):**

1. `claude -p "<prompt>"` takes the prompt as a positional argument; the
   system prompt is supplied by `.claude/CLAUDE.md` (Investigator) /
   `.claude/agents/auditor.md` (Auditor), with `--system-prompt`/
   `--append-system-prompt` available if needed.
2. `-p/--print` prints one response and **exits cleanly** (does not await
   further input).
3. `.mcp.json` is auto-discovered from the working directory; running the
   Auditor from an empty directory **plus `--strict-mcp-config`** yields
   genuinely zero MCP tools.

If a future Claude Code release changes any of these, `loop.py` already
falls back to parsing the structured stdout envelope
(`--output-format json`) for the report JSON; the contract is "the agent
either writes the target file or prints the report JSON".

**Tests.**

- `tests/unit/test_finding_schema.py` — required fields, ≥1 citation,
  `F-NNN` pattern, confidence enum, round-trip, canonical-JSON byte
  stability.
- `tests/unit/test_auditor_verdict_schema.py` — non-VERIFIED requires
  reasons, mixed verdicts, reason-code enum, `audit_log_hash` format.
- `tests/integration/test_agent_loop.py` — three scenarios (single-iteration
  success, two-iteration self-correction, max-iterations inconclusive) with
  `asyncio.create_subprocess_exec` mocked. **No real Claude Code is
  invoked.**

All schema and loop tests pass, and the pre-existing forensic-primitive and
audit-log test suite continues to pass unchanged.

---

*End of Ojuri Agent Design Document v0.1.*
