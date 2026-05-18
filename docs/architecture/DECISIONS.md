# Architecture Decisions Log

**Append-only.** Each entry records: date, decision title, context, alternatives
considered, rationale, and related commits/sections. Never edit or delete a past
entry — supersede it with a new dated entry that references it. Commit hashes are
short SHAs on `main` at time of writing.

---

## 2026-05-13 — Capability-based security for DFIR AI

**Context:** Protocol-SIFT-style designs expose `execute_shell_cmd` to LLMs;
hallucinations then cause real spoliation and fabricated-finding risk.
**Decision:** Replace shell access with typed forensic primitives. The agent can
only call functions the MCP server explicitly exposes; there is no shell.
**Alternatives:** Prompt-only constraints (rejected — LLM adherence is
statistical, not architectural); read-only mount only (rejected — does not
address fabricated findings).
**Rationale:** Architecture beats prompt. Eliminating the capability eliminates
a whole class of failures rather than reducing its probability.
**Related:** ARCHITECTURE.md §3–4; commit `b805874` (initial scaffold of the
capability-layer structure).

---

## 2026-05-14 — stdlib `json.dumps` for canonicalisation (not RFC 8785)

**Context:** The audit chain needs byte-stable serialisation for SHA-256.
**Decision:** Use Python stdlib
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
**Alternatives:** Full RFC 8785 / JCS (rejected — adds a dependency, no stdlib
coverage; functional equivalence for our fixed payload shapes).
**Rationale:** Pragmatic. Our primitive inputs/outputs are a fixed set with no
exotic Unicode or number forms; `sort_keys` + compact separators give
byte-stability. `verify_chain.py` reimplements the same canonicalisation
independently for drift detection.
**Related:** ARCHITECTURE.md §6.2; commit `10bf333` (hash-chained audit logger),
`524c772` (independent verifier).

---

## 2026-05-15 — `pyscca` direct C-extension call (not subprocess)

**Context:** `get_prefetch_entries` must parse Win10 prefetch (`.pf`,
MAM-compressed).
**Decision:** Direct in-process `pyscca` call (the official `libscca` Python
binding). No subprocess.
**Alternatives:** PECmd subprocess (rejected — requires .NET); a third-party
prefetch parser script (rejected — adds a dependency); ad-hoc parser (rejected —
unsafe, not court-vetted).
**Rationale:** `pyscca` is the official libscca binding, license-clean and
in-process. It also demonstrates the capability layer is tool-agnostic
(backend strategy B).
**Related:** ARCHITECTURE.md §5.2–5.3; commit `9bd7c2f`.

---

## 2026-05-16 — MFTECmd subprocess + CSV (not analyzeMFT)

**Context:** `get_mft_timeline` needs robust `$MFT` parsing.
**Decision:** MFTECmd via subprocess with `--csv`; UTF-8-with-BOM handled via
`encoding="utf-8-sig"`.
**Alternatives:** `analyzeMFT --json` (rejected after empirical probe — broken
output: ~6,318 rows for 117 real records, with binary-blob escapes).
**Rationale:** MFTECmd is mature and well-maintained and produces clean CSV.
The BOM-handling requirement was discovered empirically, not assumed.
**Related:** ARCHITECTURE.md §5.2–5.3; commit `b3b1969`.

---

## 2026-05-17 — Dual-agent design: Option 4 + Pattern B + Format 2 + bounded self-correction

**Context:** The Reasoning Layer must address Find Evil!'s "autonomous
execution quality" and "hallucination management" criteria.
**Decision:** Hybrid architecture (Option 4) — Investigator in the main Claude
Code session, Auditor as an isolated subprocess. Auditor reads the audit log
only (Pattern B). Findings are structured records with citations (Format 2).
Bounded self-correction (3 iterations default, hard cap 10).
**Alternatives:** Single session with two personas (rejected — same model
self-reviewing, weak defensibility); two fully separate long-lived processes
(rejected — overcomplicated for the MVP).
**Rationale:** The Auditor's no-tool constraint is architecturally enforced via
subprocess isolation + `--strict-mcp-config`, not prompt-instructed. Structured
findings make verification mechanical.
**Related:** ARCHITECTURE.md §8; [docs/design/agents.md](../design/agents.md);
commit `6074dd4`.

---

## 2026-05-17 — Two-stage evidence layer (open + mount)

**Context:** Need to handle multiple forensic image formats (E01, raw, …) while
preserving the audited hardening properties of `mount_evidence.sh`.
**Decision:** Add `scripts/open_evidence.sh` that detects the format and
prepares a raw filesystem tree; the existing `mount_evidence.sh` does the final
hardening **unchanged**.
**Alternatives:** Extend `mount_evidence.sh` in place (rejected — couples
format handling with hardening); a separate script per format (rejected —
fragments the workflow).
**Rationale:** Separation of concerns. `open_evidence.sh` owns format;
`mount_evidence.sh` owns hardening. Composable, and the audited hardening path
stays stable as formats are added.
**Related:** ARCHITECTURE.md §7; `scripts/open_evidence.sh` (uncommitted at
time of writing — pending review).

---

## 2026-05-17 — Robust read-only mount: kernel `ntfs3` fallback (empirical)

**Context:** First real-evidence mount. `/cases/rocba/rocba-cdrive.e01` is a
single NTFS *volume* image (no Sleuth Kit-recognised partition table; `mmls`
exits 1; `fdisk` reports a false-positive "dos" label with out-of-range
entries). `ntfs-3g` (the default-driver mount) **rejected it** with
`Failed to read last sector (170764286): Invalid argument` — the NTFS-recorded
size is a few sectors larger than the imaged sector count (a missing backup
boot sector, common when a partition rather than a whole disk is imaged).
**Decision:** `open_evidence.sh` mounts via a `loop_mount_ro` helper that tries
the kernel default driver first, then falls back to the in-kernel `ntfs3`
driver with `ro,noatime`. The image mounts cleanly under `ntfs3`.
**Alternatives:** `ntfsfix` (rejected — writes to the volume, destroys chain of
custody); `ntfs-3g -o force` (rejected — enables recovery/write semantics);
computing a partition offset with `mmls`/`losetup` (not applicable — this is a
volume, not a partitioned disk).
**Rationale:** `ntfs3 -o ro` is in-kernel, performs no journal replay or
recovery on a read-only mount, and is non-modifying — forensically safe. This
is standard practice for volume images with a trailing-sector mismatch, not a
workaround. The fallback is generic (default driver still serves clean images
and non-NTFS filesystems). This deviates from the literal Stage-1 sketch
(`mount ewf1` directly), which silently assumed a clean single-volume image;
the deviation is recorded here per the no-silent-deviation rule.
**Related:** ARCHITECTURE.md §7.2–7.3; `scripts/open_evidence.sh`
(`loop_mount_ro`); verified end-to-end on `rocba_test` (Win10 volume: 211
Prefetch `.pf`, `$MFT` 469 MB, `Users/fredr` + `Users/srl-h` NTUSER.DAT).

---

## 2026-05-17 — Baseline evidence: per-file I/O error tolerance

**Context:** First real-evidence baseline (`rocba_test`). `baseline_evidence.py`
aborted on the first `OSError` raised while walking/hashing the tree, blocking
the workflow. The brief anticipated the trigger would be `$GetCurrent/media`-type
`OSError [Errno 5]` (Input/output error) — sectors outside the imaged region.
**Empirically the cause was different** and is recorded here per the
no-silent-deviation rule: on this Win10 volume mounted read-only via the
in-kernel `ntfs3` driver (see 2026-05-17 "Robust read-only mount"), `$GetCurrent`
hashed cleanly and **zero** `Errno 5` occurred. Instead **18,611 files raised
`OSError [Errno 22]` (EINVAL)** — the well-known `ntfs3` behaviour of refusing
reads of transparently NTFS/WOF-compressed files (`ntfs-3g` would decompress
them) — concentrated under `Windows/` (15,843) and `Program Files*/` (2,722).
Also observed: 6 × `Errno 13` (EACCES, incl. 2 `Windows.old/.../DriverStore`
*directories* surfaced via the `os.walk` error callback) and 1 × `Errno 2`
(ENOENT). The error-tolerance requirement is identical regardless of which
errno fires.
**Decision:** Catch `OSError` per-file (`lstat`/`open`/`read`) and per-directory
(via `os.walk(onerror=…)`) during the walk. Maintain a `skipped` list in the
output JSON with `{path, error_class, errno, message}`. Continue baselining the
rest of the tree. Non-zero exit only on catastrophic failure (zero files
hashed). Skipped count is printed to stderr so it is visible to the analyst.
Legacy top-level keys (`total_files`, `total_bytes`, `algorithm`,
`evidence_root`, `baseline_created_utc`) are retained alongside the new
`mount_point`/`baseline_timestamp_utc`/`skipped`/`summary` keys so `--verify`
and the evidence-layer integration test remain green.
**Alternatives:** Crash on first error (rejected — incompatible with real
evidence); silently skip without recording (rejected — chain-of-custody
requires accountability for every file in the source tree). Re-mounting via
`ntfs-3g` to decompress the EINVAL files (out of scope here — the evidence
layer mount path is IMMUTABLE per ARCHITECTURE.md §7.3 and not edited by this
task; logged below as a known limitation).
**Rationale:** Forensic baselining is a tamper-detection mechanism, not an
integrity gate. Files that cannot be hashed today must be recorded as such so
any future change (including the file later becoming readable) is detectable.
**Known limitation (flagged, not fixed here):** 18,611 NTFS/WOF-compressed
system files are unhashed under the `ntfs3` mount. They are *accounted for* in
`skipped` (chain of custody intact) but not yet *content-baselined*. A future
decision should evaluate an `ntfs-3g` re-mount or a WOF-aware reader to close
this gap; this is a driver limitation, not a defect in `baseline_evidence.py`.
**Related:** ARCHITECTURE.md §7.3; `scripts/baseline_evidence.py`; verified
end-to-end on `rocba_test` (**206,679 hashed, 18,618 skipped, 57,804,944,481
bytes hashed**, 649.9 s, exit 0).

---

<!-- Append new decisions below this line. Do not edit entries above. -->

## 2026-05-17 — WOF reparse-point clarification (correction to prior entry)

Context: After committing the per-file I/O error tolerance fix, deeper
investigation revealed the actual nature of the 18,611 skipped files.
The previous entry described them as "transparently NTFS/WOF-compressed
system files." This framing implies the files are *content-compressed*
on the volume — implying a decompressor would solve the problem.
Empirical evidence:
- On ntfs-3g mount of the same volume, these files appear as 34-byte
  symbolic links reporting "unsupported reparse tag 0x80000017".
- stat output: "unsupported reparse tag 0x80000017" — this is
  IO_REPARSE_TAG_WOF, the Windows Overlay Filter reparse tag.
- WOF reparse points are NOT compressed file content stored in NTFS.
  They are *pointers* to a separate WIM (Windows Imaging Format) backing
  store. Actual file content lives in that backing store, indexed by
  the reparse point's metadata.
- Reading these files requires (a) Windows' kernel WOF driver, or
  (b) a Linux WOF decompressor library that locates the WIM backing
  store and decompresses the indexed bytes using Microsoft's XPRESS
  compression variants. No mature Linux implementation exists for (b).
- Dual-FUSE strategy (ntfs3 primary + ntfs-3g secondary mount) was
  empirically tested and DOES NOT help — both drivers fail at the
  same WOF reparse-tag layer.
Decision: Document the correct root cause. The baseline limitation is
a fundamental Linux NTFS-driver constraint, not an Ojuri defect.
Roadmap path forward is a native Windows port of Ojuri, not a Linux
workaround.
Alternatives explored and rejected:
- ntfs-3g -o force,ro as primary mount: rejected — force flag bypasses
  volume validation that exists for tamper detection; chain-of-custody
  question outweighs the marginal benefit.
- Dual-FUSE mount (ntfs3 + ntfs-3g): empirically tested; ntfs-3g hits
  same wall on WOF reparse points. No benefit.
- Native Linux WOF decompressor library: out of scope; no mature
  production-grade implementation exists; building one is 200-500
  hours of engineering effort.
- Native filesystem access via Python NTFS library instead of mounted
  volume: substantial new architecture replacing the kernel-mount
  read-only enforcement; out of scope.
Rationale: The skipped files are system DLLs, MSIX bundle contents,
and Windows catalog files. Empirical analysis of the rocba_test
baseline confirmed: of 18,618 skipped paths, 0 are in user document
directories. The IP-theft demo case's analytical evidence (NTUSER.DAT,
SYSTEM hive, MFT, Prefetch, OneDrive/Dropbox/iCloud content
directories) all hashed successfully.
Related: ARCHITECTURE.md §7.3 (corrected); §12 roadmap (native
Windows port added); scripts/baseline_evidence.py (no code change —
the per-file tolerance is exactly right regardless of cause).

---

## 2026-05-17 — Evidence discovery primitive (mandatory first call)

Context: The first three primitives (registry/prefetch/MFT) require explicit
paths to artifacts. The orchestrator was passing these via CLI flags
(--ntuser-hive, --prefetch-dir, --mft-file). This couples the orchestrator
to case-specific knowledge and prevents the agent from autonomously discovering
evidence on new cases. Per ARCHITECTURE.md §8 (Reasoning Layer) and the
Find Evil! "autonomous execution quality" criterion, the agent should
discover its own evidence paths.
Decision: Implement list_evidence_artefacts as the 4th MCP primitive.
Output schema includes user profiles, system hives, prefetch directories,
and MFT files. Mandatory: the Investigator system prompt requires this
primitive be called first on every case. The orchestrator's CLI now
requires --evidence-root (replacing --ntuser-hive/--prefetch-dir/--mft-file).
Alternatives: Optional discovery (rejected — leaves the door open for the
Investigator to skip discovery and miss artifacts); scripted helper that
prints paths (rejected — outside the audit chain; not chain-of-custody
compliant); discovery as part of evidence layer (rejected — would couple
evidence opening to NTFS knowledge; better as a separate primitive).
Rationale: Pure-Python walk, no subprocess, tolerant of partial failures.
This is the fourth backend pattern (in addition to subprocess+regex,
direct library, subprocess+CSV).
Related: ARCHITECTURE.md §5.2, §8; ojuri/mcp_server/primitives/list_evidence_artefacts.py;
ojuri/agents/loop.py main(); verified end-to-end on rocba_test.

## 2026-05-18 — Permission model: --allowedTools per agent
Context: First real agent run (run1, evidence rocba_test) failed with
Investigator unable to call any MCP primitive. Empirical investigation
showed claude -p (non-interactive) defaults to DENYING tool calls
because there's no human to approve them. Permission denial returned
immediately without surfacing as a JSON parse error — instead Claude
returned a polite "tool was blocked" message in the result field.
Decision: Use --allowedTools <list> per agent rather than the broader
--dangerously-skip-permissions:
- Investigator: mcp__ojuri__list_evidence_artefacts, mcp__ojuri__get_registry_autostarts,
  mcp__ojuri__get_prefetch_entries, mcp__ojuri__get_mft_timeline, Write
- Auditor: Read, Write (plus existing --strict-mcp-config)
The Investigator can call only the 4 forensic primitives plus file Write;
it cannot call Bash, Edit, web fetch, or any other built-in tool. The
Auditor cannot call MCP tools at all (allowed list excludes them; also
--strict-mcp-config means none are loaded).
Alternatives:
- --dangerously-skip-permissions: works but bypasses all permission
  checks. Too broad. If the prompt is somehow manipulated to invoke
  Bash, it would execute. The narrower --allowedTools defends against
  prompt-injection escalation.
- Use Claude Code interactive mode (no -p flag): requires human approval
  per tool call. Incompatible with autonomous orchestrator.
- Pre-approve tools in .claude/settings.local.json: works but mixes
  test-environment trust with orchestrator-environment trust; less
  auditable.
Rationale: Surgical permission per agent matches the existing trust
boundary design (Pattern B in §8). The Investigator has access to
exactly what it needs; the Auditor has even less.
Related: ojuri/agents/loop.py (run_investigator, run_auditor cmd lists);
ARCHITECTURE.md §8 (Reasoning Layer; add note about --allowedTools);
first real agent run on rocba_test.

## 2026-05-18 — User-scope persistence primitive (get_user_autostarts)
Context: First real agent run (run2) revealed F-002 — no Ojuri primitive
parses NTUSER.DAT (per-user / HKCU), so user-account-scoped login
persistence is invisible. The case question "what persistence is
configured for the fredr account?" cannot be answered by HKLM data alone.
Decision: Add get_user_autostarts(ntuser_hive_path) as the 5th primitive.
Mirrors get_registry_autostarts (same rip.pl backend, same 'run' plugin
— rip.pl auto-detects hive root). Returns Run/RunOnce/RunOnceEx entries
from the user hive. Investigator's discovery output already provides
NTUSER.DAT paths per user.
Alternatives: Extend get_registry_autostarts with an optional
ntuser_hive parameter (rejected — conflates HKLM and HKCU scopes in one
tool, harder for Investigator to reason about); separate output schema
would still be needed.
Rationale: Separate primitive with clear scope. Backend strategy A
(subprocess+regex) reused. Investigator can choose HKLM, HKCU, or both
based on the case question.
Out of scope for v0: Winlogon (Shell, Userinit), Shell Folders Startup,
and other user-scope persistence vectors — roadmap.
Related: ARCHITECTURE.md §5.2 (new spec); ojuri/mcp_server/primitives/user_autostarts.py;
ojuri/agents/investigator/system_prompt.md (HKCU guidance added).
