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
