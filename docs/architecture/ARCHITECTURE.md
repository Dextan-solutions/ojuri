# Ojuri Architecture

> **Version:** v0.1 (markdown source — generated `.docx` versioning tracked separately under `docs/architecture/`)
> **Status:** Living document — Week 3 in progress
> **Last updated:** 2026-05-17
> **See also:** [DECISIONS.md](./DECISIONS.md) · [SOURCE_PROMPT.md](./SOURCE_PROMPT.md) · [Agent design](../design/agents.md)

---

## 1. Purpose

Ojuri is a capability-constrained Model Context Protocol (MCP) server that lets an
LLM reasoning agent perform digital-forensics-and-incident-response (DFIR)
analysis on Windows evidence **without ever holding a shell**. The problem it
solves is *hallucination in AI-assisted DFIR*: an LLM given a shell and a prompt
will, often enough to be disqualifying, invent artefacts, mis-cite timestamps,
or reach conclusions the underlying data does not support — and in forensics a
plausible-sounding false finding is worse than no finding. Ojuri's thesis is
that **capability-based security applied to forensic tooling** turns "please
don't hallucinate or write to evidence" from a statistical prompt-time hope into
an architectural guarantee: the agent can only call a fixed set of typed,
court-vetted primitives, every call is hash-chained into a tamper-evident audit
log, and the evidence is mounted read-only at the kernel level. What the agent
cannot do, it cannot do — regardless of what it is convinced to attempt.

---

## 2. Problem statement

### 2.1 Why current AI-assisted DFIR is hallucination-prone

The common pattern ("Protocol-SIFT-style") is an MCP server that exposes
`execute_shell_cmd` (or equivalent) to an LLM and constrains behaviour through
the system prompt: *"only run read-only commands, never write to the evidence,
cite your sources."* This fails for three structural reasons:

- **Prompt adherence is statistical, not architectural.** An LLM follows
  instructions with high probability, not certainty. A 1-in-200 deviation is
  fine for a chatbot and fatal for a forensic report that may be cross-examined.
- **A shell is an unbounded capability.** `execute_shell_cmd` can read, write,
  delete, network, and execute. No prompt can subtract capability from a tool
  that structurally has it; it can only ask the model not to use it.
- **Free-text output is unverifiable.** When findings are prose, there is no
  mechanical way to check that "the registry shows persistence at
  `Run\Updater`" corresponds to any command that actually ran or any bytes that
  actually existed.

### 2.2 What "defensible" means in DFIR

A finding is *defensible* when it could survive adversarial scrutiny in a legal
or formal-review setting. Operationally that requires:

- **Legal admissibility** — a documented, repeatable method using accepted
  tools, not a black-box model assertion.
- **Audit trail** — a complete, ordered, tamper-evident record of every
  operation performed against the evidence, independently checkable.
- **Evidence integrity** — provable non-modification of source data
  (chain of custody): the analysis cannot have altered what it analysed.

### 2.3 What goes wrong when those properties are absent

- A fabricated artefact ("`evil.exe` ran at 02:14") drives an incident response
  in the wrong direction and, if it reaches a report, discredits the entire
  investigation when challenged.
- A write to source data (even an accidental `atime` update or a tool that
  rebuilds an index) destroys chain of custody for that artefact and is often
  fatal to its admissibility.
- An audit log the analyst can rewrite after the fact proves nothing — its
  existence is security theatre.

Ojuri is built so that each of these is prevented by code, not by instruction.

---

## 3. Threat model

Ojuri defends against three adversary categories. The "adversary" is not
necessarily malicious — the LLM hallucinating in good faith is the primary one.

### 3.1 Hallucinated facts

*The reasoning agent produces a plausible-sounding finding the evidence does not
support.*

- **What defends:** Findings must be structured `Finding` records each carrying
  ≥1 citation to a specific audit-log sequence number with a ≤200-char excerpt
  of real tool output. A second, tool-less **Auditor** agent verifies every
  citation against the cryptographic audit log and issues a per-finding verdict;
  unverifiable findings are `DISPUTED` and the bounded self-correction loop
  forces revision, downgrade, or additional evidence (see §8 and
  [agents.md](../design/agents.md)).
- **What does not defend:** Prompting the model to "be careful"; a single model
  reviewing its own output (same blind spots, capturable by its own framing).

### 3.2 Evidence spoliation

*A write reaches the source image — directly, or as a side effect of a tool.*

- **What defends:** Four independent layers (§7.3): `ewfmount` has no write
  path; the loop-mount is `-o ro`; the bind-mount is remounted
  `ro,noexec,nodev,nosuid`; and a SHA-256 baseline detects any change post hoc.
  The agent never has a shell, so it cannot run an arbitrary writing tool even
  if induced to.
- **What does not defend:** A read-only *prompt instruction* on a writable
  mount; trusting that every backend tool is side-effect-free.

### 3.3 Audit-log tampering

*Someone rewrites the record of what the agent did, after the fact.*

- **What defends:** The audit log is an append-only hash chain — each record
  binds the previous record's hash, so editing or deleting any record breaks
  every subsequent link. `verify_chain.py` is a **stdlib-only, zero-dependency,
  no-`ojuri`-import** verifier that reimplements the canonicalisation
  independently, so writer/reader drift is itself detectable (§6.4).
- **What does not defend:** A plain log file; a log the same process can
  rewrite without detection; a verifier that shares code with the writer (a
  shared bug would hide the very tampering it should catch).

---

## 4. Five-layer architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 1 — REASONING (UNTRUSTED)                                   │
  │  Investigator agent  ·  Auditor agent  ·  loop.py orchestrator     │
  │  May hallucinate. Constrained only by what Layer 2 exposes.        │
  └───────────────────────────────┬──────────────────────────────────┘
                                   │  MCP stdio (typed calls only)
  ════════════════════════════════╪═══════════ TRUST BOUNDARY ════════
                                   │
  ┌───────────────────────────────▼──────────────────────────────────┐
  │  LAYER 2 — CAPABILITY (Ojuri MCP server)                           │
  │  Typed primitives only · Pydantic in/out · path validation        │
  │  Every call hash-chained into the audit log. NO shell exposed.     │
  └───────────────────────────────┬──────────────────────────────────┘
                                   │  in-process backend dispatch
  ┌───────────────────────────────▼──────────────────────────────────┐
  │  LAYER 3 — BACKEND (TRUSTED, swappable)                            │
  │  SIFT MVP: rip.pl · pyscca · MFTECmd. Tool-agnostic interface.     │
  └───────────────────────────────┬──────────────────────────────────┘
                                   │  filesystem reads only
  ┌───────────────────────────────▼──────────────────────────────────┐
  │  LAYER 4 — EVIDENCE (IMMUTABLE)                                    │
  │  open_evidence.sh (format) → mount_evidence.sh (hardening)         │
  │  ro,noexec,nodev,nosuid kernel mount of E01 / raw image.          │
  └──────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────┐
  │  LAYER 5 — VERIFIER (INDEPENDENT)                                  │
  │  verify_chain.py · stdlib-only · no ojuri imports                 │
  │  Re-derives the chain from scratch; detects tampering AND drift.   │
  └──────────────────────────────────────────────────────────────────┘
```

1. **Reasoning Layer (Investigator + Auditor) — UNTRUSTED.** Two LLM agents and
   a deterministic Python orchestrator. Assumed capable of hallucination; never
   trusted, only constrained and audited. Specified in
   [docs/design/agents.md](../design/agents.md); summarised in §8.
2. **Capability Layer (Ojuri MCP server) — TRUST BOUNDARY.** The MCP server in
   `ojuri/mcp_server/server.py`. Exposes a *closed set* of typed forensic
   primitives with Pydantic-validated inputs and outputs. There is no
   general-purpose execution primitive. Every call is recorded into the audit
   chain. **This is the trust boundary**: everything above it is untrusted;
   everything below is deterministic code that can be tested and verified.
3. **Backend Layer (SIFT MVP, swappable) — TRUSTED.** Concrete implementations
   that turn a primitive into facts using court-vetted CLI tools or libraries.
   The interface is tool-agnostic (§5.3); the SIFT backend is the MVP.
4. **Evidence Layer (read-only mounts, format opener) — IMMUTABLE.** A
   two-stage pipeline (§7) that opens a forensic image and exposes its
   filesystem under kernel-enforced read-only, no-exec, no-dev, no-suid mounts.
5. **Verifier (`verify_chain.py`, stdlib-only) — INDEPENDENT.** A standalone
   script that re-derives and checks the entire audit chain with no shared code
   path with the writer, so a writer bug cannot mask tampering.

The single most important property: **#2 is the trust boundary.** Defensibility
does not come from trusting the model; it comes from the model being unable to
do anything the code below the boundary did not verify and record.

---

## 5. Capability Layer: Forensic Primitives

### 5.1 Catalogue (29 analytical designed + 1 discovery, 5 implemented in MVP)

A *primitive* answers one forensic question with a typed result. The full
design catalogue is 29 analytical primitives plus 1 discovery primitive
(`list_evidence_artefacts`, the mandatory first call that locates artefacts
for the rest); 5 are implemented end-to-end. Status legend:
**✓ implemented** · **○ designed, not yet built**.

| # | Primitive | Question it answers | Status |
|---|-----------|---------------------|--------|
| D | `list_evidence_artefacts` | Where are the canonical forensic artefacts on this mount? | ✓ |
| 1 | `get_registry_autostarts` | What is configured to autostart (machine / HKLM)? | ✓ |
| 1a | `get_user_autostarts` | What per-user (HKCU) login persistence is configured? | ✓ |
| 2 | `get_prefetch_entries` | What programs ran, when, how often? | ✓ |
| 3 | `get_mft_timeline` | What is the NTFS filesystem timeline? | ✓ |
| 4 | `get_scheduled_tasks` | What scheduled tasks exist? | ○ |
| 5 | `get_services` | What Windows services are installed/auto-start? | ○ |
| 6 | `get_userassist` | What did the interactive user launch (UserAssist)? | ○ |
| 7 | `get_shimcache` | What executables were seen (AppCompatCache)? | ○ |
| 8 | `get_amcache` | What executables are recorded in Amcache? | ○ |
| 9 | `get_shellbags` | What folders were browsed (ShellBags)? | ○ |
| 10 | `get_jumplists` | What files/apps via Jump Lists? | ○ |
| 11 | `get_lnk_files` | What LNK shortcuts and their targets? | ○ |
| 12 | `get_recent_docs` | What recent documents (RecentDocs)? | ○ |
| 13 | `get_browser_history` | What URLs were visited? | ○ |
| 14 | `get_event_logs` | What security/system events (EVTX)? | ○ |
| 15 | `get_logon_sessions` | What interactive/network logons (4624/4625)? | ○ |
| 16 | `get_usb_devices` | What removable devices were attached? | ○ |
| 17 | `get_network_shares` | What shares/mapped drives existed? | ○ |
| 18 | `get_powershell_history` | What PowerShell ran (ConsoleHost_history)? | ○ |
| 19 | `get_wmi_persistence` | What WMI event-consumer persistence? | ○ |
| 20 | `get_bam_dam` | What execution via BAM/DAM? | ○ |
| 21 | `get_srum` | What app/network resource usage (SRUM)? | ○ |
| 22 | `get_recycle_bin` | What was deleted ($Recycle.Bin / $I)? | ○ |
| 23 | `get_volume_shadow_copies` | What VSS snapshots exist? | ○ |
| 24 | `get_alternate_data_streams` | What NTFS ADS exist? | ○ |
| 25 | `get_file_hashes` | SHA-256 of a specified evidence file. | ○ |
| 26 | `get_string_matches` | Where does a string/IOC appear (bounded)? | ○ |
| 27 | `get_memory_pslist` | What processes in a memory image? | ○ |
| 28 | `get_memory_netscan` | What network artefacts in a memory image? | ○ |

The naming, typed-I/O, validation, and audit pattern is identical for all of
them; the five implemented ones prove the pattern across four backend
strategies (§5.3) — `get_user_autostarts` reuses Strategy A, demonstrating
that a second primitive slots into an existing strategy with no boundary
change. The remaining 25 analytical primitives are roadmap (§12), not
architectural unknowns.

### 5.2 Implemented primitives (full spec)

#### 5.2.1 `get_registry_autostarts`

- **Source:** `ojuri/mcp_server/primitives/registry_autostarts.py`
- **Input (`GetRegistryAutostartsInput`):**
  - `software_hive_path: str` — absolute path to the SOFTWARE hive inside the
    mounted evidence.
  - `system_hive_path: str | None` — optional SYSTEM hive (required for service
    autostarts).
  - Both validated by a `field_validator` rejecting shell metacharacters
    (`; | & \` $ ( ) \n \r`) and `..` traversal.
- **Output (`GetRegistryAutostartsOutput`):**
  - `primitive_name: "get_registry_autostarts"` (literal, anti-spoof)
  - `total_entries: int`
  - `entries: list[AutostartEntry]` where each entry is
    `{name, path, value, last_modified, hive_source, mechanism}` and
    `mechanism ∈ {Run, RunOnceEx, Service}`.
- **Backend:** SIFT — `rip.pl` (RegRipper3) run as a subprocess with multiple
  plugins; output parsed by regex into typed `AutostartEntry` records.
  *(Strategy A: subprocess + regex.)*
- **Test fixture:** `tests/fixtures/NTUSER.DAT` — a real Windows hive from the
  `EricZimmerman/Registry` corpus (MIT-licensed, redistributable).
- **Coverage:** Week-2 Task 1 covers Run keys, RunOnceEx, Service DLL
  autostarts. Future expansion: Winlogon shell, AppInit_DLLs, IFEO.

#### 5.2.5 `get_user_autostarts`

- **Source:** `ojuri/mcp_server/primitives/user_autostarts.py`
- **Role:** the **per-user (HKCU)** companion to `get_registry_autostarts`
  (which is machine-scope / HKLM only). The Run/RunOnce/RunOnceEx keys under
  `HKCU\Software\Microsoft\Windows\CurrentVersion` live in each user's
  `NTUSER.DAT`, not in any machine hive — so user-account-scoped login
  persistence is invisible to `get_registry_autostarts`. Surfaced by the
  first real agent run (run2, finding F-002); see DECISIONS 2026-05-18.
- **Input (`GetUserAutostartsInput`):**
  - `ntuser_hive_path: str` — absolute path to one user's `NTUSER.DAT`, from
    `list_evidence_artefacts` (`user_profiles[].ntuser_dat`). Single hive, not
    a list: the orchestrator calls once per user.
  - Validated by the same `field_validator` as `get_registry_autostarts`,
    rejecting shell metacharacters (`; | & \` ( ) \n \r`), `$(`/`${` shell
    substitution, and `..` traversal — `$` alone is allowed (NTFS naming).
- **Output (`GetUserAutostartsOutput`):**
  - `primitive_name: "get_user_autostarts"` (literal, anti-spoof)
  - `total_entries: int`
  - `entries: list[UserAutostartEntry]` where each entry is
    `{name, path, last_modified|None, mechanism, hive_source, username|None}`
    and `mechanism ∈ {Run, RunOnce, RunOnceEx}`; sorted by
    `(mechanism, name)`. `username` is derived from the hive path's parent
    directory (`.../Users/fredr/NTUSER.DAT` → `fredr`). An empty list is a
    valid result and is itself a finding (no per-user persistence).
  - `ntuser_hive_path: str` — echoed input.
- **Backend:** SIFT — `rip.pl` (RegRipper3) `run` + `runonceex` plugins run
  as a subprocess; rip.pl is hive-aware (auto-detects HKCU vs HKLM root), so
  the same plugins read `NTUSER.DAT`. Output parsed by regex into typed
  records, recovering Run-vs-RunOnce from the key header line.
  *(Strategy A: subprocess + regex — reused, not a new strategy.)*
- **Verification:** integration test against `rocba_test` fredr `NTUSER.DAT`
  (Layer-1 architectural invariants; Layer-2 empirical ground truth).
- **Out of scope for v0 (roadmap):** Winlogon (Shell, Userinit) and the
  Shell Folders `Startup` user-scope persistence vectors.

#### 5.2.2 `get_prefetch_entries`

- **Source:** `ojuri/mcp_server/primitives/prefetch_entries.py`
- **Input (`GetPrefetchEntriesInput`):**
  - `prefetch_path: str` — absolute path to a single `.pf` file **or** a
    directory of `.pf` files (typically `C:\Windows\Prefetch`). Same path
    validator as above.
- **Output (`GetPrefetchEntriesOutput`):**
  - `primitive_name: "get_prefetch_entries"` (literal)
  - `total_entries: int`
  - `entries: list[PrefetchEntry]` where each entry is
    `{executable_name, prefetch_filename, run_count, last_run_time,
    last_run_time_unix, previous_run_times[≤7], volume_name, volume_serial,
    loaded_files[], prefetch_source}`.
- **Backend:** SIFT — **`pyscca`** (the official `libscca` Python binding)
  called **directly, in-process, with no subprocess**. Handles MAM-compressed
  Win10 prefetch natively. *(Strategy B: direct library call.)*
- **Test fixtures:** real Win10 `.pf` files —
  `CALC.EXE-3FBEF7FD.pf`, `CHROME.EXE-B3BA7868.pf`, `CMD.EXE-D269B812.pf` —
  from the `EricZimmerman/Prefetch` corpus (MIT).

#### 5.2.3 `get_mft_timeline`

- **Source:** `ojuri/mcp_server/primitives/mft_timeline.py`
- **Input (`GetMftTimelineInput`):**
  - `mft_path: str` — absolute path to a `$MFT` file.
  - `start_time: str | None`, `end_time: str | None` — optional ISO-8601 UTC
    bounds on `last_modified`.
  - `max_entries: int = 1000` — `ge=1, le=10000`; caps result size so a huge
    `$MFT` cannot blow up the model context or the audit payload.
  - `mft_path` validated by the same dangerous-character / traversal rule.
- **Output (`GetMftTimelineOutput`):**
  - `primitive_name: "get_mft_timeline"` (literal)
  - `total_entries: int`
  - `entries: list[MftEntry]` where each entry is
    `{entry_number, sequence_number, in_use, parent_path, file_name,
    extension, file_size, is_directory, has_ads, is_ads, created,
    last_modified, last_record_change, last_access, source_file}`, sorted by
    `last_modified` descending.
- **Backend:** SIFT — **MFTECmd** subprocess with `--csv`; the CSV is parsed
  with `encoding="utf-8-sig"` to absorb the UTF-8 BOM MFTECmd emits (discovered
  empirically — see DECISIONS 2026-05-16). The time-window filter is applied in
  the backend over parsed timestamps, then `max_entries` truncates after the
  descending sort. *(Strategy C: subprocess + CSV.)*
- **Test fixture:** `tests/fixtures/mft/dfr16_mft.bin` — the NIST
  "Data Leakage Case" **DFR-16** reference `$MFT` (US-Government public domain).

#### 5.2.4 `list_evidence_artefacts`

- **Source:** `ojuri/mcp_server/primitives/list_evidence_artefacts.py`
- **Role:** the **discovery** primitive. It is the **mandatory first call** on
  every case (enforced by the Investigator system prompt, §8): the other three
  primitives need explicit artefact paths, and those paths come from here. The
  orchestrator no longer passes per-artefact CLI flags — it passes one
  `--evidence-root` and the agent discovers the rest.
- **Input (`GetEvidenceArtefactsInput`):**
  - `evidence_root: str` — absolute path to a mounted evidence volume root.
    Validated by a `field_validator` that rejects shell metacharacters
    (`; | & \` $ ( ) \n \r`), `..` traversal, non-absolute paths, and any
    path **not** under the whitelist `/evidence/` or `/var/lib/ojuri/raw/`.
- **Output (`DiscoveredEvidence`):**
  - `primitive_name: "list_evidence_artefacts"` (literal, anti-spoof)
  - `evidence_root: str`
  - `user_profiles: list[UserProfile]` — each
    `{username, profile_path, ntuser_dat|None, usrclass_dat|None}`; pseudo-
    profiles (`Default`, `Default User`, `Public`, `All Users`) are skipped.
  - `system_hives: list[SystemHive]` — each `{name, path, size_bytes}` with
    `name ∈ {SOFTWARE, SYSTEM, SECURITY, SAM, DEFAULT}`; only hives that
    actually exist on disk are listed.
  - `prefetch_directories: list[str]` — the `Windows/Prefetch` directory iff
    it exists and contains `.pf` files.
  - `mft_files: list[str]` — the top-level `$MFT` iff present.
  - `summary: dict[str, int]` — counts (`users`, `system_hives`,
    `prefetch_directories`, `mft_files`).
- **Backend:** SIFT — a **pure-Python, read-only `os`/`pathlib` filesystem
  walk. No subprocess, no external tool.** Tolerant of partial results: a
  per-artefact `OSError` (EINVAL/EACCES on WOF reparse points and protected
  directories — see §7.3) skips that artefact and is logged; the discovery
  never aborts, and a user with an unreadable `NTUSER.DAT` still appears with
  `ntuser_dat=None`. Never writes anywhere (respects the read-only mount).
  *(Strategy D: pure-Python filesystem walk.)*
- **Verification:** integration test against `rocba_test` confirms ground
  truth — profiles `fredr` + `srl-h` with non-None `NTUSER.DAT`, `SOFTWARE` +
  `SYSTEM` hives, exactly one `…/Windows/Prefetch`, and a `…/$MFT`.

### 5.3 Design pattern — four backend strategies

The architectural insight the MVP proves: **the capability layer is
tool-agnostic.** A primitive defines a typed question and a typed answer; *how*
the answer is produced is a backend concern hidden behind the trust boundary.
The five implemented primitives deliberately exercise four different
strategies — `get_user_autostarts` reuses Strategy A alongside
`get_registry_autostarts`, proving a strategy carries more than one primitive:

| Strategy | Primitive | Mechanism | Why chosen |
|----------|-----------|-----------|------------|
| A. Subprocess + regex | `get_registry_autostarts`, `get_user_autostarts` | `rip.pl` multi-plugin, parse stdout | RegRipper is the de-facto registry tool; no clean library |
| B. Direct library call | `get_prefetch_entries` | `pyscca` in-process | Official binding, no .NET, no subprocess, license-clean |
| C. Subprocess + CSV | `get_mft_timeline` | `MFTECmd --csv`, BOM-aware parse | Mature, clean CSV; analyzeMFT was empirically broken |
| D. Pure-Python filesystem walk | `list_evidence_artefacts` | `os`/`pathlib` read-only walk, no subprocess | Discovery needs no external tool; stdlib-only ⇒ runs on every platform |

Same trust boundary, same Pydantic-typed output contract, five primitives
across four implementations. This is why the remaining 25 primitives are roadmap and not
risk: each new one slots into whichever of these four patterns fits its tool,
behind an unchanged boundary, and inherits audit + validation for free.

---

## 6. Audit Chain

Implementation: `ojuri/mcp_server/audit/__init__.py`. Verifier:
`scripts/verify_chain.py`.

### 6.1 Schema

Every tool call appends one JSONL record with exactly seven fields:

| Field | Type | Meaning |
|-------|------|---------|
| `sequence` | int | 1-based monotonic counter |
| `timestamp_utc` | str | ISO-8601 UTC of the record |
| `tool_name` | str | Primitive that was called |
| `input_hash` | str | `sha256:` of canonicalised input payload |
| `output_hash` | str | `sha256:` of canonicalised output payload |
| `previous_record_hash` | str | `this_record_hash` of record *N−1* |
| `this_record_hash` | str | `sha256:` of this record sans `this_record_hash` |

Hashes are presented as `sha256:<64-hex>`. Note the log stores **hashes of the
payloads, not the payloads** — the chain proves *what was asked and answered*
without bloating the log or leaking evidence content into it.

### 6.2 Canonicalisation

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

`sort_keys=True` makes field order irrelevant; compact `separators` removes
whitespace ambiguity; `ensure_ascii=False` keeps Unicode as UTF-8 bytes rather
than `\uXXXX` escapes. **Trade-off vs RFC 8785 (JCS):** full JCS additionally
specifies number serialisation and Unicode normalisation. We do not adopt it
because (a) it would add a dependency with no stdlib coverage, and (b) our
payloads are a fixed, known set of primitive inputs/outputs with no exotic
number or Unicode forms, so `sort_keys` + compact separators already give
byte-stability. `verify_chain.py` **reimplements this exact line independently**
so any future drift in either direction is itself a detectable failure
(DECISIONS 2026-05-14).

### 6.3 Implementation

Pseudocode mirroring `AuditLogger` (`audit/__init__.py`):

```
GENESIS = "sha256:" + "0"*64           # genesis previous_record_hash

on init(log_path):
    ensure parent dir exists
    recover_chain_state():
        if log missing/empty: sequence=0, last_hash=GENESIS; return
        read final non-blank line
        sequence  = rec["sequence"]
        last_hash = rec["this_record_hash"]      # continue the existing chain
        if final line unparseable: raise AuditWriteError   # fail-closed

record(tool_name, input_payload, output_payload):    # under a threading.Lock
    sequence += 1
    body = {input_hash, output_hash,
            previous_record_hash=last_hash,
            sequence, timestamp_utc, tool_name}      # six fields, no self-hash
    self_hash = sha256(canonical(body))
    full = body + {this_record_hash: self_hash}
    append canonical(full)+b"\n" to log
        f.write → f.flush → os.fsync(fileno)         # durable before returning
    on OSError: sequence -= 1; raise AuditWriteError # roll back; never claim a lost record
    last_hash = self_hash
    return full
```

Key properties: **genesis hash** is 64 zeros; a restarted process **recovers
chain state** from the last line and continues the same chain; appends are
**fsync-protected** and the in-memory sequence is **rolled back** on write
failure so the logger never reports a record that did not durably land
(fail-closed).

### 6.4 Verifier (`verify_chain.py`)

- **Independence:** stdlib only (`argparse, hashlib, json, sys, pathlib`); **no
  `ojuri` import**. It re-derives `canonical()` and the hashing from scratch.
  If the writer's canonicalisation ever drifts from this reimplementation, the
  self-hash check fails — drift is *designed to be detectable*, not assumed
  away.
- **Three checks per record:** (1) `sequence` strictly increments from 1;
  (2) `previous_record_hash` equals the prior record's `this_record_hash`
  (chain link); (3) `this_record_hash` equals the recomputed hash of the record
  minus that field (self-hash).
- **Exit codes:** `0` chain valid · `1` chain invalid (≥1 failure) · `2` file
  or argument error. Empty log ⇒ valid (nothing to verify). The agent
  orchestrator runs this in pre-flight; a broken chain aborts the loop
  (agents.md §4) — Ojuri refuses to reason over an audit log it cannot prove
  intact.

---

## 7. Evidence Layer

### 7.1 Two-stage design

| Stage | Script | Concern | Output |
|-------|--------|---------|--------|
| 1 | `scripts/open_evidence.sh` | Format detection & exposure | A raw filesystem tree under `/var/lib/ojuri/raw/<case>/` |
| 2 | `scripts/mount_evidence.sh` | Hardening (unchanged) | `/evidence/<case>/` mounted `ro,noexec,nodev,nosuid` |

Stage 1 detects the image format and turns it into a mounted filesystem
directory. Stage 2 — the pre-existing, deliberately **unmodified**
`mount_evidence.sh` — bind-mounts that directory with kernel hardening flags and
prints the baseline next-step. **Why two stages:** format handling (E01 vs raw
vs AFF4) and hardening (read-only enforcement, exec/dev/suid suppression) are
orthogonal concerns. Coupling them would mean every new format touches the
hardening code; separating them keeps the audited hardening path stable and
composable (DECISIONS 2026-05-17 "two-stage evidence layer").

### 7.2 Supported formats

| Format | Extensions | Status | Mechanism |
|--------|-----------|--------|-----------|
| EWF / EnCase | `.E01`, `.e01` | **Primary** | `ewfmount` → loop-mount |
| Raw / dd | `.dd`, `.img`, `.raw` | **Primary** | direct loop-mount |
| AFF4 | `.aff`, `.aff4` | Stub | clear error → roadmap v0.4 |
| VMware | `.vmdk` | Stub | clear error → roadmap v0.5 |
| Hyper-V | `.vhdx` | Stub | clear error → roadmap v0.5 |
| anything else | — | Error | explicit "unsupported format" message |

Stubs fail loudly with a roadmap pointer rather than silently or ambiguously —
an unsupported format must never look like an empty mount.

**Robust read-only mount (`loop_mount_ro`).** The Stage-1 filesystem mount is
not a single hardcoded `mount` call. `open_evidence.sh` tries the kernel
default driver first, then falls back to the in-kernel `ntfs3` driver with
`ro,noatime`. This was driven empirically (DECISIONS 2026-05-17 "Robust
read-only mount"): the first real evidence image (`rocba-cdrive.e01`) is a
single NTFS *volume* whose recorded size slightly exceeds the imaged sector
count (missing backup boot sector — typical when a partition, not a whole
disk, is imaged). `ntfs-3g` strictly rejects this; `ntfs3 -o ro` mounts it
without journal replay or recovery and is non-modifying, so chain of custody
is preserved. `ntfsfix` and `ntfs-3g -o force` were rejected because both
write to the volume. The opener still expects a *single-volume* image — a
full-disk image with a partition table is surfaced as a clear error, not
silently mis-mounted.

### 7.3 Read-only enforcement (four independent levels)

1. **`ewfmount` is inherently read-only.** libewf's FUSE mount exposes `ewf1`
   with no write path; there is no flag that makes it writable.
2. **`mount -o ro`** on the loop device — filesystem-level read-only for the
   NTFS volume. The `loop_mount_ro` helper guarantees every attempt (default
   driver and the `ntfs3` fallback) is `ro,noatime`; no write-capable or
   recovery-enabled mount mode is ever used.
3. **Bind-mount remount `ro,noexec,nodev,nosuid`** (done by the untouched
   `mount_evidence.sh`) — kernel-enforced at `/evidence/<case>/`: read-only,
   no binary execution, no device-node honouring, no setuid/setgid.
4. **SHA-256 baseline + verification** (`scripts/baseline_evidence.py`) — a
   post-hoc tamper-detection layer: hash every file once, re-hash later, and
   any ADDED/REMOVED/MODIFIED path is reported. Defends even against an
   out-of-band change the mount flags didn't stop. The walk **tolerates
   per-file and per-directory I/O errors** (e.g. `OSError [Errno 22]` on WOF
   reparse points (NTFS reparse tag `0x80000017` — Windows Overlay Filter; no
   Linux NTFS driver implements decompression), or `[Errno 5]` on sectors
   outside the imaged region): the offending path is recorded in a
   `skipped` list — `{path, error_class, errno, message}` — and the walk
   continues; the process exits non-zero only on catastrophic failure (zero
   files hashed). This is deliberate: baselining is tamper *detection*, not an
   integrity *gate*. Aborting on the first unreadable path would forfeit
   tamper-detection for the entire tree; instead every file that *was*
   readable at baseline time stays protected, and every unreadable path is
   explicitly accounted for (chain of custody requires that no path in the
   source tree is silently dropped). Verified on `rocba_test`: 206,679 hashed,
   18,618 skipped (see DECISIONS 2026-05-17 "Baseline evidence: per-file I/O
   error tolerance").

No single level is trusted alone; spoliation must defeat all four.

---

## 8. Reasoning Layer

Fully specified in [docs/design/agents.md](../design/agents.md); **not
duplicated here.** Summary of the selected design:

- **Option 4 (Hybrid topology):** an **Investigator** running in the main
  Claude Code session (working dir = repo root, `.mcp.json` present, MCP tools
  available) and an **Auditor** launched as an isolated subprocess.
- **Pattern B (Auditor reads the audit log only):** the Auditor is started in
  an empty working directory with `--strict-mcp-config` and no `--mcp-config`,
  so it has **zero** MCP tools by construction. It reads `audit.log` and the
  findings file, and writes verdicts. Its no-tool constraint is *architectural,
  not prompt-instructed*.
- **Format 2 (structured Findings):** each `Finding` carries a `FindingClaim`
  plus ≥1 `FindingCitation` (audit sequence, tool, output path, ≤200-char
  excerpt), making "claim → cited record → excerpt" mechanically checkable.
- **Bounded self-correction:** `DEFAULT_MAX_ITERATIONS = 3`, resolved from
  CLI > env > default, then **hard-capped at 10** and floored at 1 by the
  orchestrator, with a pure, unit-tested `decide_termination`.
- **Mandatory discovery:** the Investigator's first MCP call on every case
  **must** be `list_evidence_artefacts(evidence_root)` (§5.2.4). All
  downstream registry/prefetch/MFT calls reference paths from that discovery
  output; the orchestrator passes only `--evidence-root`, never per-artefact
  paths. Calling an analytical primitive before discovery is defined as an
  error in the Investigator system prompt.
- **Surgical permission grant (`--allowedTools`):** each agent's subprocess
  is launched with `--allowedTools` restricting it to the precise tools it
  needs. The Investigator may call the 4 Ojuri MCP primitives plus `Write`
  (to record findings); the Auditor may only call `Read` and `Write` (and
  `--strict-mcp-config` ensures no MCP tools are loaded). This is required
  because `claude -p` defaults to *denying* tool calls (no human to approve),
  and it prevents prompt-injection escalation: a manipulated Investigator
  prompt cannot trigger arbitrary tool execution (e.g. `Bash`, `Edit`).
- **Option A (confidence downgrade allowed):** a disputed finding may be
  revised, supported with more evidence, **or** downgraded to `low` confidence
  with explanation — never silently deleted. A downgraded finding is *still
  audited*.

The orchestrator (`ojuri/agents/loop.py`) is deterministic Python: it owns
iteration, timeouts (Investigator 1800 s, Auditor 600 s), pre-flight chain
verification, and exit codes (`0` success · `2` inconclusive · `3` audit
invalid · `4/5` timeouts · `6` config error).

---

## 9. Build status (snapshot — 2026-05-17)

| Phase | Scope | Status |
|-------|-------|--------|
| Week 1 | Foundation, scaffolding, evidence mount layer | ✓ complete |
| Week 2 | 3 forensic primitives + hash-chained audit + independent verifier | ✓ complete |
| Week 3 | Dual-agent reasoning layer; living docs; format-aware opener; **first real E01 mounted** (`rocba_test`: Win10 volume, 211 prefetch, 469 MB `$MFT`) | **in progress** |
| Week 4–5 | Demo run on real case, accuracy report, submission video, polish | pending |

13 commits on `main`; 13 tests passing. This section is dated and refreshed
each working session — it is a snapshot, not a guarantee.

---

## 10. Test strategy

Tests use a **two-layer assertion pattern**:

- **Layer 1 — architectural contract:** assertions that must hold regardless of
  fixture (`primitive_name` literal is correct; output is the right Pydantic
  model; `total_entries == len(entries)`; the audit chain self-verifies; path
  validators reject metacharacters/traversal). These never change.
- **Layer 2 — fixture-specific:** assertions about *this* fixture's content
  (a known executable name, a known run count, the DFR-16 file count). These
  are refreshed if the fixture is intentionally swapped.

Fixtures are **real Windows artefacts and license-clean**: MIT-licensed hives
and `.pf` files from the EricZimmerman corpora; the public-domain NIST DFR-16
`$MFT`. No synthetic forensic data is used for primitive correctness (synthetic
trees are used only for the evidence-layer baseline test, which is about the
hashing logic, not artefact parsing). Current count: **13 tests passing**
(unit + integration; agent-loop tests mock the subprocess and never invoke a
real Claude Code).

---

## 11. Risk register

| # | Risk | Status | Mitigation |
|---|------|--------|------------|
| R1 | LLM hallucinated finding reaches the report | Mitigated | Auditor + citations + bounded loop (§3.1, §8) |
| R2 | Write reaches source evidence | Mitigated | Four-level read-only enforcement (§7.3) |
| R3 | Audit log rewritten post hoc | Mitigated | Hash chain + independent stdlib verifier (§6) |
| R4 | Backend tool produces wrong/garbage output | Open | Court-vetted tools; typed parsing; empirically validated (e.g. analyzeMFT rejected) |
| R5 | Canonicalisation drift writer↔verifier | Mitigated | Verifier reimplements independently; drift fails the self-hash check (§6.4) |
| R6 | Format opener leaves a stale/partial mount | Mitigated | Idempotent opener refuses to overwrite an existing mount (§7.1, open_evidence.sh) |
| R7 | Volume image NTFS-size > imaged sectors (strict ntfs-3g reject) | Mitigated | `loop_mount_ro` falls back to read-only `ntfs3`; proven on `rocba-cdrive.e01` (§7.2) |
| R7b | Full-disk image / corrupt image | Open | `mount` surfaces the failure; opener errors clearly, expects single-volume, does not fabricate |
| R8 | Coverage gap — only 3 of 28 primitives | Accepted (MVP) | Pattern proven across 3 backend strategies; remainder is roadmap (§12) |
| R9 | Windows/macOS host parity (no `ewfmount`) | Open | Documented in REQUIREMENTS.md; native support roadmapped v0.3 |

### Spoliation test plan (forward-looking)

`tests/spoliation/` is reserved for in-process tests that assert a write
attempt against `/evidence/<case>/` fails (`Read-only file system`) and that
`baseline_evidence.py --verify` detects an out-of-band change. The kernel-mount
test is a documented manual procedure (the CI harness has no sudo); the
synthetic-tree baseline test in `tests/integration/test_evidence_layer.py`
already exercises the detection logic.

---

## 12. Roadmap

Detailed roadmap may move to `ROADMAP.md` if it grows; summary here:

- **Primitives:** the remaining 25 in the §5.1 catalogue, each slotting into one
  of the three proven backend strategies.
- **Memory forensics:** `get_memory_pslist`, `get_memory_netscan`, and
  multi-source correlation (memory ↔ disk artefacts).
- **Live endpoint:** a backend that connects to a live triage agent rather than
  a mounted image, behind the same primitive contract.
- **Persistent learning loop:** feeding audited, verified findings back as
  reusable case knowledge.
- **Evidence formats:** AFF4 (v0.4), VMDK/VHDX (v0.5), native Windows E01
  opening via Arsenal/OSFMount (v0.3).
- **Native Windows port for WOF-backed file content baselining.** WOF
  (Windows Overlay Filter) reparse points (NTFS reparse tag `0x80000017`) are
  decoded only by the Windows kernel's WOF driver. No Linux NTFS driver
  (`ntfs3` *or* `ntfs-3g`) implements WOF decompression. Affected files appear
  as 34-byte broken symlinks ("unsupported reparse tag 0x80000017"). A native
  Windows port of Ojuri would baseline these files using the host kernel's WOF
  driver. Linux dual-FUSE (`ntfs3` + `ntfs-3g`) was empirically tested and does
  **not** solve this — both drivers hit the same wall (see DECISIONS
  2026-05-17 "WOF reparse-point clarification"). The discovery primitive
  (`list_evidence_artefacts`, §5.2.4) is built and no longer roadmap.

---

## 13. Glossary

- **MFT** — Master File Table; the NTFS metadata index, one record per file,
  carrying MAC(b) timestamps. Source of filesystem timelines.
- **Prefetch** — Windows execution-acceleration files (`.pf`) recording what
  ran, when, run count, and loaded files.
- **Autoruns / autostarts** — registry/service mechanisms that launch code at
  boot or logon; a primary malware persistence surface.
- **Evidence integrity** — provable non-modification of source data; the
  technical basis of chain of custody.
- **Audit chain** — the append-only, hash-linked log of every primitive call.
- **Canonicalisation** — deterministic serialisation so the same logical object
  always yields the same bytes (and therefore the same hash).
- **Hash chain** — records each binding the prior record's hash, so any edit
  breaks all subsequent links.
- **MCP** — Model Context Protocol; the typed tool-calling transport between
  the agent and the Ojuri server.
- **Capability-based security** — security by *not granting* a capability
  rather than by *forbidding its use*; here, no shell is exposed at all.
- **RFC 8785 (JCS)** — JSON Canonicalisation Scheme; a full canonical-JSON
  standard. Ojuri uses a documented stdlib subset (§6.2).
- **EWF / E01** — Expert Witness Format; EnCase forensic image container.
- **ewfmount** — libewf FUSE tool exposing an EWF image as a raw `ewf1` device.
- **Spoliation** — destruction or alteration of evidence.

---

## 14. References

- SANS "Find Evil!" challenge brief (Devpost).
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- Expert Witness Compression Format (EWF/E01) specification, libewf docs.
- libscca / `pyscca` documentation (Windows Prefetch parsing).
- libewf / `ewfmount` documentation.
- EricZimmerman test corpora — `Registry`, `Prefetch`, `MFT` (MIT-licensed).
- NIST CFReDS "Data Leakage Case" reference dataset (DFR-16, public domain).
- RegRipper3 (`rip.pl`) and MFTECmd (Eric Zimmerman tools).

---

*Ojuri Architecture — living document. Update §9 each session; append design
changes to [DECISIONS.md](./DECISIONS.md); regenerate the submission `.docx` via
[SOURCE_PROMPT.md](./SOURCE_PROMPT.md).*
