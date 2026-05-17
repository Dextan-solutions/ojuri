#!/usr/bin/env python3
"""baseline_evidence.py — compute SHA-256 baseline for a mounted evidence directory.

Walks the evidence mount, computes SHA-256 for every regular file, and writes
a structured JSON baseline that future integrity checks compare against.

Per-file and per-directory I/O errors (e.g. OSError [Errno 5] on NTFS-internal
paths such as ``$GetCurrent/media`` exposed via a read-only ``ntfs3`` mount) are
tolerated: the offending path is recorded in a ``skipped`` list and the walk
continues. The process exits non-zero only on catastrophic failure (nothing
could be hashed at all). See ARCHITECTURE.md §7.3 and the 2026-05-17 DECISIONS
entry — baselining is a post-hoc tamper-detection layer, not an integrity gate,
so every path in the source tree must be accounted for (hashed *or* skipped).

Usage:
    python3 baseline_evidence.py <case_id> [--evidence-root /evidence] [--baseline-dir ~/ojuri/baselines]
    python3 baseline_evidence.py <case_id> --verify     # re-check, compare to existing baseline

The baseline file is written to <baseline-dir>/<case_id>_baseline.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CHUNK_SIZE = 1024 * 1024  # 1 MiB per hash update


def sha256_of_file(path: Path) -> str:
    """Compute SHA-256 of a file in streaming chunks (handles large files).

    May raise OSError if the file (or a region of it) is unreadable — the
    caller is responsible for catching it and recording the path as skipped.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _skip_entry(rel_path: str, exc: OSError) -> dict[str, Any]:
    """Build one structured ``skipped`` record from an OSError."""
    err_no = getattr(exc, "errno", None)
    prefix = os.strerror(err_no) if err_no is not None else exc.__class__.__name__
    target = getattr(exc, "filename", None)
    message = f"{prefix}: {target}" if target else f"{prefix}: {exc}"
    return {
        "path": rel_path,
        "error_class": exc.__class__.__name__,
        "errno": err_no,
        "message": message,
    }


def walk_and_hash(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Walk ``root`` recursively, tolerating per-file and per-directory I/O errors.

    For each regular file: capture its mount-relative POSIX path, size, and
    SHA-256. Symlinks and special (non-regular) files are silently excluded —
    they would double-count or break verification. Any OSError raised while
    enumerating a directory or while ``lstat``/``open``/``read``-ing a file is
    caught: the path is appended to ``skipped`` and the walk continues.

    Returns: ``(files, skipped)``. ``files`` is sorted by relative path for
    deterministic, byte-stable output; ``skipped`` is in encounter order.
    """
    results: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    def _rel(p: str) -> str:
        try:
            return Path(p).relative_to(root).as_posix()
        except ValueError:
            return p

    def _on_walk_error(exc: OSError) -> None:
        # os.walk swallows directory-enumeration errors unless we supply this
        # callback. Record the directory and let the walk continue elsewhere.
        bad = getattr(exc, "filename", None) or str(root)
        skipped.append(_skip_entry(_rel(bad), exc))

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, onerror=_on_walk_error, followlinks=False
    ):
        # Deterministic recursion + file order.
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                if os.path.islink(full):
                    # Symlinks are excluded — they point elsewhere and would
                    # double-count or break if the target moves.
                    continue
                st = os.lstat(full)
                if not os.path.isfile(full):
                    # Special files (devices, FIFOs, sockets) are not hashed.
                    continue
                digest = sha256_of_file(Path(full))
            except OSError as exc:
                skipped.append(_skip_entry(_rel(full), exc))
                continue
            results.append(
                {
                    "path": _rel(full),
                    "size_bytes": st.st_size,
                    "sha256": digest,
                }
            )

    results.sort(key=lambda e: e["path"])
    return results, skipped


def build_baseline(case_id: str, evidence_root: Path) -> dict[str, Any]:
    """Construct the full baseline dict for serialisation."""
    if not evidence_root.is_dir():
        raise SystemExit(f"Error: evidence root does not exist: {evidence_root}")

    started = time.monotonic()
    files, skipped = walk_and_hash(evidence_root)
    duration = round(time.monotonic() - started, 3)

    total_bytes = sum(f["size_bytes"] for f in files)
    return {
        "case_id": case_id,
        # New schema (per 2026-05-17 DECISIONS entry).
        "mount_point": str(evidence_root),
        "baseline_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        # Legacy fields retained for backward compatibility with --verify and
        # the evidence-layer integration test. Do not remove without updating
        # tests/integration/test_evidence_layer.py.
        "baseline_created_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_root": str(evidence_root),
        "algorithm": "sha256",
        "total_files": len(files),
        "total_bytes": total_bytes,
        "files": files,
        "skipped": skipped,
        "summary": {
            "files_hashed": len(files),
            "files_skipped": len(skipped),
            "total_bytes_hashed": total_bytes,
            "duration_seconds": duration,
        },
    }


def verify_baseline(baseline_path: Path, evidence_root: Path) -> int:
    """Re-walk evidence_root and compare to the stored baseline.

    Returns: 0 if integrity intact, 1 if any mismatch detected.
    """
    if not baseline_path.is_file():
        print(f"Error: no baseline found at {baseline_path}", file=sys.stderr)
        return 1

    with baseline_path.open() as f:
        baseline = json.load(f)

    current_files, _current_skipped = walk_and_hash(evidence_root)
    stored = {entry["path"]: entry for entry in baseline["files"]}
    current = {entry["path"]: entry for entry in current_files}

    added = set(current.keys()) - set(stored.keys())
    removed = set(stored.keys()) - set(current.keys())
    modified = []
    for path, cur in current.items():
        if path in stored and (
            cur["sha256"] != stored[path]["sha256"]
            or cur["size_bytes"] != stored[path]["size_bytes"]
        ):
            modified.append(path)

    if not (added or removed or modified):
        print(f"✓ Integrity intact: {len(stored)} files match the baseline.")
        return 0

    print("✗ Integrity mismatch detected:", file=sys.stderr)
    for path in sorted(added):
        print(f"  ADDED   {path}", file=sys.stderr)
    for path in sorted(removed):
        print(f"  REMOVED {path}", file=sys.stderr)
    for path in sorted(modified):
        print(f"  MODIFIED {path}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_id", help="Case identifier (alphanumerics, underscore, hyphen; max 64 chars)")
    parser.add_argument("--evidence-root", default="/evidence",
                        help="Root directory under which case mounts live (default: /evidence)")
    parser.add_argument("--baseline-dir", default=str(Path.home() / "ojuri" / "baselines"),
                        help="Directory to read/write baseline JSON (default: ~/ojuri/baselines)")
    parser.add_argument("--verify", action="store_true",
                        help="Re-hash the evidence and compare to the existing baseline")
    args = parser.parse_args()

    if not CASE_ID_PATTERN.match(args.case_id):
        print(f"Error: case_id must match {CASE_ID_PATTERN.pattern}", file=sys.stderr)
        print(f"Got: {args.case_id}", file=sys.stderr)
        return 2

    evidence_root = Path(args.evidence_root) / args.case_id
    baseline_dir = Path(args.baseline_dir)
    baseline_path = baseline_dir / f"{args.case_id}_baseline.json"

    if args.verify:
        return verify_baseline(baseline_path, evidence_root)

    baseline_dir.mkdir(parents=True, exist_ok=True)
    baseline = build_baseline(args.case_id, evidence_root)
    baseline_path.write_text(json.dumps(baseline, indent=2, sort_keys=True))

    summary = baseline["summary"]
    print(f"✓ Baseline created: {baseline_path}")
    print(f"  case_id:           {baseline['case_id']}")
    print(f"  mount_point:       {baseline['mount_point']}")
    print(f"  files_hashed:      {summary['files_hashed']}")
    print(f"  files_skipped:     {summary['files_skipped']}")
    print(f"  total_bytes_hashed:{summary['total_bytes_hashed']}")
    print(f"  duration_seconds:  {summary['duration_seconds']}")
    print(f"  timestamp_utc:     {baseline['baseline_timestamp_utc']}")

    if summary["files_skipped"]:
        print(f"\n  ⚠ {summary['files_skipped']} path(s) skipped (recorded in 'skipped'):",
              file=sys.stderr)
        for entry in baseline["skipped"]:
            print(f"    SKIPPED {entry['path']} "
                  f"[{entry['error_class']} errno={entry['errno']}] {entry['message']}",
                  file=sys.stderr)

    # Non-zero exit only on catastrophic failure: nothing at all could be
    # hashed. A baseline with some skips is still a usable tamper-detection
    # reference for every file that WAS readable.
    if summary["files_hashed"] == 0:
        print("✗ Catastrophic: zero files could be hashed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
