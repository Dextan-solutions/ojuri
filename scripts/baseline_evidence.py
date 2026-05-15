#!/usr/bin/env python3
"""baseline_evidence.py — compute SHA-256 baseline for a mounted evidence directory.

Walks the evidence mount, computes SHA-256 for every regular file, and writes
a structured JSON baseline that future integrity checks compare against.

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CHUNK_SIZE = 1024 * 1024  # 1 MiB per hash update


def sha256_of_file(path: Path) -> str:
    """Compute SHA-256 of a file in streaming chunks (handles large files)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def walk_and_hash(root: Path) -> list[dict[str, Any]]:
    """Walk root recursively. For each regular file, capture its relative path,
    size, and SHA-256 hash. Symlinks and special files are skipped (with a
    comment in the output)."""
    results: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            # Symlinks are skipped — they point elsewhere and would double-count
            # or break if the target moves. Documented intentional exclusion.
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest = sha256_of_file(path)
        results.append({"path": rel, "size_bytes": size, "sha256": digest})
    return results


def build_baseline(case_id: str, evidence_root: Path) -> dict[str, Any]:
    """Construct the full baseline dict for serialisation."""
    if not evidence_root.is_dir():
        raise SystemExit(f"Error: evidence root does not exist: {evidence_root}")

    files = walk_and_hash(evidence_root)
    total_bytes = sum(f["size_bytes"] for f in files)
    return {
        "case_id": case_id,
        "baseline_created_utc": datetime.now(timezone.utc).isoformat(),
        "evidence_root": str(evidence_root),
        "algorithm": "sha256",
        "total_files": len(files),
        "total_bytes": total_bytes,
        "files": files,
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

    stored = {entry["path"]: entry for entry in baseline["files"]}
    current = {entry["path"]: entry for entry in walk_and_hash(evidence_root)}

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

    print(f"✓ Baseline created: {baseline_path}")
    print(f"  case_id:      {baseline['case_id']}")
    print(f"  total_files:  {baseline['total_files']}")
    print(f"  total_bytes:  {baseline['total_bytes']}")
    print(f"  created_utc:  {baseline['baseline_created_utc']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
