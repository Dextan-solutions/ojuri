#!/usr/bin/env python3
"""verify_chain.py — independent verifier for Ojuri's hash-chained audit log.

Reads a JSONL audit log produced by ojuri.mcp_server.audit and verifies
the chain integrity using only Python stdlib. Standalone: no ojuri imports,
so this script can be run on any system to audit a log file.

Usage:
    verify_chain.py <audit_log_path> [-v|--verbose]

Exit codes:
    0   chain valid
    1   chain invalid (one or more integrity failures)
    2   file or argument error

This script reimplements canonicalisation and hashing from scratch
(rather than importing from the logger) so that drift between writer
and reader is detectable. The format is documented in §11 of the
Ojuri architecture document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ZERO_HASH = "sha256:" + ("0" * 64)


def canonical(obj) -> bytes:
    """Canonicalise an object for hashing. Must match the logger's canonicalisation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify_record_self_hash(record: dict) -> tuple[bool, str]:
    """Verify that record['this_record_hash'] is the correct hash of the rest."""
    if "this_record_hash" not in record:
        return False, "record missing this_record_hash field"
    claimed = record["this_record_hash"]
    shadow = {k: v for k, v in record.items() if k != "this_record_hash"}
    computed = sha256_hex(canonical(shadow))
    if claimed != computed:
        return False, f"this_record_hash mismatch: claimed={claimed[:24]}..., computed={computed[:24]}..."
    return True, ""


def verify_chain(log_path: Path, verbose: bool = False) -> tuple[bool, list[str], int]:
    """Verify the entire chain. Returns (is_valid, error_messages, record_count)."""
    errors: list[str] = []
    if not log_path.exists():
        return False, [f"log file not found: {log_path}"], 0
    if log_path.stat().st_size == 0:
        return True, ["log is empty (no records to verify; chain trivially valid)"], 0

    previous_hash = ZERO_HASH
    expected_sequence = 1
    record_count = 0

    with log_path.open("rb") as f:
        for line_num, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            record_count += 1
            try:
                record = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as e:
                errors.append(f"line {line_num}: invalid JSON: {e}")
                continue

            required_fields = {
                "sequence", "timestamp_utc", "tool_name",
                "input_hash", "output_hash",
                "previous_record_hash", "this_record_hash",
            }
            missing = required_fields - set(record.keys())
            if missing:
                errors.append(f"line {line_num} seq={record.get('sequence', '?')}: missing fields: {sorted(missing)}")
                continue

            # Check (1): sequence monotonicity
            if record["sequence"] != expected_sequence:
                errors.append(
                    f"line {line_num}: sequence mismatch — expected {expected_sequence}, got {record['sequence']}"
                )

            # Check (2): chain link
            if record["previous_record_hash"] != previous_hash:
                errors.append(
                    f"line {line_num} seq={record['sequence']}: chain break — "
                    f"previous_record_hash={record['previous_record_hash'][:24]}... "
                    f"but expected {previous_hash[:24]}..."
                )

            # Check (3): self-hash
            ok, msg = verify_record_self_hash(record)
            if not ok:
                errors.append(f"line {line_num} seq={record['sequence']}: {msg}")

            if verbose:
                print(f"  record {record['sequence']}: tool={record['tool_name']} "
                      f"timestamp={record['timestamp_utc']} hash={record['this_record_hash'][:24]}...")

            previous_hash = record["this_record_hash"]
            expected_sequence += 1

    return len(errors) == 0, errors, record_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independently verify the integrity of an Ojuri audit log."
    )
    parser.add_argument("log_path", type=Path, help="path to audit.log")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print one line per record during verification")
    args = parser.parse_args()

    if not args.log_path.is_file():
        print(f"error: {args.log_path} is not a file", file=sys.stderr)
        return 2

    print(f"Verifying audit chain: {args.log_path}")
    valid, errors, count = verify_chain(args.log_path, verbose=args.verbose)

    print(f"Records verified: {count}")
    if valid:
        print("CHAIN VALID — all integrity checks passed.")
        return 0
    else:
        print(f"CHAIN INVALID — {len(errors)} integrity failure(s):")
        for e in errors:
            print(f"  - {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
