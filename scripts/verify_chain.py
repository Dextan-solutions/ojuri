#!/usr/bin/env python3
"""verify_chain.py — independent verifier for Ojuri's hash-chained audit log.

Reads a JSONL audit log produced by ojuri.mcp_server.audit and verifies
the chain integrity using only Python stdlib. Standalone: no ojuri imports,
so this script can be run on any system to audit a log file.

Usage:
    verify_chain.py <audit_log_path> [-v|--verbose]

Exit codes:
    0   chain valid (and, if present, all output files match their hashes)
    1   chain invalid (one or more chain integrity failures)
    2   file or argument error
    4   output tamper detected (chain is valid, but an outputs/seq-N.json
        file's content no longer hashes to the record's output_hash)

Output cross-check (Option B, DECISIONS 2026-05-19):
    The hash-only log proves *what was answered*; the per-call payloads
    live in <log_parent>/outputs/seq-{N:03d}.json. When that directory is
    present this verifier re-hashes each output file and confirms it equals
    the record's output_hash — catching tampering of the payload layer.
    The file holds the exact canonical bytes that were hashed, so the raw
    file bytes are hashed directly. Legacy runs without an outputs/ dir
    remain fully verifiable for chain integrity (the cross-check is a
    no-op, reported but not a failure).

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


def verify_chain(
    log_path: Path, verbose: bool = False
) -> tuple[bool, list[str], int, list[tuple[int, str]]]:
    """Verify the entire chain.

    Returns (is_valid, error_messages, record_count, output_index) where
    output_index is a list of (sequence, output_hash) for every structurally
    valid record — consumed by the outputs/ cross-check.
    """
    errors: list[str] = []
    output_index: list[tuple[int, str]] = []
    if not log_path.exists():
        return False, [f"log file not found: {log_path}"], 0, output_index
    if log_path.stat().st_size == 0:
        return True, ["log is empty (no records to verify; chain trivially valid)"], 0, output_index

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

            output_index.append((record["sequence"], record["output_hash"]))

            if verbose:
                print(f"  record {record['sequence']}: tool={record['tool_name']} "
                      f"timestamp={record['timestamp_utc']} hash={record['this_record_hash'][:24]}...")

            previous_hash = record["this_record_hash"]
            expected_sequence += 1

    return len(errors) == 0, errors, record_count, output_index


def verify_outputs(
    log_path: Path, output_index: list[tuple[int, str]], verbose: bool = False
) -> tuple[bool, list[str], list[str]]:
    """Cross-check outputs/seq-{N:03d}.json against each record's output_hash.

    The file holds the exact canonical bytes that were hashed, so we hash the
    raw file bytes directly (no re-canonicalisation — re-parsing would mask a
    pretty-print or whitespace tamper).

    Returns (no_tamper, tamper_messages, info_messages). Missing files are
    informational (legacy runs without outputs/), not failures.
    """
    info: list[str] = []
    tamper: list[str] = []
    outputs_dir = log_path.parent / "outputs"
    if not outputs_dir.is_dir():
        info.append(
            f"no output files to cross-check (no {outputs_dir} directory; "
            f"legacy run — chain integrity still verified)"
        )
        return True, tamper, info

    verified = missing = 0
    for sequence, output_hash in output_index:
        out_file = outputs_dir / f"seq-{sequence:03d}.json"
        if not out_file.is_file():
            missing += 1
            info.append(f"seq {sequence} output not stored ({out_file.name} absent)")
            continue
        computed = sha256_hex(out_file.read_bytes())
        if computed == output_hash:
            verified += 1
            if verbose:
                print(f"  seq {sequence} output verified ({out_file.name})")
        else:
            tamper.append(
                f"seq {sequence} output TAMPERED — {out_file.name} hashes to "
                f"{computed[:24]}... but audit record output_hash is "
                f"{output_hash[:24]}... (file modified since the record was written)"
            )
    info.append(
        f"output cross-check: {verified} verified, {missing} not stored, "
        f"{len(tamper)} tampered"
    )
    return len(tamper) == 0, tamper, info


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
    valid, errors, count, output_index = verify_chain(
        args.log_path, verbose=args.verbose
    )

    print(f"Records verified: {count}")
    if not valid:
        print(f"CHAIN INVALID — {len(errors)} integrity failure(s):")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("CHAIN VALID — all chain integrity checks passed.")

    # Chain is intact. Cross-check the per-call output files (Option B).
    no_tamper, tamper, info = verify_outputs(
        args.log_path, output_index, verbose=args.verbose
    )
    for line in info:
        print(f"  {line}")
    if not no_tamper:
        print(f"OUTPUT TAMPER DETECTED — {len(tamper)} mismatch(es):")
        for t in tamper:
            print(f"  - {t}")
        return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())
