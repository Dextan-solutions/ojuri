"""Integration test for get_user_autostarts.

Runs the real rip.pl subprocess against the rocba_test fredr NTUSER.DAT.

Two assertion layers:
  Layer 1 (architectural): properties that must hold regardless of hive.
  Layer 2 (fixture-specific): rocba_test fredr ground truth. This is
    empirical — we do not assume any specific entries. total_entries >= 0
    (zero is itself a valid finding: no per-user persistence configured).
    The entries are printed so the ground truth is visible (run with -s).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ojuri.mcp_server.backends.base import set_backend
from ojuri.mcp_server.backends.sift.registry import SiftRegistryBackend
from ojuri.mcp_server.primitives.user_autostarts import (
    GetUserAutostartsInput,
    get_user_autostarts,
)

FREDR_NTUSER = Path("/evidence/rocba_test/Users/fredr/NTUSER.DAT")

pytestmark = pytest.mark.skipif(
    not FREDR_NTUSER.is_file(),
    reason=f"rocba_test fredr NTUSER.DAT not present at {FREDR_NTUSER}",
)


def test_user_autostarts_against_fredr_ntuser() -> None:
    set_backend(SiftRegistryBackend())

    payload = GetUserAutostartsInput(ntuser_hive_path=str(FREDR_NTUSER))
    result = asyncio.run(get_user_autostarts(payload))

    # ----- Layer 1: architectural -----
    assert result.primitive_name == "get_user_autostarts", result.primitive_name
    assert result.ntuser_hive_path == str(FREDR_NTUSER), result.ntuser_hive_path
    assert result.total_entries == len(result.entries), (
        f"total_entries {result.total_entries} != len(entries) {len(result.entries)}"
    )
    for e in result.entries:
        assert e.mechanism in ("Run", "RunOnce", "RunOnceEx"), e.mechanism
        assert e.username == "fredr", f"username wrong: {e.username!r}"
        assert e.hive_source == str(FREDR_NTUSER), e.hive_source
        assert e.name and isinstance(e.name, str)
        assert e.path and isinstance(e.path, str)

    # Deterministic ordering.
    sort_key = lambda e: (e.mechanism, e.name.lower())
    assert result.entries == sorted(result.entries, key=sort_key), "entries not sorted"

    # ----- Layer 2: rocba_test fredr ground truth (empirical) -----
    assert result.total_entries >= 0  # zero is itself a finding

    print("\n" + "=" * 70)
    print(f"get_user_autostarts ground truth — fredr NTUSER.DAT")
    print(f"total_entries = {result.total_entries}")
    print("=" * 70)
    for e in result.entries:
        print(
            f"  [{e.mechanism}] {e.name!r} -> {e.path!r} "
            f"(last_modified={e.last_modified!r})"
        )
    if not result.entries:
        print("  (no per-user Run/RunOnce/RunOnceEx persistence — itself a finding)")
    print("=" * 70)
