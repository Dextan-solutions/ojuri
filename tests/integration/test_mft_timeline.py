"""Integration test for get_mft_timeline against NIST DFR-16 $MFT fixture.

Ground truth empirically captured from MFTECmd output (not assumed):
  - 117 records total (no time filter).
  - EntryNumber 0 = "$MFT", EntryNumber 1 = "$MFTMirr".
  - LastModified0x10 distribution: 45 records on 1999-04-03,
    71 records on 2012-02-06, 1 record with empty LastModified0x10.
  - Time window 2012-02-06 00:00:00 .. 2012-02-07 00:00:00 (inclusive):
    71 records (the 1999 records and the empty-timestamp record are excluded
    because a time filter is active).
  - Time window 2012-02-07 00:00:00 .. 2012-02-08 00:00:00: 0 records.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from ojuri.mcp_server.backends.base import set_mft_backend
from ojuri.mcp_server.backends.sift.mft import SiftMftBackend
from ojuri.mcp_server.primitives.mft_timeline import (
    GetMftTimelineInput, get_mft_timeline,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "mft" / "dfr16_mft.bin"


async def run() -> int:
    if not FIXTURE.is_file():
        print(f"FAIL: fixture not found at {FIXTURE}", file=sys.stderr)
        return 1

    set_mft_backend(SiftMftBackend())
    print("OK: MFT backend initialised")

    # Test 1: No filter, should return all 117 records
    payload = GetMftTimelineInput(mft_path=str(FIXTURE), max_entries=1000)
    result = await get_mft_timeline(payload)

    # Layer 1
    assert result.primitive_name == "get_mft_timeline"
    assert result.total_entries == len(result.entries) == 117, \
        f"expected 117 entries, got {result.total_entries}"
    print(f"OK [L1]: no filter returns 117 entries")

    # Layer 1: every entry well-formed
    for e in result.entries:
        assert isinstance(e.entry_number, int)
        assert isinstance(e.file_size, int) and e.file_size >= 0
        assert isinstance(e.is_directory, bool)
    print(f"OK [L1]: all 117 entries well-formed")

    # Layer 1: sorted by last_modified desc
    last_mods = [e.last_modified for e in result.entries if e.last_modified]
    assert last_mods == sorted(last_mods, reverse=True), "entries not sorted by last_modified desc"
    print(f"OK [L1]: entries sorted by last_modified descending")

    # Layer 2: $MFT and $MFTMirr exist
    by_entry = {e.entry_number: e for e in result.entries}
    assert 0 in by_entry, "EntryNumber 0 missing"
    assert 1 in by_entry, "EntryNumber 1 missing"
    assert by_entry[0].file_name == "$MFT", f"EntryNumber 0 not $MFT: {by_entry[0].file_name}"
    assert by_entry[1].file_name == "$MFTMirr", f"EntryNumber 1 not $MFTMirr: {by_entry[1].file_name}"
    print(f"OK [L2]: $MFT and $MFTMirr present at EntryNumber 0 and 1")

    # Layer 2: timestamp distribution matches captured ground truth
    # (45 records on 1999-04-03, 71 on 2012-02-06, 1 with empty LastModified0x10)
    dates = [e.last_modified[:10] for e in result.entries if e.last_modified]
    empty = sum(1 for e in result.entries if not e.last_modified)
    n_1999 = sum(1 for d in dates if d == "1999-04-03")
    n_2012 = sum(1 for d in dates if d == "2012-02-06")
    for e in result.entries:
        if e.last_modified:
            assert e.last_modified.startswith(("1999-04-03", "2012-02-06")), \
                f"unexpected date in fixture: {e.last_modified}"
    assert (n_1999, n_2012, empty) == (45, 71, 1), \
        f"expected (1999=45, 2012=71, empty=1), got ({n_1999}, {n_2012}, {empty})"
    print(f"OK [L2]: timestamp distribution 45x1999-04-03, 71x2012-02-06, 1 empty")

    # Test 2: time window covering the 2012-02-06 fixture day
    # -> 71 (1999 records + the empty-timestamp record excluded by active filter)
    payload2 = GetMftTimelineInput(
        mft_path=str(FIXTURE),
        start_time="2012-02-06 00:00:00",
        end_time="2012-02-07 00:00:00",
    )
    result2 = await get_mft_timeline(payload2)
    assert result2.total_entries == 71, \
        f"window covering 2012-02-06: expected 71, got {result2.total_entries}"
    for e in result2.entries:
        assert e.last_modified.startswith("2012-02-06"), \
            f"window leaked non-2012-02-06 entry: {e.last_modified}"
    print(f"OK [L1+L2]: time-window over 2012-02-06 returns 71 (filtered)")

    # Test 3: time window outside fixture date range -> 0
    payload3 = GetMftTimelineInput(
        mft_path=str(FIXTURE),
        start_time="2012-02-07 00:00:00",
        end_time="2012-02-08 00:00:00",
    )
    result3 = await get_mft_timeline(payload3)
    assert result3.total_entries == 0, f"window outside fixture: expected 0, got {result3.total_entries}"
    print(f"OK [L1]: time-window outside fixture returns 0")

    # Test 4: max_entries cap
    payload4 = GetMftTimelineInput(mft_path=str(FIXTURE), max_entries=10)
    result4 = await get_mft_timeline(payload4)
    assert result4.total_entries == 10, f"max_entries=10: expected 10, got {result4.total_entries}"
    print(f"OK [L1]: max_entries=10 caps at 10")

    print("=" * 60)
    print("MFT INTEGRATION TEST PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
