"""Integration test for get_prefetch_entries.

Parses three real Win10 .pf fixtures via pyscca. Two assertion layers:
  Layer 1 (architectural): properties true regardless of fixture.
  Layer 2 (fixture-specific): values observed for these specific fixtures.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from ojuri.mcp_server.backends.base import set_prefetch_backend
from ojuri.mcp_server.backends.sift.prefetch import SiftPrefetchBackend
from ojuri.mcp_server.primitives.prefetch_entries import (
    GetPrefetchEntriesInput,
    get_prefetch_entries,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "prefetch"

EXPECTED_PF_FILES = {
    "CALC.EXE-3FBEF7FD.pf",
    "CMD.EXE-D269B812.pf",
    "CHROME.EXE-B3BA7868.pf",
}


async def run_test() -> int:
    if not FIXTURE_DIR.is_dir():
        print(f"FAIL: fixture directory missing: {FIXTURE_DIR}", file=sys.stderr)
        return 1

    set_prefetch_backend(SiftPrefetchBackend())
    print("OK: backend initialised")

    # Test 1: directory input
    payload = GetPrefetchEntriesInput(prefetch_path=str(FIXTURE_DIR))
    result = await get_prefetch_entries(payload)

    # Layer 1
    assert result.primitive_name == "get_prefetch_entries"
    assert result.total_entries == len(result.entries) == 3, \
        f"expected 3 entries, got {result.total_entries}"
    print(f"OK [L1]: 3 entries parsed from directory input")

    for e in result.entries:
        assert e.executable_name and isinstance(e.executable_name, str)
        assert e.prefetch_filename.endswith(".pf")
        assert e.run_count >= 1
        assert e.prefetch_source.startswith(str(FIXTURE_DIR))
    print(f"OK [L1]: all entries well-formed")

    sort_key = lambda x: (x.executable_name.lower(), -(x.last_run_time_unix or 0))
    assert result.entries == sorted(result.entries, key=sort_key)
    print(f"OK [L1]: entries sorted deterministically")

    # Layer 2: filenames
    returned_filenames = {e.prefetch_filename for e in result.entries}
    missing = EXPECTED_PF_FILES - returned_filenames
    if missing:
        print(f"FAIL [L2]: missing fixtures: {missing}", file=sys.stderr)
        return 1
    print(f"OK [L2]: all 3 expected fixtures present")

    # Layer 2: CALC.EXE pre-verified ground truth
    calc = next((e for e in result.entries if e.prefetch_filename == "CALC.EXE-3FBEF7FD.pf"), None)
    assert calc is not None, "CALC.EXE entry missing"
    assert calc.executable_name == "CALC.EXE", f"unexpected exec: {calc.executable_name}"
    assert calc.run_count == 2, f"unexpected run_count: {calc.run_count}"
    assert calc.loaded_files, "CALC.EXE should reference loaded files"
    assert len(calc.loaded_files) >= 50, f"expected ~63 loaded files, got {len(calc.loaded_files)}"
    print(f"OK [L2]: CALC.EXE ground truth matches (executable, run_count, loaded_files)")

    # Test 2: single-file input
    single_pf = FIXTURE_DIR / "CALC.EXE-3FBEF7FD.pf"
    payload2 = GetPrefetchEntriesInput(prefetch_path=str(single_pf))
    result2 = await get_prefetch_entries(payload2)
    assert result2.total_entries == 1, f"single-file: expected 1, got {result2.total_entries}"
    assert result2.entries[0].prefetch_filename == "CALC.EXE-3FBEF7FD.pf"
    print(f"OK [L1+L2]: single-file input returns exactly 1 entry")

    print("=" * 60)
    print("PREFETCH INTEGRATION TEST PASSED")
    print("=" * 60)
    return 0


def test_real_rocba_prefetch_partial_tolerance() -> None:
    """Real rocba Prefetch dir contains at least one .pf libscca cannot parse
    (empirically MOUSOCOREWORKER.EXE-4429AC2B.pf — "unsupported signature").
    The sweep must still return the parseable entries AND record the failures
    in `skipped` rather than aborting the whole primitive."""
    import pytest

    rocba = Path("/evidence/rocba_test/Windows/Prefetch")
    if not rocba.is_dir():
        pytest.skip(f"rocba evidence not present: {rocba}")

    set_prefetch_backend(SiftPrefetchBackend())
    payload = GetPrefetchEntriesInput(prefetch_path=str(rocba))
    result = asyncio.run(get_prefetch_entries(payload))

    assert result.total_entries == len(result.entries)
    assert result.total_entries > 0, "expected some .pf files to parse"
    assert len(result.skipped) > 0, \
        "expected at least one unparseable .pf recorded in `skipped`"
    for s in result.skipped:
        assert s.filename.lower().endswith(".pf")
        assert s.error_class and s.message


if __name__ == "__main__":
    sys.exit(asyncio.run(run_test()))
