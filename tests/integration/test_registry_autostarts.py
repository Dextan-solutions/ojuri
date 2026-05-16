"""Integration test for get_registry_autostarts.

Runs the real rip.pl subprocess against the fixture hive (tests/fixtures/NTUSER.DAT).
Two assertion layers:
  Layer 1 (architectural): properties that must hold regardless of which hive is used.
  Layer 2 (fixture-specific): entries we know are in THIS specific fixture.
If we swap the fixture later, only Layer 2 needs updating; Layer 1 protects the contract.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from ojuri.mcp_server.backends.base import set_backend
from ojuri.mcp_server.backends.sift.registry import SiftRegistryBackend
from ojuri.mcp_server.primitives.registry_autostarts import (
    GetRegistryAutostartsInput,
    get_registry_autostarts,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_HIVE = REPO_ROOT / "tests" / "fixtures" / "NTUSER.DAT"

# Layer 2: Entries known to exist in tests/fixtures/NTUSER.DAT.
# Captured empirically by running `rip.pl -r NTUSER.DAT -p run` and observing output.
# If the fixture file is replaced, update this set to match the new fixture's entries.
KNOWN_FIXTURE_ENTRIES = {
    "Amazon Music",
    "Spotify",
    "Skype",
    "DU Meter",
    "RoboForm",
    "CCleaner Monitoring",
    "DisplayFusion",
}


async def run_test() -> int:
    if not FIXTURE_HIVE.is_file():
        print(f"FAIL: fixture not found at {FIXTURE_HIVE}", file=sys.stderr)
        return 1

    set_backend(SiftRegistryBackend())
    print("OK: backend initialised")

    # Invoke the primitive. NTUSER.DAT is being passed as the software_hive_path argument
    # because rip.pl's run/runonceex plugins accept any hive containing Software\... keys
    # (NTUSER.DAT has HKCU\Software\Microsoft\Windows\CurrentVersion\Run, which is what
    # the run plugin reads — same path used by SOFTWARE hive at HKLM scope).
    payload = GetRegistryAutostartsInput(software_hive_path=str(FIXTURE_HIVE))
    result = await get_registry_autostarts(payload)

    # ----- Layer 1: Architectural assertions (hive-agnostic) -----

    # 1.1 Output object shape
    assert result.primitive_name == "get_registry_autostarts", \
        f"primitive_name wrong: {result.primitive_name}"
    assert isinstance(result.total_entries, int), \
        f"total_entries not int: {type(result.total_entries)}"
    assert result.total_entries == len(result.entries), \
        f"total_entries {result.total_entries} != len(entries) {len(result.entries)}"
    print(f"OK [L1]: output object well-formed, total_entries={result.total_entries}")

    # 1.2 Every entry has the expected fields populated correctly
    for e in result.entries:
        assert e.name and isinstance(e.name, str), f"empty/non-string name in entry: {e}"
        assert e.path and isinstance(e.path, str), f"empty/non-string path in entry: {e}"
        assert e.hive_source == str(FIXTURE_HIVE), f"hive_source wrong: {e.hive_source}"
        assert e.mechanism in ("Run", "RunOnceEx", "Service"), f"unexpected mechanism: {e.mechanism}"
    print(f"OK [L1]: all {len(result.entries)} entries have valid required fields")

    # 1.3 Entries are sorted by (mechanism, name.lower()) for determinism
    sort_key = lambda e: (e.mechanism, e.name.lower())
    sorted_check = sorted(result.entries, key=sort_key)
    assert result.entries == sorted_check, "entries not sorted by (mechanism, name)"
    print("OK [L1]: entries are sorted deterministically")

    # 1.4 No svcdll entries (we didn't pass a SYSTEM hive)
    svcdll_entries = [e for e in result.entries if e.mechanism == "Service"]
    assert svcdll_entries == [], \
        f"unexpected Service entries when no SYSTEM hive provided: {svcdll_entries}"
    print("OK [L1]: no Service entries (no SYSTEM hive passed)")

    # ----- Layer 2: Fixture-specific assertions -----

    returned_names = {e.name for e in result.entries}
    missing = KNOWN_FIXTURE_ENTRIES - returned_names
    if missing:
        print(f"FAIL [L2]: fixture's known entries missing from result: {missing}", file=sys.stderr)
        print(f"actual entries returned: {sorted(returned_names)}", file=sys.stderr)
        return 1
    print(f"OK [L2]: all {len(KNOWN_FIXTURE_ENTRIES)} known fixture entries present in result")

    # Layer 2: at least one path contains expected substring (sanity check on path parsing)
    amazon = next((e for e in result.entries if e.name == "Amazon Music"), None)
    assert amazon is not None, "Amazon Music entry missing"
    assert "Amazon Music Helper.exe" in amazon.path, \
        f"Amazon Music path looks wrong: {amazon.path!r}"
    print(f"OK [L2]: Amazon Music path correctly parsed: {amazon.path}")

    print("=" * 60)
    print("INTEGRATION TEST PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_test()))
