"""Integration test for list_evidence_artefacts against the rocba_test mount.

Skipped (not failed) if /evidence/rocba_test is not mounted, so the suite
stays green on machines without the evidence volume.

Two-layer assertion pattern:
  * Layer 1 — architectural contract (holds for any evidence root).
  * Layer 2 — rocba_test ground truth (fredr + srl-h profiles, real hives,
    real Prefetch, real $MFT) — captured empirically, not assumed.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from ojuri.mcp_server.backends.base import set_evidence_backend
from ojuri.mcp_server.backends.sift.evidence import SiftEvidenceDiscoveryBackend
from ojuri.mcp_server.primitives.list_evidence_artefacts import (
    GetEvidenceArtefactsInput,
    list_evidence_artefacts,
)

EVIDENCE_ROOT = "/evidence/rocba_test"

pytestmark = pytest.mark.skipif(
    not os.path.isdir(os.path.join(EVIDENCE_ROOT, "Users")),
    reason=f"{EVIDENCE_ROOT} not mounted (Win10 rocba_test volume required)",
)


@pytest.fixture(scope="module")
def discovered():
    set_evidence_backend(SiftEvidenceDiscoveryBackend())
    payload = GetEvidenceArtefactsInput(evidence_root=EVIDENCE_ROOT)
    return asyncio.run(list_evidence_artefacts(payload))


# -- Layer 1: architectural contract ----------------------------------------
def test_layer1_architectural_contract(discovered) -> None:
    assert discovered.primitive_name == "list_evidence_artefacts"
    assert discovered.evidence_root == EVIDENCE_ROOT
    assert isinstance(discovered.user_profiles, list)
    assert len(discovered.user_profiles) >= 1
    assert isinstance(discovered.system_hives, list)
    assert len(discovered.system_hives) >= 1
    valid_hive_names = {"SOFTWARE", "SYSTEM", "SECURITY", "SAM", "DEFAULT"}
    for h in discovered.system_hives:
        assert h.name in valid_hive_names
        assert h.size_bytes > 0
    assert isinstance(discovered.prefetch_directories, list)
    assert isinstance(discovered.mft_files, list)
    assert len(discovered.mft_files) >= 1
    assert discovered.summary["users"] == len(discovered.user_profiles)
    assert discovered.summary["system_hives"] == len(discovered.system_hives)
    assert discovered.summary["prefetch_directories"] == len(
        discovered.prefetch_directories
    )
    assert discovered.summary["mft_files"] == len(discovered.mft_files)


# -- Layer 2: rocba_test ground truth ---------------------------------------
def test_layer2_user_profiles(discovered) -> None:
    by_name = {u.username: u for u in discovered.user_profiles}
    assert len(discovered.user_profiles) >= 2
    assert "fredr" in by_name, f"got users: {list(by_name)}"
    assert "srl-h" in by_name, f"got users: {list(by_name)}"
    assert by_name["fredr"].ntuser_dat is not None
    assert by_name["fredr"].ntuser_dat.endswith("/Users/fredr/NTUSER.DAT")
    assert by_name["srl-h"].ntuser_dat is not None
    assert by_name["srl-h"].ntuser_dat.endswith("/Users/srl-h/NTUSER.DAT")
    # Skipped pseudo-profiles must not appear.
    for skipped in ("Default", "Default User", "Public", "All Users"):
        assert skipped not in by_name


def test_layer2_system_hives(discovered) -> None:
    names = {h.name for h in discovered.system_hives}
    assert "SOFTWARE" in names
    assert "SYSTEM" in names


def test_layer2_prefetch_and_mft(discovered) -> None:
    assert len(discovered.prefetch_directories) == 1
    assert discovered.prefetch_directories[0].endswith("/Windows/Prefetch")
    assert any(p.endswith("/$MFT") for p in discovered.mft_files)


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
