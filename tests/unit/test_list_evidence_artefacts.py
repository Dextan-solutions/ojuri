"""Unit tests for list_evidence_artefacts input validation and schemas.

No filesystem walk and no backend invocation: these tests exercise the
Pydantic input validator (path safety + whitelist) and the output-schema
contracts (UserProfile / SystemHive / DiscoveredEvidence).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ojuri.mcp_server.primitives.list_evidence_artefacts import (
    DiscoveredEvidence,
    GetEvidenceArtefactsInput,
    SystemHive,
    UserProfile,
)


def test_valid_evidence_root_accepted() -> None:
    a = GetEvidenceArtefactsInput(evidence_root="/evidence/rocba_test")
    assert a.evidence_root == "/evidence/rocba_test"
    b = GetEvidenceArtefactsInput(evidence_root="/var/lib/ojuri/raw/case_001")
    assert b.evidence_root == "/var/lib/ojuri/raw/case_001"


def test_path_with_shell_metachar_rejected() -> None:
    for bad in (
        "/evidence/x; rm -rf /",
        "/evidence/$(whoami)",
        "/evidence/a|b",
        "/evidence/a`id`",
        "/evidence/a&b",
    ):
        with pytest.raises(ValidationError):
            GetEvidenceArtefactsInput(evidence_root=bad)


def test_path_traversal_rejected() -> None:
    with pytest.raises(ValidationError):
        GetEvidenceArtefactsInput(evidence_root="/evidence/../etc")


def test_relative_path_rejected() -> None:
    with pytest.raises(ValidationError):
        GetEvidenceArtefactsInput(evidence_root="evidence/rocba_test")


def test_path_outside_whitelist_rejected() -> None:
    for bad in ("/etc/passwd", "/home/sansforensics", "/tmp/x", "/", "/evidencex"):
        with pytest.raises(ValidationError):
            GetEvidenceArtefactsInput(evidence_root=bad)


def test_schema_userprofile_required_fields() -> None:
    with pytest.raises(ValidationError):
        UserProfile(profile_path="/evidence/x/Users/fredr")  # missing username
    up = UserProfile(
        username="fredr",
        profile_path="/evidence/x/Users/fredr",
        ntuser_dat=None,
        usrclass_dat=None,
    )
    assert up.username == "fredr"
    assert up.ntuser_dat is None


def test_schema_systemhive_name_enum_constrained() -> None:
    with pytest.raises(ValidationError):
        SystemHive(name="BOGUS", path="/evidence/x/c/BOGUS", size_bytes=1)
    sh = SystemHive(
        name="SOFTWARE",
        path="/evidence/x/Windows/System32/config/SOFTWARE",
        size_bytes=12345,
    )
    assert sh.name == "SOFTWARE"


def test_discoveredevidence_serialization_roundtrip() -> None:
    de = DiscoveredEvidence(
        evidence_root="/evidence/rocba_test",
        user_profiles=[
            UserProfile(
                username="fredr",
                profile_path="/evidence/rocba_test/Users/fredr",
                ntuser_dat="/evidence/rocba_test/Users/fredr/NTUSER.DAT",
                usrclass_dat=None,
            )
        ],
        system_hives=[
            SystemHive(
                name="SYSTEM",
                path="/evidence/rocba_test/Windows/System32/config/SYSTEM",
                size_bytes=999,
            )
        ],
        prefetch_directories=["/evidence/rocba_test/Windows/Prefetch"],
        mft_files=["/evidence/rocba_test/$MFT"],
        summary={"users": 1, "system_hives": 1, "prefetch_directories": 1, "mft_files": 1},
    )
    assert de.primitive_name == "list_evidence_artefacts"
    dumped = de.model_dump_json()
    restored = DiscoveredEvidence.model_validate_json(dumped)
    assert restored == de
    assert restored.summary["users"] == 1


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
