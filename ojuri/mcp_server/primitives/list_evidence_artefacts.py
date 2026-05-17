"""list_evidence_artefacts primitive — the discovery primitive.

Asks: 'Where are the canonical forensic artefacts on this mounted evidence?'

This is the FOURTH implemented primitive and the mandatory first call on every
case: it walks a mounted evidence root and returns the absolute paths the other
primitives (registry/prefetch/MFT) need as input. It does NOT subprocess any
external tool — it is a pure-Python read-only filesystem walk (backend
strategy D).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ojuri.mcp_server.backends.base import get_evidence_backend

logger = logging.getLogger("ojuri.primitives.list_evidence_artefacts")

# Discovery may only be pointed at a mounted evidence tree or the raw staging
# area. Anything else (/, /etc, /home, /tmp, …) is rejected up front.
ALLOWED_EVIDENCE_PREFIXES = ("/evidence/", "/var/lib/ojuri/raw/")


def _path_is_whitelisted(v: str) -> bool:
    """True iff v is an absolute path under an allowed evidence parent dir."""
    return any(
        v == prefix.rstrip("/") or v.startswith(prefix)
        for prefix in ALLOWED_EVIDENCE_PREFIXES
    )


class GetEvidenceArtefactsInput(BaseModel):
    """Input schema for list_evidence_artefacts."""

    evidence_root: str = Field(
        ...,
        description=(
            "Absolute path to the root of a mounted evidence volume "
            "(e.g. /evidence/<case>). Must be under /evidence/ or "
            "/var/lib/ojuri/raw/. Read-only; never written to."
        ),
    )

    @field_validator("evidence_root")
    @classmethod
    def path_must_be_safe(cls, v: str) -> str:
        # Reject shell metacharacters (defence-in-depth; no subprocess here,
        # but the same rule is used by every other primitive's path field).
        dangerous = (";", "|", "&", "`", "$", "(", ")", "\n", "\r")
        if any(d in v for d in dangerous):
            raise ValueError(f"path contains dangerous characters: {v!r}")
        if ".." in v:
            raise ValueError(f"path traversal detected: {v!r}")
        if not v.startswith("/"):
            raise ValueError(f"path must be absolute: {v!r}")
        if not _path_is_whitelisted(v):
            raise ValueError(
                f"path not under an allowed evidence root "
                f"({', '.join(ALLOWED_EVIDENCE_PREFIXES)}): {v!r}"
            )
        return v


class UserProfile(BaseModel):
    """One discovered Windows user profile under Users/."""

    username: str = Field(..., description="Basename of the profile directory, e.g. 'fredr'.")
    profile_path: str = Field(..., description="Absolute path to the user profile directory.")
    ntuser_dat: str | None = Field(
        None,
        description="Absolute path to NTUSER.DAT, or None if missing/unreadable.",
    )
    usrclass_dat: str | None = Field(
        None,
        description=(
            "Absolute path to AppData/Local/Microsoft/Windows/UsrClass.dat, "
            "or None if missing/unreadable."
        ),
    )


class SystemHive(BaseModel):
    """One discovered system registry hive under Windows/System32/config/."""

    name: Literal["SOFTWARE", "SYSTEM", "SECURITY", "SAM", "DEFAULT"] = Field(
        ..., description="Canonical hive name."
    )
    path: str = Field(..., description="Absolute path to the hive file.")
    size_bytes: int = Field(..., description="File size in bytes (sanity check).")


class DiscoveredEvidence(BaseModel):
    """Output schema for list_evidence_artefacts."""

    primitive_name: Literal["list_evidence_artefacts"] = "list_evidence_artefacts"
    evidence_root: str = Field(..., description="The evidence root that was walked.")
    user_profiles: list[UserProfile] = Field(
        ..., description="Discovered user profiles with their per-user hives."
    )
    system_hives: list[SystemHive] = Field(
        ..., description="Discovered system hives that exist on disk."
    )
    prefetch_directories: list[str] = Field(
        ..., description="Absolute path(s) to Prefetch directories containing .pf files."
    )
    mft_files: list[str] = Field(
        ..., description="Absolute path(s) to $MFT file(s)."
    )
    summary: dict[str, int] = Field(
        ..., description="Counts: users, system_hives, prefetch_directories, mft_files."
    )


async def list_evidence_artefacts(
    payload: GetEvidenceArtefactsInput,
) -> DiscoveredEvidence:
    """Walk the evidence root and return categorized artefact paths."""
    backend = get_evidence_backend()
    root = Path(payload.evidence_root)
    logger.info("list_evidence_artefacts evidence_root=%s", root)
    return await backend.list_evidence_artefacts(root)
