"""get_user_autostarts primitive — per-user (HKCU) login persistence.

Asks: 'What is configured to autostart for THIS user account?'

Companion to get_registry_autostarts, which covers machine-scope (HKLM) Run/
RunOnceEx/Service autostarts from the SOFTWARE/SYSTEM hives. That primitive
cannot see per-user persistence: the Run/RunOnce/RunOnceEx keys under
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion live in each user's
NTUSER.DAT, not in any machine hive. This primitive ingests a single
NTUSER.DAT hive (path supplied by list_evidence_artefacts discovery) and
returns that user's autostart entries.

Coverage in v0: Run, RunOnce, RunOnceEx (via the hive-aware RegRipper 'run'
and 'runonceex' plugins — rip.pl auto-detects the hive root, so the same
plugins that read HKLM\\Software also read HKCU\\Software in NTUSER.DAT).
Roadmap (out of scope for v0): Winlogon (Shell, Userinit) and the
Shell Folders Startup user-scope persistence vectors.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ojuri.mcp_server.backends.base import get_registry_backend

logger = logging.getLogger("ojuri.primitives.user_autostarts")


class GetUserAutostartsInput(BaseModel):
    """Input schema for get_user_autostarts."""

    ntuser_hive_path: str = Field(
        ...,
        description="Absolute path to a single user's NTUSER.DAT hive inside the "
        "mounted evidence. Obtain this from list_evidence_artefacts "
        "(user_profiles[].ntuser_dat). Call this primitive once per user.",
    )

    @field_validator("ntuser_hive_path")
    @classmethod
    def path_must_be_safe(cls, v: str) -> str:
        # Reject shell metacharacters and traversal patterns.
        # '$' is intentionally NOT in this list: it is a legitimate NTFS
        # metadata-file naming convention ($MFT, $LogFile, $Bitmap). Shell
        # substitution forms ('$(' and '${') are rejected explicitly below.
        dangerous = (";", "|", "&", "`", "(", ")", "\n", "\r")
        if any(d in v for d in dangerous):
            raise ValueError(f"path contains dangerous characters: {v!r}")
        if "$(" in v or "${" in v:
            raise ValueError(f"path contains shell substitution: {v!r}")
        if ".." in v:
            raise ValueError(f"path traversal detected: {v!r}")
        return v


class UserAutostartEntry(BaseModel):
    """One per-user autostart record. Returned in lists from the primitive."""

    name: str = Field(..., description="Registry value name.")
    path: str = Field(..., description="The executable path or command referenced by this autostart.")
    last_modified: str | None = Field(
        None,
        description="LastWrite time of the parent registry key, as reported by "
        "RegRipper. None if RegRipper did not emit one for the key.",
    )
    mechanism: Literal["Run", "RunOnce", "RunOnceEx"] = Field(
        ...,
        description="Which per-user autostart mechanism this entry represents.",
    )
    hive_source: str = Field(..., description="Absolute path of the NTUSER.DAT hive this entry was read from.")
    username: str | None = Field(
        None,
        description="Profile owner, derived from the NTUSER.DAT path's parent "
        "directory name (e.g. .../Users/fredr/NTUSER.DAT -> 'fredr'). "
        "None if it could not be derived.",
    )


class GetUserAutostartsOutput(BaseModel):
    """Output schema for get_user_autostarts."""

    primitive_name: Literal["get_user_autostarts"] = "get_user_autostarts"
    total_entries: int = Field(..., description="Number of per-user autostart entries found.")
    entries: list[UserAutostartEntry] = Field(
        ..., description="All per-user autostart entries, sorted by (mechanism, name)."
    )
    ntuser_hive_path: str = Field(..., description="The NTUSER.DAT path this result was produced from.")


async def get_user_autostarts(payload: GetUserAutostartsInput) -> GetUserAutostartsOutput:
    """Return all per-user autostart entries from the given NTUSER.DAT hive."""
    backend = get_registry_backend()
    hive = Path(payload.ntuser_hive_path)
    logger.info("get_user_autostarts ntuser=%s", hive)
    entries = await backend.get_user_autostarts(hive)
    return GetUserAutostartsOutput(
        total_entries=len(entries),
        entries=entries,
        ntuser_hive_path=payload.ntuser_hive_path,
    )
