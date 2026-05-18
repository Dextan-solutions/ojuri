"""get_registry_autostarts primitive — the first real forensic primitive.

Asks: 'What is configured to autostart on this system?'
Coverage in Week 2 Task 1: Run keys, RunOnceEx, Service DLL autostarts.
Future expansion: Winlogon shell, AppInit_DLLs, image file execution options.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ojuri.mcp_server.backends.base import get_registry_backend

logger = logging.getLogger("ojuri.primitives.registry_autostarts")


class GetRegistryAutostartsInput(BaseModel):
    """Input schema for get_registry_autostarts."""

    software_hive_path: str = Field(
        ...,
        description="Absolute path to the SOFTWARE registry hive file inside the mounted evidence.",
    )
    system_hive_path: str | None = Field(
        None,
        description="Optional absolute path to the SYSTEM hive (required for service autostarts).",
    )

    @field_validator("software_hive_path", "system_hive_path")
    @classmethod
    def path_must_be_safe(cls, v: str | None) -> str | None:
        if v is None:
            return None
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


class AutostartEntry(BaseModel):
    """One autostart record. Returned in lists from the primitive."""

    name: str = Field(..., description="Registry value name or service name.")
    path: str = Field(..., description="The executable path or DLL referenced by this autostart.")
    value: str = Field(..., description="Full raw value string from the registry (same as path for most mechanisms).")
    last_modified: str = Field(
        "",
        description="LastWrite time of the parent registry key, as reported by RegRipper. May be empty if not available.",
    )
    hive_source: str = Field(..., description="Absolute path of the hive this entry was read from.")
    mechanism: Literal["Run", "RunOnceEx", "Service"] = Field(
        ...,
        description="Which autostart mechanism this entry represents. Distinguishes Run keys from service auto-start.",
    )


class GetRegistryAutostartsOutput(BaseModel):
    """Output schema for get_registry_autostarts."""

    primitive_name: Literal["get_registry_autostarts"] = "get_registry_autostarts"
    total_entries: int = Field(..., description="Number of autostart entries found across all mechanisms.")
    entries: list[AutostartEntry] = Field(..., description="All autostart entries, sorted by (mechanism, name).")


async def get_registry_autostarts(payload: GetRegistryAutostartsInput) -> GetRegistryAutostartsOutput:
    """Return all autostart entries from the given hive(s) via the active backend."""
    backend = get_registry_backend()
    software = Path(payload.software_hive_path)
    system = Path(payload.system_hive_path) if payload.system_hive_path else None
    logger.info("get_registry_autostarts software=%s system=%s", software, system)
    entries = await backend.get_registry_autostarts(software, system)
    return GetRegistryAutostartsOutput(
        total_entries=len(entries),
        entries=entries,
    )
