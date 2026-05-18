"""get_prefetch_entries primitive — parses Windows Prefetch (.pf) files.

Asks: 'What programs ran on this system, when, and how often?'
Backend: SIFT via pyscca (libscca C bindings).
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ojuri.mcp_server.backends.base import get_prefetch_backend
from pathlib import Path

logger = logging.getLogger("ojuri.primitives.prefetch_entries")


class GetPrefetchEntriesInput(BaseModel):
    prefetch_path: str = Field(
        ...,
        description="Absolute path to a Prefetch .pf file OR a directory containing .pf files.",
    )

    @field_validator("prefetch_path")
    @classmethod
    def path_must_be_safe(cls, v: str) -> str:
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


class PrefetchEntry(BaseModel):
    executable_name: str = Field(..., description="Executable filename as recorded inside the prefetch file.")
    prefetch_filename: str = Field(..., description="The .pf filename itself.")
    run_count: int = Field(..., description="Number of times this executable has run.")
    last_run_time: str = Field("", description="ISO-8601 UTC of most recent execution.")
    last_run_time_unix: int | None = Field(None, description="Unix epoch seconds of last_run_time.")
    previous_run_times: list[str] = Field(default_factory=list, description="Up to 7 prior execution timestamps.")
    volume_name: str = Field("", description="Volume device path the executable was launched from.")
    volume_serial: str = Field("", description="Volume serial number (hex string).")
    loaded_files: list[str] = Field(default_factory=list, description="File references recorded by the prefetcher.")
    prefetch_source: str = Field(..., description="Absolute path of the .pf file this entry was read from.")


class GetPrefetchEntriesOutput(BaseModel):
    primitive_name: Literal["get_prefetch_entries"] = "get_prefetch_entries"
    total_entries: int = Field(..., description="Number of prefetch files successfully parsed.")
    entries: list[PrefetchEntry] = Field(..., description="One entry per parsed .pf file.")


async def get_prefetch_entries(payload: GetPrefetchEntriesInput) -> GetPrefetchEntriesOutput:
    backend = get_prefetch_backend()
    path = Path(payload.prefetch_path)
    logger.info("get_prefetch_entries path=%s", path)
    entries = await backend.get_prefetch_entries(path)
    return GetPrefetchEntriesOutput(total_entries=len(entries), entries=entries)
