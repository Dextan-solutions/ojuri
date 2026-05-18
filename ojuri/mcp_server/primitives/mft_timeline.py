"""get_mft_timeline primitive — parses NTFS MFT for timeline analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from ojuri.mcp_server.backends.base import get_mft_backend

logger = logging.getLogger("ojuri.primitives.mft_timeline")


class GetMftTimelineInput(BaseModel):
    mft_path: str = Field(..., description="Absolute path to an $MFT file.")
    start_time: str | None = Field(None, description="Optional ISO-8601 UTC lower bound for LastModified.")
    end_time: str | None = Field(None, description="Optional ISO-8601 UTC upper bound for LastModified.")
    max_entries: int = Field(1000, ge=1, le=10000, description="Max entries to return (cap 10000).")

    @field_validator("mft_path")
    @classmethod
    def path_safe(cls, v: str) -> str:
        # '$' is intentionally NOT in this list: it is a legitimate NTFS
        # metadata-file naming convention ($MFT, $LogFile, $Bitmap). Shell
        # substitution forms ('$(' and '${') are rejected explicitly below.
        dangerous = (";", "|", "&", "`", "(", ")", "\n", "\r")
        if any(d in v for d in dangerous):
            raise ValueError(f"path contains dangerous characters: {v!r}")
        if "$(" in v or "${" in v:
            raise ValueError(f"path contains shell substitution: {v!r}")
        if ".." in v:
            raise ValueError(f"path traversal: {v!r}")
        return v


class MftEntry(BaseModel):
    entry_number: int = Field(..., description="MFT record number.")
    sequence_number: int = Field(..., description="MFT sequence number.")
    in_use: bool = Field(..., description="Whether the record is allocated.")
    parent_path: str = Field("", description="Full path to parent directory.")
    file_name: str = Field("", description="File or directory name.")
    extension: str = Field("", description="File extension (empty for directories).")
    file_size: int = Field(0, description="File size in bytes (0 for directories/ADS metadata).")
    is_directory: bool = Field(False, description="True if directory.")
    has_ads: bool = Field(False, description="True if this entry has one or more Alternate Data Streams.")
    is_ads: bool = Field(False, description="True if this entry represents an ADS.")
    created: str = Field("", description="Standard Information created timestamp (raw MFTECmd format).")
    last_modified: str = Field("", description="Standard Information last-modified timestamp.")
    last_record_change: str = Field("", description="Standard Information record-change timestamp.")
    last_access: str = Field("", description="Standard Information last-access timestamp.")
    source_file: str = Field("", description="Original $MFT file path MFTECmd parsed.")


class GetMftTimelineOutput(BaseModel):
    primitive_name: Literal["get_mft_timeline"] = "get_mft_timeline"
    total_entries: int = Field(..., description="Number of entries returned.")
    entries: list[MftEntry] = Field(..., description="Entries sorted by last_modified desc.")


async def get_mft_timeline(payload: GetMftTimelineInput) -> GetMftTimelineOutput:
    backend = get_mft_backend()
    path = Path(payload.mft_path)
    logger.info("get_mft_timeline path=%s start=%s end=%s max=%d",
                path, payload.start_time, payload.end_time, payload.max_entries)
    entries = await backend.get_mft_timeline(
        path, payload.start_time, payload.end_time, payload.max_entries
    )
    return GetMftTimelineOutput(total_entries=len(entries), entries=entries)
