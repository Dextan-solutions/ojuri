"""SIFT backend for MFT queries. Subprocesses MFTECmd, parses CSV output."""

from __future__ import annotations

import asyncio
import csv
import logging
import tempfile
from datetime import datetime
from pathlib import Path

from ojuri.mcp_server.backends.base import BackendError, MftBackend

logger = logging.getLogger("ojuri.backends.sift.mft")

MFTECMD_TIMEOUT_SECONDS = 120
# Cap to avoid memory issues. Hard upper limit regardless of caller's max_entries.
HARD_CAP = 10_000


def _parse_mftecmd_time(raw: str) -> datetime | None:
    """Parse MFTECmd timestamp like '2012-02-06 16:16:19.6033593' to UTC datetime.
    Empty string returns None. Truncates fractional seconds to 6 digits."""
    if not raw or not raw.strip():
        return None
    try:
        # MFTECmd uses 7-digit fractional seconds; Python expects max 6
        if '.' in raw:
            base, frac = raw.rsplit('.', 1)
            frac = frac[:6]
            raw = f"{base}.{frac}"
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


class SiftMftBackend(MftBackend):
    async def get_mft_timeline(
        self,
        mft_path: Path,
        start_time: str | None,
        end_time: str | None,
        max_entries: int,
    ) -> list:
        from ojuri.mcp_server.primitives.mft_timeline import MftEntry

        if not mft_path.exists():
            raise FileNotFoundError(f"mft_path not found: {mft_path}")
        if not mft_path.is_file():
            raise BackendError(f"mft_path is not a file: {mft_path}")

        # Parse bounds
        start_dt = _parse_mftecmd_time(start_time) if start_time else None
        end_dt = _parse_mftecmd_time(end_time) if end_time else None
        cap = min(max(1, max_entries), HARD_CAP)

        # Run MFTECmd in a temp directory
        with tempfile.TemporaryDirectory(prefix="ojuri_mft_") as tmp:
            tmp_path = Path(tmp)
            csv_name = "out.csv"
            cmd = [
                "MFTECmd",
                "-f", str(mft_path),
                "--csv", str(tmp_path),
                "--csvf", csv_name,
            ]
            logger.info("Running MFTECmd: %s", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=MFTECMD_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                proc.kill()
                raise BackendError(f"MFTECmd timed out after {MFTECMD_TIMEOUT_SECONDS}s")

            if proc.returncode != 0:
                raise BackendError(
                    f"MFTECmd exited {proc.returncode}: stderr={stderr.decode(errors='replace')[:500]}"
                )

            csv_path = tmp_path / csv_name
            if not csv_path.exists():
                raise BackendError(f"MFTECmd produced no CSV at {csv_path}")

            # Parse CSV. MFTECmd writes a UTF-8 BOM; utf-8-sig strips it so the
            # first column key is "EntryNumber" rather than "﻿EntryNumber".
            entries: list[MftEntry] = []
            with csv_path.open(newline="", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    last_modified_dt = _parse_mftecmd_time(row.get("LastModified0x10", ""))

                    # Time-window filter
                    if last_modified_dt is None:
                        # Records without LastModified0x10 only included if no time filter active
                        if start_dt or end_dt:
                            continue
                    else:
                        if start_dt and last_modified_dt < start_dt:
                            continue
                        if end_dt and last_modified_dt > end_dt:
                            continue

                    try:
                        entry = MftEntry(
                            entry_number=int(row["EntryNumber"]),
                            sequence_number=int(row["SequenceNumber"]),
                            in_use=row["InUse"].lower() == "true",
                            parent_path=row.get("ParentPath", "") or "",
                            file_name=row.get("FileName", "") or "",
                            extension=row.get("Extension", "") or "",
                            file_size=int(row["FileSize"]) if row.get("FileSize") else 0,
                            is_directory=row.get("IsDirectory", "").lower() == "true",
                            has_ads=row.get("HasAds", "").lower() == "true",
                            is_ads=row.get("IsAds", "").lower() == "true",
                            created=row.get("Created0x10", "") or "",
                            last_modified=row.get("LastModified0x10", "") or "",
                            last_record_change=row.get("LastRecordChange0x10", "") or "",
                            last_access=row.get("LastAccess0x10", "") or "",
                            source_file=row.get("SourceFile", "") or "",
                        )
                        entries.append(entry)
                    except (ValueError, KeyError) as e:
                        logger.warning("Skipped malformed row: %s", e)
                        continue

            # Sort descending by last_modified (empty strings sort last)
            entries.sort(key=lambda e: e.last_modified or "", reverse=True)

            # Cap
            if len(entries) > cap:
                entries = entries[:cap]

            logger.info("MFT parse complete: %d entries returned (start=%s end=%s cap=%d)",
                        len(entries), start_time, end_time, cap)
            return entries
