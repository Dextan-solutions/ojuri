"""SIFT backend implementation for prefetch queries.

Uses pyscca (libscca's Python C-extension bindings) to parse Windows Prefetch
.pf files. No subprocess; direct library call.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timezone
from pathlib import Path

import pyscca

from ojuri.mcp_server.backends.base import BackendError, PrefetchBackend

logger = logging.getLogger("ojuri.backends.sift.prefetch")


class SiftPrefetchBackend(PrefetchBackend):
    """pyscca-based prefetch parser."""

    async def get_prefetch_entries(self, prefetch_path: Path) -> list:
        from ojuri.mcp_server.primitives.prefetch_entries import PrefetchEntry

        if not prefetch_path.exists():
            raise FileNotFoundError(f"prefetch_path not found: {prefetch_path}")

        if prefetch_path.is_file():
            pf_files = [prefetch_path]
        else:
            pf_files = sorted(prefetch_path.glob("*.pf"))
            pf_files.extend(sorted(prefetch_path.glob("*.PF")))
            pf_files = sorted(set(pf_files))

        if not pf_files:
            logger.warning("No .pf files found at %s", prefetch_path)
            return []

        results: list[PrefetchEntry] = []
        for pf in pf_files:
            try:
                entry = await asyncio.to_thread(self._parse_one, pf)
                results.append(entry)
                logger.info("Parsed prefetch: %s executable=%s run_count=%d",
                            pf.name, entry.executable_name, entry.run_count)
            except Exception as e:
                raise BackendError(f"Failed to parse {pf}: {type(e).__name__}: {e}") from e

        results.sort(key=lambda e: (e.executable_name.lower(), -(e.last_run_time_unix or 0)))
        return results

    @staticmethod
    def _parse_one(pf_path: Path):
        from ojuri.mcp_server.primitives.prefetch_entries import PrefetchEntry

        f = pyscca.file()
        try:
            f.open(str(pf_path))
            exec_name = f.executable_filename or ""
            run_count = f.run_count or 0

            last_dt = None
            last_unix = None
            try:
                last_dt = f.get_last_run_time(0)
                if last_dt is not None:
                    last_unix = int(last_dt.replace(tzinfo=timezone.utc).timestamp())
            except Exception:
                last_dt = None
                last_unix = None

            previous_runs: list[str] = []
            for i in range(1, 8):
                try:
                    t = f.get_last_run_time(i)
                    if t is not None:
                        previous_runs.append(t.replace(tzinfo=timezone.utc).isoformat())
                except Exception:
                    break

            loaded_files: list[str] = []
            n = f.number_of_filenames or 0
            for i in range(n):
                try:
                    name = f.get_filename(i)
                    if name:
                        loaded_files.append(name)
                except Exception:
                    continue

            volume_name = ""
            volume_serial = ""
            try:
                if (f.number_of_volumes or 0) > 0:
                    v = f.get_volume_information(0)
                    volume_name = getattr(v, "device_path", "") or ""
                    try:
                        sn = v.serial_number
                        volume_serial = f"{sn:08X}" if sn is not None else ""
                    except Exception:
                        volume_serial = ""
            except Exception:
                pass

            return PrefetchEntry(
                executable_name=exec_name,
                prefetch_filename=pf_path.name,
                run_count=run_count,
                last_run_time=last_dt.replace(tzinfo=timezone.utc).isoformat() if last_dt else "",
                last_run_time_unix=last_unix,
                previous_run_times=previous_runs,
                volume_name=volume_name,
                volume_serial=volume_serial,
                loaded_files=loaded_files,
                prefetch_source=str(pf_path),
            )
        finally:
            try:
                f.close()
            except Exception:
                pass
