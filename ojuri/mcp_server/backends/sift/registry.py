"""SIFT backend implementation for registry queries.

Invokes RegRipper plugins via subprocess and parses their text output into typed
AutostartEntry records. Implements RegistryBackend from ojuri.mcp_server.backends.base.

Plugins covered in Week 2 Task 1: run, runonceex, svcdll.
Plugin paths and binary path are discovered at construction time, not hardcoded.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import time
from pathlib import Path

from ojuri.mcp_server.backends.base import BackendError, RegistryBackend
from ojuri.mcp_server.backends.sift.discovery import (
    find_plugins_dir,
    find_rip_pl,
    verify_plugins_available,
)

logger = logging.getLogger("ojuri.backends.sift.registry")

SUBPROCESS_TIMEOUT_SECONDS = 60
PLUGINS_FOR_AUTOSTARTS = ("run", "runonceex", "svcdll")
# Maps each plugin to the mechanism name to record in AutostartEntry.mechanism.
PLUGIN_MECHANISM = {
    "run": "Run",
    "runonceex": "RunOnceEx",
    "svcdll": "Service",
}


class SiftRegistryBackend(RegistryBackend):
    """RegRipper-based registry backend for SIFT Workstation."""

    def __init__(self) -> None:
        self.rip_path = find_rip_pl()
        self.plugins_dir = find_plugins_dir()
        verify_plugins_available(self.plugins_dir, list(PLUGINS_FOR_AUTOSTARTS))
        logger.info(
            "SiftRegistryBackend initialized. rip=%s plugins=%s",
            self.rip_path, self.plugins_dir,
        )

    async def get_registry_autostarts(
        self, software_hive_path: Path, system_hive_path: Path | None = None
    ) -> list:
        """Run the three autostart plugins against the appropriate hives and merge results."""
        # Lazy import to avoid circular reference at module load.
        from ojuri.mcp_server.primitives.registry_autostarts import AutostartEntry

        if not software_hive_path.is_file():
            raise FileNotFoundError(f"SOFTWARE hive not found: {software_hive_path}")

        results: list[AutostartEntry] = []

        # Run-related plugins target the SOFTWARE hive.
        for plugin in ("run", "runonceex"):
            raw = await self._run_plugin(plugin, software_hive_path)
            entries = self._parse_plugin_output(raw, plugin, software_hive_path)
            results.extend(entries)

        # svcdll plugin targets the SYSTEM hive if provided.
        if system_hive_path is not None:
            if not system_hive_path.is_file():
                raise FileNotFoundError(f"SYSTEM hive not found: {system_hive_path}")
            raw = await self._run_plugin("svcdll", system_hive_path)
            entries = self._parse_plugin_output(raw, "svcdll", system_hive_path)
            results.extend(entries)

        # Deterministic sort: by mechanism, then name.
        results.sort(key=lambda e: (e.mechanism, e.name.lower()))
        return results

    async def _run_plugin(self, plugin_name: str, hive_path: Path) -> str:
        """Invoke rip.pl with the named plugin against the named hive. Returns stdout text."""
        cmd = [str(self.rip_path), "-r", str(hive_path), "-p", plugin_name]
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=SUBPROCESS_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise BackendError(
                    f"rip.pl timed out after {SUBPROCESS_TIMEOUT_SECONDS}s: plugin={plugin_name} hive={hive_path}"
                )
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.info(
                "rip.pl invocation plugin=%s hive=%s duration_ms=%d exit_code=%d",
                plugin_name, hive_path, duration_ms, proc.returncode,
            )
            if proc.returncode != 0:
                raise BackendError(
                    f"rip.pl failed: plugin={plugin_name} returncode={proc.returncode} "
                    f"stderr={stderr.decode('utf-8', errors='replace')[:500]}"
                )
            return stdout.decode("utf-8", errors="replace")
        except FileNotFoundError as e:
            raise BackendError(f"rip.pl binary not found: {e}") from e

    def _parse_plugin_output(self, raw_output: str, plugin_name: str, hive_path: Path) -> list:
        """Parse RegRipper text output for a single plugin into AutostartEntry list.

        The format varies subtly between plugins. We use a tolerant approach: scan
        for lines that look like "name -> value" or "name : value" patterns under
        a registry-key header. Plugins emit a "LastWrite Time" line for each key;
        we capture that for last_modified.
        """
        from ojuri.mcp_server.primitives.registry_autostarts import AutostartEntry

        mechanism = PLUGIN_MECHANISM.get(plugin_name, plugin_name)
        entries: list[AutostartEntry] = []
        current_last_write: str | None = None

        # Heuristic line patterns. We deliberately accept variation.
        lastwrite_re = re.compile(r"LastWrite\s*Time\s*[:=]?\s*(.+)", re.IGNORECASE)
        # Name -> Value style entry (covers Run, RunOnceEx, svcdll outputs we've seen).
        # Captures: name (left of arrow), value (right of arrow).
        # Tolerates leading whitespace.
        entry_re = re.compile(r'^\s+(.+?)\s+-\s+"?(.+?)"?\s*$')

        for line in raw_output.splitlines():
            m = lastwrite_re.search(line)
            if m:
                current_last_write = m.group(1).strip()
                continue
            m = entry_re.match(line)
            if m:
                name = m.group(1).strip()
                value = m.group(2).strip()
                if name and value:
                    entries.append(AutostartEntry(
                        name=name,
                        path=value,
                        value=value,
                        last_modified=current_last_write or "",
                        hive_source=str(hive_path),
                        mechanism=mechanism,
                    ))
        return entries
