"""Abstract backend interface for Ojuri.

Concrete backends (SIFT, memory, cloud) implement this interface. The MCP server's
primitives are backend-agnostic; they call into whichever backend is registered at
startup via the factory function in this module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Import only for type hints; avoid runtime cycle with primitives module.
    from ojuri.mcp_server.primitives.registry_autostarts import AutostartEntry
    from ojuri.mcp_server.primitives.prefetch_entries import PrefetchEntry
    from ojuri.mcp_server.primitives.mft_timeline import MftEntry


class RegistryBackend(ABC):
    """Abstract registry-query interface. Every backend that supports registry
    queries (SIFT, memory image analysis, cloud audit logs adapted to registry-like
    shape) must implement these methods."""

    @abstractmethod
    async def get_registry_autostarts(
        self, software_hive_path: Path, system_hive_path: Path | None = None
    ) -> list["AutostartEntry"]:
        """Return all autostart entries from the given hive(s).

        Args:
            software_hive_path: path to the SOFTWARE hive (required; contains
                Run/RunOnceEx keys).
            system_hive_path: optional path to the SYSTEM hive (contains service
                auto-start config). If None, service autostarts are not included
                in the result.

        Returns:
            list of AutostartEntry, sorted by (mechanism, name) for determinism.

        Raises:
            FileNotFoundError if a required hive path does not exist.
            BackendError if the backend's tool invocation fails irrecoverably.
        """
        raise NotImplementedError


class BackendError(Exception):
    """Raised when a backend operation fails irrecoverably (tool missing, subprocess
    error, output unparseable). Distinct from validation errors which are raised by
    the primitive layer before the backend is even called."""


# Factory function — primitives import this and call it to get the active backend.
# Tests monkeypatch this function to inject mock backends.

_active_backend: RegistryBackend | None = None


def set_backend(backend: RegistryBackend) -> None:
    """Register a backend as the active one. Called at MCP server startup."""
    global _active_backend
    _active_backend = backend


def get_registry_backend() -> RegistryBackend:
    """Return the currently registered registry backend. Raises if none is set."""
    if _active_backend is None:
        raise BackendError(
            "No backend registered. Call set_backend() at server startup."
        )
    return _active_backend


# ---- Prefetch backend -----------------------------------------------------


class PrefetchBackend(ABC):
    """Abstract prefetch-query interface. Implementations parse Windows Prefetch
    (.pf) files and return typed PrefetchEntry records."""

    @abstractmethod
    async def get_prefetch_entries(self, prefetch_path: Path) -> list["PrefetchEntry"]:
        """Parse Prefetch files at prefetch_path.

        Args:
            prefetch_path: either a single .pf file OR a directory of .pf files.

        Returns:
            list of PrefetchEntry sorted by (executable_name, last_run_time desc).

        Raises:
            FileNotFoundError if prefetch_path does not exist.
            BackendError if parsing fails irrecoverably.
        """
        raise NotImplementedError


_active_prefetch_backend: PrefetchBackend | None = None


def set_prefetch_backend(backend: PrefetchBackend) -> None:
    global _active_prefetch_backend
    _active_prefetch_backend = backend


def get_prefetch_backend() -> PrefetchBackend:
    if _active_prefetch_backend is None:
        raise BackendError(
            "No prefetch backend registered. Call set_prefetch_backend() at server startup."
        )
    return _active_prefetch_backend


# ---- MFT backend ----------------------------------------------------------


class MftBackend(ABC):
    """Abstract MFT-query interface."""

    @abstractmethod
    async def get_mft_timeline(
        self,
        mft_path: Path,
        start_time: str | None,
        end_time: str | None,
        max_entries: int,
    ) -> list["MftEntry"]:
        """Parse an $MFT file and return entries within an optional time window.

        Args:
            mft_path: Path to the $MFT file.
            start_time: ISO-8601 UTC lower bound (inclusive). None = no lower bound.
            end_time: ISO-8601 UTC upper bound (inclusive). None = no upper bound.
            max_entries: Maximum entries to return (cap 10000).

        Returns:
            list of MftEntry, sorted by last_modified descending.

        Raises:
            FileNotFoundError if mft_path doesn't exist.
            BackendError on parse failure.
        """
        raise NotImplementedError


_active_mft_backend: MftBackend | None = None


def set_mft_backend(backend: MftBackend) -> None:
    global _active_mft_backend
    _active_mft_backend = backend


def get_mft_backend() -> MftBackend:
    if _active_mft_backend is None:
        raise BackendError("No MFT backend registered. Call set_mft_backend() at server startup.")
    return _active_mft_backend
