"""SIFT backend tool discovery.

Locates the RegRipper installation and plugins directory on the host. Falls back
across known candidate paths rather than hardcoding. Called at backend init time.
"""

from __future__ import annotations

import shutil
from pathlib import Path

CANDIDATE_PLUGIN_DIRS = (
    Path("/usr/local/src/regripper/plugins"),
    Path("/usr/lib/regripper/plugins"),
    Path("/opt/regripper/plugins"),
    Path("/usr/share/regripper/plugins"),
)


def find_rip_pl() -> Path:
    """Locate the rip.pl binary. Checks PATH first, then known absolute locations."""
    on_path = shutil.which("rip.pl")
    if on_path:
        return Path(on_path)
    for candidate in (
        Path("/usr/local/bin/rip.pl"),
        Path("/usr/local/src/regripper/rip.pl"),
        Path("/usr/bin/rip.pl"),
    ):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "rip.pl not found in PATH or any known location. Install RegRipper."
    )


def find_plugins_dir() -> Path:
    """Locate the RegRipper plugins directory by checking candidate paths."""
    for candidate in CANDIDATE_PLUGIN_DIRS:
        if candidate.is_dir() and (candidate / "run.pl").is_file():
            return candidate
    raise FileNotFoundError(
        f"RegRipper plugins directory not found. Searched: "
        f"{[str(p) for p in CANDIDATE_PLUGIN_DIRS]}"
    )


def verify_plugins_available(plugins_dir: Path, plugin_names: list[str]) -> None:
    """Confirm specific plugin files exist in the plugins directory. Raises if any missing."""
    missing = []
    for name in plugin_names:
        candidate = plugins_dir / f"{name}.pl"
        if not candidate.is_file():
            missing.append(name)
    if missing:
        raise FileNotFoundError(
            f"Required RegRipper plugins missing from {plugins_dir}: {missing}"
        )
