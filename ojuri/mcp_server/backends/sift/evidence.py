"""SIFT backend implementation for evidence discovery.

Pure-Python, read-only filesystem walk of a mounted evidence root. No
subprocess, no external tool. Implements EvidenceDiscoveryBackend from
ojuri.mcp_server.backends.base.

Backend strategy D: pure-Python filesystem walk (the fourth pattern, in
addition to subprocess+regex, direct library, subprocess+CSV).

Tolerant of partial results: a per-artefact OSError skips that artefact (and
is logged) without aborting the whole discovery — real evidence mounts surface
EINVAL/EACCES on WOF reparse points and protected directories.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ojuri.mcp_server.backends.base import EvidenceDiscoveryBackend

logger = logging.getLogger("ojuri.backends.sift.evidence")

# Profile directories that are not real interactive users.
_SKIP_PROFILES = {"Default", "Default User", "Public", "All Users"}

# Canonical system hives, in deterministic order.
_SYSTEM_HIVES = ("SOFTWARE", "SYSTEM", "SECURITY", "SAM", "DEFAULT")


class SiftEvidenceDiscoveryBackend(EvidenceDiscoveryBackend):
    """Filesystem-walk evidence-discovery backend for SIFT Workstation."""

    async def list_evidence_artefacts(self, evidence_root: Path):
        # Lazy import to avoid a circular reference at module load.
        from ojuri.mcp_server.primitives.list_evidence_artefacts import (
            DiscoveredEvidence,
            SystemHive,
            UserProfile,
        )

        if not evidence_root.exists():
            raise FileNotFoundError(f"evidence_root not found: {evidence_root}")
        if not evidence_root.is_dir():
            raise NotADirectoryError(
                f"evidence_root is not a directory: {evidence_root}"
            )

        user_profiles = self._discover_user_profiles(evidence_root, UserProfile)
        system_hives = self._discover_system_hives(evidence_root, SystemHive)
        prefetch_directories = self._discover_prefetch_dirs(evidence_root)
        mft_files = self._discover_mft_files(evidence_root)

        return DiscoveredEvidence(
            evidence_root=str(evidence_root),
            user_profiles=user_profiles,
            system_hives=system_hives,
            prefetch_directories=prefetch_directories,
            mft_files=mft_files,
            summary={
                "users": len(user_profiles),
                "system_hives": len(system_hives),
                "prefetch_directories": len(prefetch_directories),
                "mft_files": len(mft_files),
            },
        )

    # -- user profiles ------------------------------------------------------
    def _discover_user_profiles(self, root: Path, UserProfile) -> list:
        users_dir = root / "Users"
        profiles: list = []
        try:
            entries = sorted(os.listdir(users_dir))
        except OSError as e:
            logger.warning("cannot list Users/ under %s: %s", root, e)
            return profiles

        for name in entries:
            if name in _SKIP_PROFILES:
                continue
            profile_path = users_dir / name
            try:
                if not profile_path.is_dir():
                    continue
            except OSError as e:
                logger.warning("skipping profile %s: %s", profile_path, e)
                continue

            ntuser = profile_path / "NTUSER.DAT"
            usrclass = (
                profile_path
                / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
            )

            ntuser_dat: str | None = None
            try:
                if os.path.isfile(ntuser):
                    ntuser_dat = str(ntuser)
            except OSError as e:
                logger.warning("NTUSER.DAT unreadable for %s: %s", name, e)

            usrclass_dat: str | None = None
            try:
                if os.path.isfile(usrclass):
                    usrclass_dat = str(usrclass)
            except OSError as e:
                logger.warning("UsrClass.dat unreadable for %s: %s", name, e)

            profiles.append(
                UserProfile(
                    username=name,
                    profile_path=str(profile_path),
                    ntuser_dat=ntuser_dat,
                    usrclass_dat=usrclass_dat,
                )
            )
        return profiles

    # -- system hives -------------------------------------------------------
    def _discover_system_hives(self, root: Path, SystemHive) -> list:
        config_dir = root / "Windows" / "System32" / "config"
        hives: list = []
        for hive_name in _SYSTEM_HIVES:
            hive_path = config_dir / hive_name
            try:
                if not os.path.isfile(hive_path):
                    continue
                size_bytes = os.lstat(hive_path).st_size
            except OSError as e:
                logger.warning("system hive %s unreadable: %s", hive_path, e)
                continue
            hives.append(
                SystemHive(
                    name=hive_name,
                    path=str(hive_path),
                    size_bytes=size_bytes,
                )
            )
        return hives

    # -- prefetch -----------------------------------------------------------
    def _discover_prefetch_dirs(self, root: Path) -> list[str]:
        prefetch_dir = root / "Windows" / "Prefetch"
        try:
            if not prefetch_dir.is_dir():
                return []
            has_pf = any(
                entry.lower().endswith(".pf")
                for entry in os.listdir(prefetch_dir)
            )
        except OSError as e:
            logger.warning("Prefetch dir unreadable under %s: %s", root, e)
            return []
        return [str(prefetch_dir)] if has_pf else []

    # -- $MFT ---------------------------------------------------------------
    def _discover_mft_files(self, root: Path) -> list[str]:
        mft_path = root / "$MFT"
        try:
            if os.path.isfile(mft_path):
                return [str(mft_path)]
        except OSError as e:
            logger.warning("$MFT unreadable under %s: %s", root, e)
        return []
