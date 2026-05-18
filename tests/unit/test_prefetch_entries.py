"""Unit tests for prefetch_entries input validation. No file I/O."""

from __future__ import annotations

import asyncio

from pydantic import ValidationError

from ojuri.mcp_server.backends.sift.prefetch import SiftPrefetchBackend
from ojuri.mcp_server.primitives.prefetch_entries import (
    GetPrefetchEntriesInput,
    PrefetchEntry,
)


def test_valid_path_accepted() -> None:
    inp = GetPrefetchEntriesInput(prefetch_path="/evidence/case_001/Prefetch")
    assert inp.prefetch_path == "/evidence/case_001/Prefetch"


def test_shell_metachar_rejected() -> None:
    for bad in ["/evidence/x;rm -rf", "/x|y", "/x`z", "/x$(y)"]:
        try:
            GetPrefetchEntriesInput(prefetch_path=bad)
        except ValidationError:
            continue
        raise AssertionError(f"expected rejection for {bad!r}")


def test_dollar_sign_in_ntfs_name_accepted() -> None:
    inp = GetPrefetchEntriesInput(prefetch_path="/evidence/rocba_test/$MFT")
    assert inp.prefetch_path == "/evidence/rocba_test/$MFT"


def test_command_substitution_rejected() -> None:
    try:
        GetPrefetchEntriesInput(prefetch_path="/evidence/$(whoami)/file")
    except ValidationError:
        return
    raise AssertionError("expected reject for command substitution")


def test_parameter_expansion_rejected() -> None:
    try:
        GetPrefetchEntriesInput(prefetch_path="/evidence/${HOME}/file")
    except ValidationError:
        return
    raise AssertionError("expected reject for parameter expansion")


def test_path_traversal_rejected() -> None:
    try:
        GetPrefetchEntriesInput(prefetch_path="/evidence/../etc/passwd")
    except ValidationError:
        return
    raise AssertionError("expected rejection for path traversal")


def test_skipped_pf_recorded_not_raised(tmp_path, monkeypatch) -> None:
    """A libscca failure on one .pf must be recorded in `skipped` while the
    remaining files still parse — the whole sweep must not abort."""
    good = tmp_path / "GOOD.EXE-AAAAAAAA.pf"
    bad = tmp_path / "MOUSOCOREWORKER.EXE-4429AC2B.pf"
    good.write_bytes(b"\x00")
    bad.write_bytes(b"\x00")

    def fake_parse_one(pf_path):
        if pf_path.name == bad.name:
            # Mirrors what pyscca raises on an unsupported signature.
            raise OSError(
                "pyscca_file_open: ... libscca_io_handle_read_compressed_file_"
                "header: unsupported signature."
            )
        return PrefetchEntry(
            executable_name="GOOD.EXE",
            prefetch_filename=pf_path.name,
            run_count=1,
            prefetch_source=str(pf_path),
        )

    monkeypatch.setattr(SiftPrefetchBackend, "_parse_one",
                         staticmethod(fake_parse_one))

    backend = SiftPrefetchBackend()
    entries, skipped = asyncio.run(backend.get_prefetch_entries(tmp_path))

    assert len(entries) == 1, "the good .pf must still parse"
    assert entries[0].prefetch_filename == good.name
    assert len(skipped) == 1, "the bad .pf must be recorded, not raised"
    s = skipped[0]
    assert s.filename == bad.name
    assert s.error_class == "OSError"
    assert "unsupported signature" in s.message


if __name__ == "__main__":
    test_valid_path_accepted()
    test_shell_metachar_rejected()
    test_dollar_sign_in_ntfs_name_accepted()
    test_command_substitution_rejected()
    test_parameter_expansion_rejected()
    test_path_traversal_rejected()
    print("All unit tests passed.")
