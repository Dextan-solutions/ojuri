"""Unit tests for mft_timeline input validation. No subprocess."""

from __future__ import annotations

from pydantic import ValidationError

from ojuri.mcp_server.primitives.mft_timeline import GetMftTimelineInput


def test_valid_inputs_accepted() -> None:
    inp = GetMftTimelineInput(mft_path="/evidence/case_001/MFT", start_time="2024-01-01T00:00:00", end_time="2024-12-31T23:59:59", max_entries=500)
    assert inp.mft_path == "/evidence/case_001/MFT"
    assert inp.max_entries == 500


def test_path_with_shell_metachar_rejected() -> None:
    for bad in ["/x;rm -rf /", "/y|z", "/`evil`"]:
        try:
            GetMftTimelineInput(mft_path=bad)
        except ValidationError:
            continue
        raise AssertionError(f"expected reject for {bad!r}")


def test_dollar_sign_in_ntfs_name_accepted() -> None:
    inp = GetMftTimelineInput(mft_path="/evidence/rocba_test/$MFT")
    assert inp.mft_path == "/evidence/rocba_test/$MFT"


def test_command_substitution_rejected() -> None:
    try:
        GetMftTimelineInput(mft_path="/evidence/$(whoami)/file")
    except ValidationError:
        return
    raise AssertionError("expected reject for command substitution")


def test_parameter_expansion_rejected() -> None:
    try:
        GetMftTimelineInput(mft_path="/evidence/${HOME}/file")
    except ValidationError:
        return
    raise AssertionError("expected reject for parameter expansion")


def test_path_traversal_rejected() -> None:
    try:
        GetMftTimelineInput(mft_path="/evidence/../etc/passwd")
    except ValidationError:
        return
    raise AssertionError("expected reject for path traversal")


def test_max_entries_clamped() -> None:
    try:
        GetMftTimelineInput(mft_path="/x", max_entries=99999)
    except ValidationError:
        return
    raise AssertionError("expected reject for max_entries > 10000")


def test_min_max_entries() -> None:
    try:
        GetMftTimelineInput(mft_path="/x", max_entries=0)
    except ValidationError:
        return
    raise AssertionError("expected reject for max_entries=0")


def test_time_fields_optional() -> None:
    inp = GetMftTimelineInput(mft_path="/x")
    assert inp.start_time is None
    assert inp.end_time is None


if __name__ == "__main__":
    test_valid_inputs_accepted()
    test_path_with_shell_metachar_rejected()
    test_dollar_sign_in_ntfs_name_accepted()
    test_command_substitution_rejected()
    test_parameter_expansion_rejected()
    test_path_traversal_rejected()
    test_max_entries_clamped()
    test_min_max_entries()
    test_time_fields_optional()
    print("All MFT unit tests passed.")
