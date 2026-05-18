"""Unit tests for prefetch_entries input validation. No file I/O."""

from __future__ import annotations

from pydantic import ValidationError

from ojuri.mcp_server.primitives.prefetch_entries import GetPrefetchEntriesInput


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


if __name__ == "__main__":
    test_valid_path_accepted()
    test_shell_metachar_rejected()
    test_dollar_sign_in_ntfs_name_accepted()
    test_command_substitution_rejected()
    test_parameter_expansion_rejected()
    test_path_traversal_rejected()
    print("All unit tests passed.")
