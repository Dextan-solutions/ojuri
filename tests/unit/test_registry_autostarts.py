"""Unit tests for registry_autostarts parser logic.

These tests feed canned text matching real RegRipper output format (name - "path")
to the parser and verify it produces the right AutostartEntry records.
No subprocess invocation; no fixture file required.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from ojuri.mcp_server.backends.sift.registry import SiftRegistryBackend
from ojuri.mcp_server.primitives.registry_autostarts import GetRegistryAutostartsInput


# Real RegRipper 'run' plugin output format, captured empirically.
CANNED_RUN_OUTPUT = """Launching run v.20200511
run v.20200511
(Software, NTUSER.DAT) [Autostart] Get autostart key contents from Software hive

Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time 2014-12-08 13:19:24Z
  TestApp1 - "C:\\Program Files\\TestApp\\app1.exe"
  TestApp2 - "C:\\Program Files\\TestApp\\app2.exe"
  UnquotedApp - C:\\Program Files\\Other\\other.exe
Software\\Microsoft\\Windows\\CurrentVersion\\Run has no subkeys.
"""

# Real RegRipper 'runonceex' format when key is absent.
CANNED_RUNONCEEX_EMPTY_OUTPUT = """Launching runonceex v.20200427
runonceex v.20200427
(Software) Gets contents of RunOnceEx values

RunOnceEx

Microsoft\\Windows\\CurrentVersion\\RunOnceEx not found.
"""


def test_parse_run_output_extracts_quoted_entries() -> None:
    backend = SiftRegistryBackend.__new__(SiftRegistryBackend)
    entries = backend._parse_plugin_output(
        CANNED_RUN_OUTPUT, "run", Path("/tmp/fake_hive")
    )
    # Expect 3 entries: TestApp1 (quoted), TestApp2 (quoted), UnquotedApp (unquoted).
    assert len(entries) == 3, f"expected 3 entries, got {len(entries)}: {[e.name for e in entries]}"
    names = {e.name for e in entries}
    assert names == {"TestApp1", "TestApp2", "UnquotedApp"}, f"got names: {names}"

    # Quoted path: quotes should be stripped from the captured path.
    testapp1 = next(e for e in entries if e.name == "TestApp1")
    assert testapp1.path == "C:\\Program Files\\TestApp\\app1.exe", f"got: {testapp1.path!r}"

    # Unquoted path: should be captured as-is.
    unquoted = next(e for e in entries if e.name == "UnquotedApp")
    assert unquoted.path == "C:\\Program Files\\Other\\other.exe", f"got: {unquoted.path!r}"

    # All have mechanism=Run and matching hive_source.
    for e in entries:
        assert e.mechanism == "Run", f"mechanism={e.mechanism}"
        assert e.hive_source == "/tmp/fake_hive"

    # LastWrite captured.
    assert testapp1.last_modified == "2014-12-08 13:19:24Z", f"got: {testapp1.last_modified!r}"


def test_parse_empty_runonceex_returns_no_entries() -> None:
    backend = SiftRegistryBackend.__new__(SiftRegistryBackend)
    entries = backend._parse_plugin_output(
        CANNED_RUNONCEEX_EMPTY_OUTPUT, "runonceex", Path("/tmp/fake_hive")
    )
    assert entries == [], f"expected no entries, got {entries}"


def test_parse_completely_empty_output() -> None:
    backend = SiftRegistryBackend.__new__(SiftRegistryBackend)
    entries = backend._parse_plugin_output("", "run", Path("/tmp/fake_hive"))
    assert entries == []


def test_dollar_sign_in_ntfs_name_accepted() -> None:
    inp = GetRegistryAutostartsInput(software_hive_path="/evidence/rocba_test/$MFT")
    assert inp.software_hive_path == "/evidence/rocba_test/$MFT"


def test_command_substitution_rejected() -> None:
    try:
        GetRegistryAutostartsInput(software_hive_path="/evidence/$(whoami)/SOFTWARE")
    except ValidationError:
        return
    raise AssertionError("expected reject for command substitution")


def test_parameter_expansion_rejected() -> None:
    try:
        GetRegistryAutostartsInput(software_hive_path="/evidence/${HOME}/SOFTWARE")
    except ValidationError:
        return
    raise AssertionError("expected reject for parameter expansion")


if __name__ == "__main__":
    test_parse_run_output_extracts_quoted_entries()
    test_parse_empty_runonceex_returns_no_entries()
    test_parse_completely_empty_output()
    test_dollar_sign_in_ntfs_name_accepted()
    test_command_substitution_rejected()
    test_parameter_expansion_rejected()
    print("All unit tests passed.")
