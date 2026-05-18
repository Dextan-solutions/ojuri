"""Unit tests for get_user_autostarts input validation, schemas, and parser.

No subprocess invocation; no fixture file required. The input validator
mirrors get_registry_autostarts (including the '$' NTFS-name fix); the parser
adds Run-vs-RunOnce mechanism splitting from the RegRipper key header.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ojuri.mcp_server.backends.sift.registry import SiftRegistryBackend
from ojuri.mcp_server.primitives.user_autostarts import (
    GetUserAutostartsInput,
    UserAutostartEntry,
)

NTUSER_PATH = "/evidence/rocba_test/Users/fredr/NTUSER.DAT"

# Real RegRipper 'run' plugin output: an NTUSER.DAT has Run and RunOnce keys
# under HKCU\Software\Microsoft\Windows\CurrentVersion.
CANNED_RUN_OUTPUT = """Launching run v.20200511
run v.20200511
(Software, NTUSER.DAT) [Autostart] Get autostart key contents from Software hive

Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time 2014-12-08 13:19:24Z
  OneDrive - "C:\\Users\\fredr\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
  Updater - C:\\Users\\fredr\\evil.exe
Software\\Microsoft\\Windows\\CurrentVersion\\Run has no subkeys.

Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
LastWrite Time 2015-01-02 09:00:00Z
  CleanupTask - "C:\\Windows\\Temp\\cleanup.exe"
Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce has no subkeys.
"""


# ---- Input validation -----------------------------------------------------


def test_valid_path_accepted() -> None:
    inp = GetUserAutostartsInput(ntuser_hive_path=NTUSER_PATH)
    assert inp.ntuser_hive_path == NTUSER_PATH


def test_shell_metachar_rejected() -> None:
    with pytest.raises(ValidationError):
        GetUserAutostartsInput(ntuser_hive_path="/evidence/x; rm -rf //NTUSER.DAT")


def test_dollar_sign_in_ntfs_name_accepted() -> None:
    # '$' is a legitimate NTFS metadata-file naming convention; the same fix
    # applied to the other primitives must apply here.
    inp = GetUserAutostartsInput(ntuser_hive_path="/evidence/rocba_test/$Extend/NTUSER.DAT")
    assert inp.ntuser_hive_path == "/evidence/rocba_test/$Extend/NTUSER.DAT"


def test_command_substitution_rejected() -> None:
    with pytest.raises(ValidationError):
        GetUserAutostartsInput(ntuser_hive_path="/evidence/$(whoami)/NTUSER.DAT")


def test_parameter_expansion_rejected() -> None:
    with pytest.raises(ValidationError):
        GetUserAutostartsInput(ntuser_hive_path="/evidence/${HOME}/NTUSER.DAT")


def test_path_traversal_rejected() -> None:
    with pytest.raises(ValidationError):
        GetUserAutostartsInput(ntuser_hive_path="/evidence/../../etc/NTUSER.DAT")


# ---- Schemas --------------------------------------------------------------


def test_schema_userautostartentry_required_fields() -> None:
    entry = UserAutostartEntry(
        name="OneDrive",
        path="C:\\OneDrive.exe",
        mechanism="Run",
        hive_source=NTUSER_PATH,
    )
    # last_modified and username are optional and default to None.
    assert entry.last_modified is None
    assert entry.username is None
    # name, path, mechanism, hive_source are required.
    with pytest.raises(ValidationError):
        UserAutostartEntry(path="x", mechanism="Run", hive_source=NTUSER_PATH)
    with pytest.raises(ValidationError):
        UserAutostartEntry(name="x", path="y", hive_source=NTUSER_PATH)


def test_mechanism_literal_constrained() -> None:
    for mech in ("Run", "RunOnce", "RunOnceEx"):
        UserAutostartEntry(name="n", path="p", mechanism=mech, hive_source="h")
    with pytest.raises(ValidationError):
        UserAutostartEntry(name="n", path="p", mechanism="Service", hive_source="h")


# ---- Parser ---------------------------------------------------------------


def test_parser_splits_run_and_runonce() -> None:
    backend = SiftRegistryBackend.__new__(SiftRegistryBackend)
    entries = backend._parse_user_plugin_output(
        CANNED_RUN_OUTPUT, "run", Path(NTUSER_PATH), "fredr"
    )
    by_name = {e.name: e for e in entries}
    assert set(by_name) == {"OneDrive", "Updater", "CleanupTask"}
    assert by_name["OneDrive"].mechanism == "Run"
    assert by_name["Updater"].mechanism == "Run"
    assert by_name["CleanupTask"].mechanism == "RunOnce"
    assert by_name["OneDrive"].last_modified == "2014-12-08 13:19:24Z"
    assert by_name["CleanupTask"].last_modified == "2015-01-02 09:00:00Z"
    for e in entries:
        assert e.username == "fredr"
        assert e.hive_source == NTUSER_PATH


def test_parser_runonceex_plugin_is_runonceex() -> None:
    backend = SiftRegistryBackend.__new__(SiftRegistryBackend)
    raw = (
        "Launching runonceex v.20200427\n"
        "RunOnceEx\n"
        "LastWrite Time 2015-03-03 03:03:03Z\n"
        '  0001 - "C:\\Windows\\Temp\\stage.dll"\n'
    )
    entries = backend._parse_user_plugin_output(
        raw, "runonceex", Path(NTUSER_PATH), "fredr"
    )
    assert len(entries) == 1
    assert entries[0].mechanism == "RunOnceEx"
    assert entries[0].name == "0001"


def test_parser_empty_output_returns_nothing() -> None:
    backend = SiftRegistryBackend.__new__(SiftRegistryBackend)
    assert backend._parse_user_plugin_output("", "run", Path(NTUSER_PATH), "fredr") == []


if __name__ == "__main__":
    test_valid_path_accepted()
    test_shell_metachar_rejected()
    test_dollar_sign_in_ntfs_name_accepted()
    test_command_substitution_rejected()
    test_parameter_expansion_rejected()
    test_path_traversal_rejected()
    test_schema_userautostartentry_required_fields()
    test_mechanism_literal_constrained()
    test_parser_splits_run_and_runonce()
    test_parser_runonceex_plugin_is_runonceex()
    test_parser_empty_output_returns_nothing()
    print("All unit tests passed.")
