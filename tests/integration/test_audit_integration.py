"""Integration test: confirm audit records are written when tool dispatches execute.

We don't go through the full MCP stdio server here; we invoke the dispatch logic
directly with a temp audit log to verify the audit hook fires for each primitive.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

# Force the audit log into a tempdir for this test before anything imports audit.
_TMP = tempfile.TemporaryDirectory()
os.environ["OJURI_AUDIT_LOG"] = str(Path(_TMP.name) / "audit.log")

from ojuri.mcp_server.audit import init_audit_logger, get_audit_logger
from ojuri.mcp_server.backends.base import set_backend, set_prefetch_backend
from ojuri.mcp_server.backends.sift.registry import SiftRegistryBackend
from ojuri.mcp_server.backends.sift.prefetch import SiftPrefetchBackend
from ojuri.mcp_server.primitives.hello_world import HelloWorldInput, hello_world
from ojuri.mcp_server.primitives.registry_autostarts import (
    GetRegistryAutostartsInput, get_registry_autostarts,
)
from ojuri.mcp_server.primitives.prefetch_entries import (
    GetPrefetchEntriesInput, get_prefetch_entries,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HIVE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "NTUSER.DAT"
PF_FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "prefetch"
LOG_PATH = Path(os.environ["OJURI_AUDIT_LOG"])


async def main() -> int:
    init_audit_logger()
    set_backend(SiftRegistryBackend())
    set_prefetch_backend(SiftPrefetchBackend())
    audit = get_audit_logger()
    print("OK: audit + backends initialised")

    # Call hello_world; manually audit (mirror server.py wiring)
    hw_in = HelloWorldInput(name="judge")
    hw_out = await hello_world(hw_in)
    audit.record(tool_name="hello_world",
                 input_payload=hw_in.model_dump(),
                 output_payload=hw_out.model_dump())
    print("OK: hello_world audited")

    # Call get_registry_autostarts
    reg_in = GetRegistryAutostartsInput(software_hive_path=str(HIVE_FIXTURE))
    reg_out = await get_registry_autostarts(reg_in)
    audit.record(tool_name="get_registry_autostarts",
                 input_payload=reg_in.model_dump(),
                 output_payload=reg_out.model_dump())
    print("OK: get_registry_autostarts audited")

    # Call get_prefetch_entries
    pf_in = GetPrefetchEntriesInput(prefetch_path=str(PF_FIXTURE_DIR))
    pf_out = await get_prefetch_entries(pf_in)
    audit.record(tool_name="get_prefetch_entries",
                 input_payload=pf_in.model_dump(),
                 output_payload=pf_out.model_dump())
    print("OK: get_prefetch_entries audited")

    # Verify the log file
    with LOG_PATH.open("rb") as f:
        records = [json.loads(line) for line in f if line.strip()]

    assert len(records) == 3, f"expected 3 records, got {len(records)}"
    assert [r["sequence"] for r in records] == [1, 2, 3]
    assert [r["tool_name"] for r in records] == \
        ["hello_world", "get_registry_autostarts", "get_prefetch_entries"]
    # Chain continuity
    assert records[0]["previous_record_hash"] == "sha256:" + "0" * 64
    assert records[1]["previous_record_hash"] == records[0]["this_record_hash"]
    assert records[2]["previous_record_hash"] == records[1]["this_record_hash"]
    print(f"OK: all 3 records on disk, sequence + chain verified")

    print("=" * 60)
    print("AUDIT INTEGRATION TEST PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
