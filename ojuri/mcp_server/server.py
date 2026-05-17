"""Ojuri MCP Server entry point.

This server exposes typed forensic primitives over the MCP stdio transport.
For Week 1: hello_world. Week 2: get_registry_autostarts and more.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from ojuri.mcp_server.audit import init_audit_logger, get_audit_logger
from ojuri.mcp_server.backends.base import (
    set_backend,
    set_prefetch_backend,
    set_mft_backend,
)
from ojuri.mcp_server.backends.sift.registry import SiftRegistryBackend
from ojuri.mcp_server.backends.sift.prefetch import SiftPrefetchBackend
from ojuri.mcp_server.backends.sift.mft import SiftMftBackend
from ojuri.mcp_server.primitives.hello_world import (
    HelloWorldInput,
    hello_world,
)
from ojuri.mcp_server.primitives.registry_autostarts import (
    GetRegistryAutostartsInput,
    get_registry_autostarts,
)
from ojuri.mcp_server.primitives.prefetch_entries import (
    GetPrefetchEntriesInput,
    get_prefetch_entries,
)
from ojuri.mcp_server.primitives.mft_timeline import (
    GetMftTimelineInput,
    get_mft_timeline,
)

logger = logging.getLogger("ojuri.mcp_server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

SERVER_NAME = "ojuri"
SERVER_VERSION = "0.1.0"

app = Server(SERVER_NAME)


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    """Declare which primitives this server exposes."""
    return [
        types.Tool(
            name="get_hello_world",
            description=(
                "Returns a typed greeting. Stand-in for real forensic primitives; "
                "used to verify the MCP server is reachable and functioning."
            ),
            inputSchema=HelloWorldInput.model_json_schema(),
        ),
        types.Tool(
            name="get_registry_autostarts",
            description=(
                "Returns all autostart entries from the Windows registry, covering Run keys, "
                "RunOnceEx, and Service DLL autostarts. Used to detect malware persistence. "
                "Requires the path to a SOFTWARE hive; optionally a SYSTEM hive for service autostarts. "
                "Returns one record per autostart entry with the program path, mechanism type, "
                "hive source, and the LastWrite time of the registry key."
            ),
            inputSchema=GetRegistryAutostartsInput.model_json_schema(),
        ),
        types.Tool(
            name="get_prefetch_entries",
            description=(
                "Returns Windows Prefetch entries showing what programs ran on the system, "
                "when, how often, and what files they touched. Input is either a path to a "
                "single .pf file or a directory containing .pf files (typically C:\\\\Windows\\\\Prefetch). "
                "Each entry includes the executable name, run count, up to 8 execution timestamps, "
                "the volume the executable ran from, and the list of files the prefetcher recorded."
            ),
            inputSchema=GetPrefetchEntriesInput.model_json_schema(),
        ),
        types.Tool(
            name="get_mft_timeline",
            description=(
                "Returns NTFS filesystem timeline entries from a parsed $MFT file. "
                "Each entry includes file/directory name, parent path, size, all "
                "MAC(b) timestamps from Standard Information, and ADS flags. "
                "Use optional start_time and end_time (ISO-8601 UTC) to narrow to a "
                "window of interest. Results sorted by LastModified descending; "
                "max_entries caps result count (default 1000, max 10000)."
            ),
            inputSchema=GetMftTimelineInput.model_json_schema(),
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    """Dispatch a tool call to the appropriate primitive."""
    logger.info("tool call: %s arguments=%s", name, arguments)

    if name == "get_hello_world":
        payload = HelloWorldInput(**arguments)
        result = await hello_world(payload)
        get_audit_logger().record(
            tool_name="get_hello_world",
            input_payload=payload.model_dump(),
            output_payload=result.model_dump(),
        )
        return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

    if name == "get_registry_autostarts":
        payload = GetRegistryAutostartsInput(**arguments)
        result = await get_registry_autostarts(payload)
        get_audit_logger().record(
            tool_name="get_registry_autostarts",
            input_payload=payload.model_dump(),
            output_payload=result.model_dump(),
        )
        return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

    if name == "get_prefetch_entries":
        payload = GetPrefetchEntriesInput(**arguments)
        result = await get_prefetch_entries(payload)
        get_audit_logger().record(
            tool_name="get_prefetch_entries",
            input_payload=payload.model_dump(),
            output_payload=result.model_dump(),
        )
        return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

    if name == "get_mft_timeline":
        payload = GetMftTimelineInput(**arguments)
        result = await get_mft_timeline(payload)
        get_audit_logger().record(
            tool_name="get_mft_timeline",
            input_payload=payload.model_dump(),
            output_payload=result.model_dump(),
        )
        return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

    raise ValueError(f"Unknown tool: {name}")


async def main() -> None:
    """Run the server over stdio transport. Initialize backends before serving."""
    logger.info("Starting Ojuri MCP server %s v%s", SERVER_NAME, SERVER_VERSION)
    # Initialize the SIFT backend and register it as the active one.
    set_backend(SiftRegistryBackend())
    logger.info("SIFT backend registered.")
    set_prefetch_backend(SiftPrefetchBackend())
    logger.info("SIFT prefetch backend registered.")
    set_mft_backend(SiftMftBackend())
    logger.info("SIFT MFT backend registered.")
    init_audit_logger()
    logger.info("Audit logger initialised.")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
