"""Ojuri MCP Server entry point.

This server exposes typed forensic primitives over the MCP stdio transport.
For Week 1 Task 2 it exposes a single primitive (hello_world) to prove the architecture.
Real primitives are added in Week 2.

Run with: python -m ojuri.mcp_server.server
Or via the launcher: scripts/run_server.sh
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from ojuri.mcp_server.primitives.hello_world import (
    HelloWorldInput,
    hello_world,
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
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    """Dispatch a tool call to the appropriate primitive."""
    logger.info("tool call: %s arguments=%s", name, arguments)

    if name == "get_hello_world":
        payload = HelloWorldInput(**arguments)
        result = await hello_world(payload)
        return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

    raise ValueError(f"Unknown tool: {name}")


async def main() -> None:
    """Run the server over stdio transport."""
    logger.info("Starting Ojuri MCP server %s v%s", SERVER_NAME, SERVER_VERSION)
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
