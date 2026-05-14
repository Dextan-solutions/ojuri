"""Smoke test: start the MCP server as a subprocess, call get_hello_world, verify the response.

This is the proof-of-life test for the Week 1 Task 2 milestone. If this passes,
the MCP server is wired correctly end-to-end and ready to accept real primitives.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parents[2]


async def run_smoke_test() -> int:
    """Connect to the Ojuri MCP server, call get_hello_world, validate the response.

    Returns 0 on success, 1 on failure. Prints PASS / FAIL to stdout for the human reader.
    """
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ojuri.mcp_server.server"],
        cwd=str(REPO_ROOT),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            assert "get_hello_world" in tool_names, f"get_hello_world not in {tool_names}"
            print("OK: get_hello_world is exposed")

            # 2. Call the tool with a known input
            result = await session.call_tool(
                "get_hello_world", {"name": "judge"}
            )
            assert result.content, "result.content is empty"
            text_block = result.content[0]
            assert hasattr(text_block, "text"), "no text in result"
            payload = json.loads(text_block.text)
            assert payload["greeting"] == "Hello, judge. The Ojuri MCP server is alive.", (
                f"unexpected greeting: {payload['greeting']}"
            )
            assert payload["primitive_name"] == "hello_world"
            assert "timestamp_utc" in payload and payload["timestamp_utc"]
            print(f"OK: response = {payload}")

            # 3. Verify input validation rejects malformed input.
            # MCP reports tool execution errors in-band via CallToolResult.isError=True
            # rather than raising client-side, so we inspect the result instead of
            # wrapping in try/except.
            err_result = await session.call_tool(
                "get_hello_world", {"name": "evil; rm -rf"}
            )
            if not getattr(err_result, "isError", False):
                print("FAIL: malformed input was not flagged as error")
                return 1
            err_text = err_result.content[0].text if err_result.content else ""
            err_lower = err_text.lower()
            if not any(
                marker in err_lower
                for marker in ("validation", "disallowed characters", "validationerror")
            ):
                print("FAIL: error message does not indicate validation failure")
                print(f"actual error text: {err_text}")
                return 1
            excerpt = err_text.replace("\n", " ")[:200]
            print(f"OK: malformed input correctly rejected with validation error — {excerpt}")

    print("=" * 60)
    print("SMOKE TEST PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_smoke_test()))
