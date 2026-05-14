#!/usr/bin/env bash
# Ojuri MCP Server launcher. Activates the venv and starts the server over stdio.
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
exec python -m ojuri.mcp_server.server
