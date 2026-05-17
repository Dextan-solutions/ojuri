#!/bin/bash
# Copies system prompts into Claude Code project config locations.
# Investigator prompt becomes .claude/CLAUDE.md; Auditor prompt is in .claude/agents/.

set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p .claude/agents
cp ojuri/agents/investigator/system_prompt.md .claude/CLAUDE.md
cp ojuri/agents/auditor/system_prompt.md .claude/agents/auditor.md

echo "Setup complete. Investigator prompt at .claude/CLAUDE.md"
echo "Auditor prompt at .claude/agents/auditor.md"
