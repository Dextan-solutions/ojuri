# Ojuri

*(Yoruba: ojuri — literally "eye saw")*

**A forensically defensible AI agent for digital forensics and incident response.**

Built on the SIFT Workstation. Architected for portable enterprise deployment.

---

## Status

🚧 **Active development.** Submission target: SANS Protocol SIFT AI DFIR Challenge, 15 June 2026.

## The thesis

Every existing DFIR AI agent gives the language model direct access to a shell. The only thing preventing destructive actions is a prompt telling the model not to take them. When the model hallucinates — and they do — the guardrail evaporates.

Ojuri inverts the design. The agent is treated as untrusted: it can call only typed, read-only forensic primitives through a Model Context Protocol (MCP) server. Destructive commands are not in its vocabulary. Evidence is mounted read-only at the kernel level. Every operation is recorded in a hash-chained audit log that any reviewer can independently verify.

The result: an AI agent whose findings are defensible by construction, not by hope. The system does not narrate the analyst's intuition. It reports what the evidence shows.

## Architecture at a glance

See `docs/architecture/` for the full architecture document (v1.1, 51 pages, three parts). High level:

- **Reasoning layer (untrusted):** Investigator + Auditor agents running on Claude Code.
- **Capability layer (trust boundary):** Ojuri MCP server exposing typed forensic primitives.
- **Backend layer (swappable):** SIFT backend for the MVP; memory and cloud backends designed.
- **Evidence layer (read-only):** OS-enforced read-only mount, SHA-256 baselines, append-only hash-chained audit log.

## Compatible MCP clients

Ojuri implements the Model Context Protocol (MCP) standard and works with any MCP-compatible client. The server is platform-independent Python; only the SIFT backend requires SIFT Workstation tooling.

**Tested with:**
- Claude Code v2.1.138 on SIFT Workstation 2024.4

**Designed for compatibility with:**
- Claude Desktop (Anthropic)
- Cursor (IDE with MCP support)
- Cline (VS Code extension)
- Continue.dev (IDE extension)
- Any other MCP client implementing the standard

The `.mcp.json` file at the repository root provides a project-scoped registration that Claude Code reads automatically. Other clients have their own registration mechanisms; the server (`scripts/run_server.sh`) is the same regardless of client.

**Future backends in the architecture document (memory analysis via Volatility, cloud forensics via Microsoft Graph API and AWS CloudTrail) are specified but not yet implemented in this version. The architectural pattern allows them to be added without changing the server or the MCP interface.**

## Try it out

See `docs/try-it-out.md` for step-by-step setup on the SIFT Workstation.

## License

MIT. See `LICENSE`.

## Acknowledgements

Built on the foundation laid by the Protocol SIFT research team at SANS. The architectural shift to a typed capability boundary is exactly what the competition brief itself named as "the most sound architecture in the evaluation."
