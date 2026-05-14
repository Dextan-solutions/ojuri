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

## Try it out

See `docs/try-it-out.md` for step-by-step setup on the SIFT Workstation.

## License

MIT. See `LICENSE`.

## Acknowledgements

Built on the foundation laid by the Protocol SIFT research team at SANS. The architectural shift to a typed capability boundary is exactly what the competition brief itself named as "the most sound architecture in the evaluation."
