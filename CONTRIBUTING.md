# Contributing to Ojuri

## Status: closed for contributions until 15 June 2026

Ojuri is a solo submission to the SANS Protocol SIFT AI DFIR Challenge. Until the submission deadline of **15 June 2026**, external contributions cannot be accepted. Please do not open pull requests before that date.

## After the submission

Once the competition has closed, Ojuri will be open to contributions. The project welcomes:

- Additional backend implementations (e.g. memory, cloud) that conform to the typed primitive interface.
- New forensic primitives that extend the capability surface without breaking the read-only invariant.
- Spoliation tests that probe the integrity guarantees.
- Documentation and tutorials.

## Architectural ground rules

The Ojuri architecture rests on two non-negotiable patterns:

1. **Typed primitives, not shell access.** The agent must never receive a generic `run_command` tool. Every capability is a typed, validated, read-only MCP primitive.
2. **Swappable backends.** The MCP server defines an abstract backend interface; SIFT, memory, and cloud are concrete implementations. Contributions must preserve this separation.

Read `docs/architecture/` for the full design rationale before proposing changes.
