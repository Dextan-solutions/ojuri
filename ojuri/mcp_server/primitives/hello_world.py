"""Hello-world primitive — a stand-in for real forensic primitives.

This file establishes the architectural pattern every future primitive will follow:
- Strict Pydantic input model with field validation
- Strict Pydantic output model with documented fields
- A pure async function that takes the typed input and returns the typed output
- No shell access, no arbitrary file I/O, no network — read-only by construction

Real primitives (get_registry_autostarts, get_mft_timeline, etc.) replace this in Week 2.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class HelloWorldInput(BaseModel):
    """Input to the hello_world primitive. Demonstrates typed input validation."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Name to greet. Must be 1-64 characters; alphanumerics, spaces, hyphens, and underscores only.",
    )

    @field_validator("name")
    @classmethod
    def name_must_be_safe(cls, v: str) -> str:
        # Whitelist: alphanumerics, spaces, hyphens, underscores only.
        # This is the same defensive pattern we will use on every primitive input.
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_")
        if not all(c in allowed for c in v):
            raise ValueError(
                "name contains disallowed characters; allowed: a-z A-Z 0-9 space hyphen underscore"
            )
        return v


class HelloWorldOutput(BaseModel):
    """Output of the hello_world primitive. Demonstrates typed output structure."""

    greeting: str = Field(..., description="The greeting message.")
    primitive_name: Literal["hello_world"] = Field(
        "hello_world",
        description="Identifies the primitive that produced this response. Real primitives will use this for audit-log correlation.",
    )
    timestamp_utc: str = Field(
        ...,
        description="ISO-8601 UTC timestamp of when the primitive was invoked.",
    )


async def hello_world(payload: HelloWorldInput) -> HelloWorldOutput:
    """Return a typed greeting. Pure function — no side effects, no I/O."""
    return HelloWorldOutput(
        greeting=f"Hello, {payload.name}. The Ojuri MCP server is alive.",
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
    )
