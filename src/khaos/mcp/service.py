"""Model Context Protocol service scaffolding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable, Mapping

@dataclass(slots=True)
class MCPServiceDescriptor:
    """Describe the Khaos MCP endpoints exposed to hosts."""

    name: str
    version: str
    capabilities: Mapping[str, Any]
    transport: str = "stdio"

def build_mcp_routes() -> Iterable[dict[str, Any]]:
    """Return the route table expected by MCP hosts.

    This function intentionally returns static metadata for now. Runtime wiring
    will map these descriptors to actual coroutine handlers once the engine
    endpoints are implemented.
    """

    return [
        {
            "name": "khaos.runScenario",
            "description": "Execute a chaos scenario against a registered agent target.",
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "scenario": {"type": "string"},
                    "target": {"type": "string"},
                    "seed": {"type": "integer", "minimum": 0},
                },
                "required": ["scenario", "target"],
            },
        },
        {
            "name": "khaos.listMetrics",
            "description": "Enumerate metrics collected for the last executed scenario.",
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "runId": {"type": "string"},
                },
                "required": ["runId"],
            },
        },
    ]
