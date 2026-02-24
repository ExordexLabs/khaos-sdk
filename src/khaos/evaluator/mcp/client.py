"""MCP client harness for security testing.

Wraps the official ``mcp`` Python SDK's ClientSession to provide a
uniform interface for connecting to MCP servers via stdio, SSE, or
streamable-HTTP transports.

Usage::

    spec = parse_server_spec("npx @modelcontextprotocol/server-filesystem /tmp")
    async with MCPTestClient() as client:
        await client.connect(spec)
        tools = await client.list_tools()
        result = await client.call_tool("read_file", {"path": "/tmp/test.txt"})
"""

from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.sse import sse_client
from mcp.types import (
    CallToolResult,
    ListResourcesResult,
    ListToolsResult,
    ReadResourceResult,
    Resource,
    Tool,
)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class MCPServerSpec:
    """Specification for connecting to an MCP server."""

    name: str
    transport: Literal["stdio", "sse", "streamable-http"] = "stdio"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    env: dict[str, str] | None = None


@dataclass(slots=True)
class ToolInfo:
    """Simplified tool metadata extracted from an MCP server."""

    name: str
    description: str | None
    input_schema: dict[str, Any]


@dataclass(slots=True)
class ResourceInfo:
    """Simplified resource metadata extracted from an MCP server."""

    uri: str
    name: str | None
    description: str | None
    mime_type: str | None


@dataclass(slots=True)
class ToolResult:
    """Simplified result from calling an MCP tool."""

    content: list[dict[str, Any]]
    is_error: bool


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class MCPTestClient:
    """Async context-manager that talks MCP to a target server.

    Supports stdio (subprocess), SSE, and streamable-HTTP transports.
    """

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._cleanup: Any = None  # context manager exit handle
        self._transport_ctx: Any = None

    async def __aenter__(self) -> MCPTestClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # -- connection ---------------------------------------------------------

    async def connect(self, spec: MCPServerSpec) -> None:
        """Establish a connection to the MCP server described by *spec*."""
        if spec.transport == "stdio":
            await self._connect_stdio(spec)
        elif spec.transport in ("sse", "streamable-http"):
            await self._connect_sse(spec)
        else:
            raise ValueError(f"Unsupported transport: {spec.transport}")

    async def _connect_stdio(self, spec: MCPServerSpec) -> None:
        if not spec.command:
            raise ValueError("stdio transport requires a command")

        params = StdioServerParameters(
            command=spec.command,
            args=spec.args or [],
            env=spec.env,
        )

        # stdio_client is an async context manager yielding (read, write) streams
        self._transport_ctx = stdio_client(params)
        streams = await self._transport_ctx.__aenter__()
        read_stream, write_stream = streams

        self._session = ClientSession(read_stream, write_stream)
        await self._session.__aenter__()
        await self._session.initialize()

    async def _connect_sse(self, spec: MCPServerSpec) -> None:
        if not spec.url:
            raise ValueError("SSE/streamable-HTTP transport requires a url")

        self._transport_ctx = sse_client(spec.url)
        streams = await self._transport_ctx.__aenter__()
        read_stream, write_stream = streams

        self._session = ClientSession(read_stream, write_stream)
        await self._session.__aenter__()
        await self._session.initialize()

    # -- queries ------------------------------------------------------------

    async def list_tools(self) -> list[ToolInfo]:
        """Return all tools exposed by the connected server."""
        self._ensure_connected()
        assert self._session is not None
        result: ListToolsResult = await self._session.list_tools()
        return [
            ToolInfo(
                name=t.name,
                description=t.description,
                input_schema=t.inputSchema if isinstance(t.inputSchema, dict) else {},
            )
            for t in result.tools
        ]

    async def list_resources(self) -> list[ResourceInfo]:
        """Return all resources exposed by the connected server."""
        self._ensure_connected()
        assert self._session is not None
        result: ListResourcesResult = await self._session.list_resources()
        return [
            ResourceInfo(
                uri=str(r.uri),
                name=r.name,
                description=r.description,
                mime_type=r.mimeType,
            )
            for r in result.resources
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        """Invoke a tool and return its result."""
        self._ensure_connected()
        assert self._session is not None
        result: CallToolResult = await self._session.call_tool(name, arguments)
        content: list[dict[str, Any]] = []
        for item in result.content:
            content.append({"type": item.type, "text": getattr(item, "text", "")})
        return ToolResult(content=content, is_error=bool(result.isError))

    async def read_resource(self, uri: str) -> list[dict[str, Any]]:
        """Read a resource by URI and return its contents."""
        self._ensure_connected()
        assert self._session is not None
        result: ReadResourceResult = await self._session.read_resource(uri)
        contents: list[dict[str, Any]] = []
        for item in result.contents:
            contents.append({
                "uri": str(item.uri),
                "text": getattr(item, "text", None),
                "mime_type": getattr(item, "mimeType", None),
            })
        return contents

    # -- lifecycle ----------------------------------------------------------

    async def close(self) -> None:
        """Gracefully shut down the session and transport."""
        if self._session is not None:
            try:
                await self._session.__aexit__(None, None, None)
            except Exception:
                pass
            self._session = None

        if self._transport_ctx is not None:
            try:
                await self._transport_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._transport_ctx = None

    def _ensure_connected(self) -> None:
        if self._session is None:
            raise RuntimeError("Not connected. Call connect() first.")


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------

def parse_server_spec(spec: str) -> MCPServerSpec:
    """Parse a CLI server specification into an ``MCPServerSpec``.

    Accepted formats:

    * **URL** — ``http://localhost:3001/sse`` or ``https://...``
      → SSE / streamable-HTTP transport.
    * **Command string** — ``npx @modelcontextprotocol/server-filesystem /tmp``
      → stdio transport (first token is command, rest are args).
    * **Python command** — ``python my_server.py``
      → stdio transport.

    Examples::

        parse_server_spec("npx @modelcontextprotocol/server-filesystem /tmp")
        parse_server_spec("http://localhost:3001/sse")
        parse_server_spec("python my_server.py --port 8080")
    """
    text = spec.strip()
    if not text:
        raise ValueError("Empty server specification")

    # URL-based transports
    if text.startswith(("http://", "https://")):
        name = text.split("//", 1)[1].split("/")[0]  # hostname as name
        return MCPServerSpec(
            name=name,
            transport="sse",
            url=text,
        )

    # Command-based (stdio) transport
    parts = shlex.split(text)
    command = parts[0]
    args = parts[1:] if len(parts) > 1 else []

    # Derive a human-friendly name from the command/args
    name = command
    for arg in args:
        if arg.startswith("@") or (not arg.startswith("-") and "/" not in arg[:2]):
            name = arg
            break

    return MCPServerSpec(
        name=name,
        transport="stdio",
        command=command,
        args=args,
    )


def spec_from_config(
    name: str,
    config: dict[str, Any],
) -> MCPServerSpec:
    """Convert a config dict (Khaos or Claude Desktop format) to an MCPServerSpec."""
    transport = config.get("transport", "stdio")

    if transport == "stdio":
        return MCPServerSpec(
            name=name,
            transport="stdio",
            command=config.get("command"),
            args=config.get("args", []),
            env=config.get("env"),
        )

    return MCPServerSpec(
        name=name,
        transport=transport,
        url=config.get("url"),
        env=config.get("env"),
    )


__all__ = [
    "MCPServerSpec",
    "MCPTestClient",
    "ToolInfo",
    "ResourceInfo",
    "ToolResult",
    "parse_server_spec",
    "spec_from_config",
]
