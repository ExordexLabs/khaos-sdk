"""Tests for khaos.evaluator.mcp.client — spec parsing and data types."""

from __future__ import annotations

import pytest

from khaos.evaluator.mcp.client import (
    MCPServerSpec,
    MCPTestClient,
    ToolInfo,
    ToolResult,
    ResourceInfo,
    parse_server_spec,
    spec_from_config,
)


# ---------------------------------------------------------------------------
# parse_server_spec
# ---------------------------------------------------------------------------


class TestParseServerSpec:
    """Tests for parse_server_spec()."""

    def test_http_url(self):
        spec = parse_server_spec("http://localhost:3001/sse")
        assert spec.transport == "sse"
        assert spec.url == "http://localhost:3001/sse"
        assert spec.name == "localhost:3001"
        assert spec.command is None

    def test_https_url(self):
        spec = parse_server_spec("https://example.com/mcp")
        assert spec.transport == "sse"
        assert spec.url == "https://example.com/mcp"
        assert spec.name == "example.com"

    def test_npx_command(self):
        spec = parse_server_spec(
            "npx @modelcontextprotocol/server-filesystem /tmp"
        )
        assert spec.transport == "stdio"
        assert spec.command == "npx"
        assert "@modelcontextprotocol/server-filesystem" in spec.args
        assert "/tmp" in spec.args
        assert spec.url is None

    def test_python_command(self):
        spec = parse_server_spec("python my_server.py --port 8080")
        assert spec.transport == "stdio"
        assert spec.command == "python"
        assert "my_server.py" in spec.args
        assert "--port" in spec.args

    def test_empty_spec_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            parse_server_spec("")

    def test_whitespace_spec_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            parse_server_spec("   ")

    def test_single_command(self):
        spec = parse_server_spec("my-server")
        assert spec.transport == "stdio"
        assert spec.command == "my-server"
        assert spec.args == []

    def test_npx_name_uses_package(self):
        spec = parse_server_spec("npx -y @acme/cool-server /data")
        assert spec.name == "@acme/cool-server"


# ---------------------------------------------------------------------------
# spec_from_config
# ---------------------------------------------------------------------------


class TestSpecFromConfig:
    """Tests for spec_from_config()."""

    def test_stdio_config(self):
        config = {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            "env": {"NODE_ENV": "production"},
        }
        spec = spec_from_config("filesystem", config)
        assert spec.name == "filesystem"
        assert spec.transport == "stdio"
        assert spec.command == "npx"
        assert spec.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        assert spec.env == {"NODE_ENV": "production"}

    def test_sse_config(self):
        config = {
            "transport": "sse",
            "url": "http://localhost:3001/sse",
        }
        spec = spec_from_config("remote", config)
        assert spec.transport == "sse"
        assert spec.url == "http://localhost:3001/sse"
        assert spec.command is None

    def test_defaults_to_stdio(self):
        config = {"command": "my-server"}
        spec = spec_from_config("test", config)
        assert spec.transport == "stdio"

    def test_env_is_none_when_absent(self):
        config = {"command": "my-server"}
        spec = spec_from_config("test", config)
        assert spec.env is None


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class TestDataTypes:
    """Tests for ToolInfo, ResourceInfo, ToolResult."""

    def test_tool_info(self):
        t = ToolInfo(name="read", description="Read a file", input_schema={"type": "object"})
        assert t.name == "read"
        assert t.description == "Read a file"

    def test_tool_result_error(self):
        r = ToolResult(content=[{"text": "not found"}], is_error=True)
        assert r.is_error is True

    def test_tool_result_success(self):
        r = ToolResult(content=[{"text": "ok"}], is_error=False)
        assert r.is_error is False

    def test_resource_info(self):
        r = ResourceInfo(uri="file:///tmp", name="tmp", description="Temp", mime_type="text/plain")
        assert r.uri == "file:///tmp"


# ---------------------------------------------------------------------------
# MCPTestClient (unit — no live server)
# ---------------------------------------------------------------------------


class TestMCPTestClient:
    """Unit tests for MCPTestClient without a real server."""

    async def test_not_connected_raises(self):
        client = MCPTestClient()
        with pytest.raises(RuntimeError, match="Not connected"):
            await client.list_tools()

    async def test_context_manager(self):
        async with MCPTestClient() as client:
            assert client._session is None  # not connected yet

    async def test_connect_bad_transport(self):
        spec = MCPServerSpec(name="bad", transport="grpc")  # type: ignore[arg-type]
        client = MCPTestClient()
        with pytest.raises(ValueError, match="Unsupported transport"):
            await client.connect(spec)

    async def test_connect_stdio_no_command(self):
        spec = MCPServerSpec(name="bad", transport="stdio", command=None)
        client = MCPTestClient()
        with pytest.raises(ValueError, match="requires a command"):
            await client.connect(spec)

    async def test_connect_sse_no_url(self):
        spec = MCPServerSpec(name="bad", transport="sse", url=None)
        client = MCPTestClient()
        with pytest.raises(ValueError, match="requires a url"):
            await client.connect(spec)
