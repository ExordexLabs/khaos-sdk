"""MCP testing fixtures and scanner integration.

Provides pytest-friendly wrappers around the MCP evaluator
(client, scanner, fuzzer) for testing MCP server security.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from khaos.evaluator.mcp.client import (
    MCPServerSpec,
    MCPTestClient,
    ToolInfo,
    ToolResult,
    parse_server_spec,
)
from khaos.evaluator.mcp.scanner import RiskFinding, ScanResult, scan_server
from khaos.evaluator.mcp.fuzzer import FuzzCase, generate_fuzz_cases


@dataclass
class MCPScanResult:
    """Testing-friendly wrapper around :class:`ScanResult`."""

    inner: ScanResult

    @property
    def findings(self) -> list[RiskFinding]:
        return self.inner.risk_findings

    @property
    def critical(self) -> int:
        return self.inner.critical_count

    @property
    def high(self) -> int:
        return self.inner.high_count

    @property
    def tools(self) -> list[ToolInfo]:
        return self.inner.tools

    def assert_no_critical(self, msg: str = "") -> None:
        """Assert there are no critical findings."""
        if self.critical > 0:
            criticals = [f for f in self.findings if f.severity == "critical"]
            details = "; ".join(f"{f.title} ({f.owasp_id})" for f in criticals[:3])
            fail = f"Found {self.critical} critical findings: {details}"
            if msg:
                fail = f"{fail} — {msg}"
            raise AssertionError(fail)

    def assert_no_high_or_critical(self, msg: str = "") -> None:
        """Assert there are no high or critical findings."""
        count = self.critical + self.high
        if count > 0:
            severe = [f for f in self.findings if f.severity in ("critical", "high")]
            details = "; ".join(f"{f.title} ({f.severity})" for f in severe[:3])
            fail = f"Found {count} high/critical findings: {details}"
            if msg:
                fail = f"{fail} — {msg}"
            raise AssertionError(fail)


def create_mcp_client(
    server_command: str,
    *,
    transport: str = "stdio",
    env: dict[str, str] | None = None,
) -> MCPTestClient:
    """Create an :class:`MCPTestClient` pre-configured for the given server.

    The returned client is an async context manager::

        async with create_mcp_client("npx @mcp/server /tmp") as client:
            tools = await client.list_tools()

    Note: The caller must ``await client.connect(spec)`` after entering
    the context, or use :func:`scan_mcp_server` for a higher-level API.
    """
    return MCPTestClient()


def _build_spec(
    server_command: str,
    *,
    transport: str = "stdio",
    env: dict[str, str] | None = None,
) -> MCPServerSpec:
    """Parse a server command string into an MCPServerSpec."""
    spec = parse_server_spec(server_command)
    if transport != "stdio":
        spec.transport = transport  # type: ignore[assignment]
    if env:
        spec.env = env
    return spec


async def _scan_async(spec: MCPServerSpec) -> ScanResult:
    return await scan_server(spec)


def scan_mcp_server(
    server_command: str,
    *,
    transport: str = "stdio",
    env: dict[str, str] | None = None,
    checks: list[str] | None = None,
) -> MCPScanResult:
    """Scan an MCP server and return a testing-friendly result.

    This is a synchronous wrapper that runs the async scanner.

    Args:
        server_command: Command to start the MCP server.
        transport: Transport type (``"stdio"``, ``"sse"``, ``"streamable-http"``).
        env: Environment variables for the server process.
        checks: Optional list of specific checks to run (currently unused,
                reserved for future filtering).

    Returns:
        An :class:`MCPScanResult` with assertion helpers.
    """
    spec = _build_spec(server_command, transport=transport, env=env)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = pool.submit(asyncio.run, _scan_async(spec)).result()
    else:
        result = asyncio.run(_scan_async(spec))

    return MCPScanResult(inner=result)


def fuzz_mcp_tool(
    tool: ToolInfo,
    *,
    categories: list[str] | None = None,
) -> list[FuzzCase]:
    """Generate fuzz test cases for a single MCP tool.

    Args:
        tool: The tool to fuzz.
        categories: Optional filter for attack categories
                    (e.g., ``["path-traversal", "sql-injection"]``).

    Returns:
        List of :class:`FuzzCase` instances.
    """
    cases = generate_fuzz_cases(tool)
    if categories:
        cases = [c for c in cases if c.attack_category in categories]
    return cases


__all__ = [
    "MCPScanResult",
    "create_mcp_client",
    "scan_mcp_server",
    "fuzz_mcp_tool",
]
