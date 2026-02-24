"""Integration tests for high-risk community MCP servers.

These tests require external dependencies (npm packages, Python packages)
and are skipped automatically if the dependencies are not available.

Run with:
    pytest tests/integration/ -m integration
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess

import pytest

from khaos.evaluator.mcp.client import MCPServerSpec, MCPTestClient
from khaos.evaluator.mcp.scanner import scan_server
from khaos.evaluator.mcp.fuzzer import generate_fuzz_cases_for_tools
from khaos.evaluator.mcp.analyzer import analyze_tool_response
from khaos.evaluator.mcp.report import TestResultCollector

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

_HAS_NPX = shutil.which("npx") is not None
_HAS_PYTHON = shutil.which("python") is not None


def _can_import(module: str) -> bool:
    """Check if a Python module is importable."""
    try:
        __import__(module)
        return True
    except ImportError:
        return False


_HAS_MCP_SHELL_SERVER = _can_import("mcp_shell_server")

# ---------------------------------------------------------------------------
# Server specifications
# ---------------------------------------------------------------------------

DESKTOP_COMMANDER_SPEC = MCPServerSpec(
    name="desktop-commander",
    transport="stdio",
    command="npx",
    args=["-y", "@wonderwhy-er/desktop-commander"],
)

SHELL_SERVER_SPEC = MCPServerSpec(
    name="mcp-shell-server",
    transport="stdio",
    command="python",
    args=["-m", "mcp_shell_server"],
    env={"ALLOW_COMMANDS": "ls,echo,cat,pwd,whoami"},
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_async(coro):
    """Run an async coroutine."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Desktop Commander tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.skipif(not _HAS_NPX, reason="npx not available")
class TestDesktopCommander:
    """Integration tests for Desktop Commander MCP server."""

    def test_scan_discovers_tools(self):
        """Scan should discover command-execution tools and flag MCP05."""
        result = _run_async(scan_server(DESKTOP_COMMANDER_SPEC))
        assert len(result.tools) > 0
        # Should have command-execution related tools
        tool_names = [t.name for t in result.tools]
        assert any(
            kw in name.lower()
            for name in tool_names
            for kw in ("exec", "command", "run", "shell", "terminal")
        ), f"Expected command-execution tools, got: {tool_names}"
        # Should flag MCP05 (input validation / injection risk)
        assert "MCP05" in result.owasp_flags

    def test_fuzz_command_injection(self):
        """Fuzz pipeline should find command injection vectors."""
        scan_result = _run_async(scan_server(DESKTOP_COMMANDER_SPEC))

        # Generate fuzz cases filtered to command injection
        fuzz_cases = generate_fuzz_cases_for_tools(scan_result.tools)
        cmd_cases = [
            c for c in fuzz_cases
            if c.attack_category in ("command-injection", "path-traversal")
        ]
        assert len(cmd_cases) > 0, "Should generate command injection fuzz cases"

        # Run a limited set of fuzz cases
        cmd_cases = cmd_cases[:10]

        async def _fuzz():
            collector = TestResultCollector()
            async with MCPTestClient() as client:
                await client.connect(DESKTOP_COMMANDER_SPEC)
                for case in cmd_cases:
                    try:
                        result = await asyncio.wait_for(
                            client.call_tool(case.tool_name, case.arguments),
                            timeout=15.0,
                        )
                        analysis = analyze_tool_response(case, result)
                    except Exception:
                        from khaos.evaluator.mcp.analyzer import AnalysisResult
                        analysis = AnalysisResult(classification="error")
                    collector.add(case, analysis)
            return collector

        collector = _run_async(_fuzz())
        assert collector.total > 0

    def test_full_pipeline(self):
        """End-to-end: scan -> fuzz -> analyze -> report."""
        async def _pipeline():
            # Scan
            scan_result = await scan_server(DESKTOP_COMMANDER_SPEC)
            assert len(scan_result.tools) > 0

            # Generate and run fuzz cases (limited)
            fuzz_cases = generate_fuzz_cases_for_tools(scan_result.tools)[:20]
            collector = TestResultCollector()

            async with MCPTestClient() as client:
                await client.connect(DESKTOP_COMMANDER_SPEC)
                for case in fuzz_cases:
                    try:
                        result = await asyncio.wait_for(
                            client.call_tool(case.tool_name, case.arguments),
                            timeout=15.0,
                        )
                        analysis = analyze_tool_response(case, result)
                    except Exception:
                        from khaos.evaluator.mcp.analyzer import AnalysisResult
                        analysis = AnalysisResult(classification="error")
                    collector.add(case, analysis)

            return scan_result, collector

        scan_result, collector = _run_async(_pipeline())
        assert collector.total > 0
        # Should have at least scan findings
        assert scan_result.total_findings > 0


# ---------------------------------------------------------------------------
# Shell Server tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.skipif(
    not _HAS_PYTHON or not _HAS_MCP_SHELL_SERVER,
    reason="mcp-shell-server not installed",
)
class TestShellServer:
    """Integration tests for MCP Shell Server."""

    def test_scan_discovers_tools(self):
        """Scan should discover shell execution tools and flag MCP05."""
        result = _run_async(scan_server(SHELL_SERVER_SPEC))
        assert len(result.tools) > 0
        # Should flag input validation risks
        assert any(
            f.owasp_id == "MCP05" for f in result.risk_findings
        ), "Should flag MCP05 for shell execution tools"

    def test_fuzz_command_injection(self):
        """Fuzz pipeline should test command injection on shell server."""
        scan_result = _run_async(scan_server(SHELL_SERVER_SPEC))

        fuzz_cases = generate_fuzz_cases_for_tools(scan_result.tools)
        cmd_cases = [
            c for c in fuzz_cases
            if c.attack_category == "command-injection"
        ][:10]

        if not cmd_cases:
            pytest.skip("No command injection fuzz cases generated")

        async def _fuzz():
            collector = TestResultCollector()
            async with MCPTestClient() as client:
                await client.connect(SHELL_SERVER_SPEC)
                for case in cmd_cases:
                    try:
                        result = await asyncio.wait_for(
                            client.call_tool(case.tool_name, case.arguments),
                            timeout=15.0,
                        )
                        analysis = analyze_tool_response(case, result)
                    except Exception:
                        from khaos.evaluator.mcp.analyzer import AnalysisResult
                        analysis = AnalysisResult(classification="error")
                    collector.add(case, analysis)
            return collector

        collector = _run_async(_fuzz())
        assert collector.total > 0

    def test_full_pipeline(self):
        """End-to-end: scan -> fuzz -> analyze -> report."""
        async def _pipeline():
            scan_result = await scan_server(SHELL_SERVER_SPEC)
            assert len(scan_result.tools) > 0

            fuzz_cases = generate_fuzz_cases_for_tools(scan_result.tools)[:20]
            collector = TestResultCollector()

            async with MCPTestClient() as client:
                await client.connect(SHELL_SERVER_SPEC)
                for case in fuzz_cases:
                    try:
                        result = await asyncio.wait_for(
                            client.call_tool(case.tool_name, case.arguments),
                            timeout=15.0,
                        )
                        analysis = analyze_tool_response(case, result)
                    except Exception:
                        from khaos.evaluator.mcp.analyzer import AnalysisResult
                        analysis = AnalysisResult(classification="error")
                    collector.add(case, analysis)

            return scan_result, collector

        scan_result, collector = _run_async(_pipeline())
        assert collector.total > 0
        assert scan_result.total_findings > 0
