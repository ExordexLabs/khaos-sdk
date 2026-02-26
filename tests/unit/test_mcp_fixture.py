"""Unit tests for khaos.testing.mcp."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from khaos.evaluator.mcp.client import ToolInfo
from khaos.evaluator.mcp.scanner import RiskFinding, ScanResult
from khaos.evaluator.mcp.fuzzer import FuzzCase
from khaos.testing.mcp import (
    MCPScanResult,
    fuzz_mcp_tool,
)


def _make_finding(severity: str = "low", title: str = "Test") -> RiskFinding:
    return RiskFinding(
        category="test",
        severity=severity,
        owasp_id="MCP01",
        title=title,
        detail="detail",
    )


def _make_scan_result(findings: list[RiskFinding] | None = None) -> ScanResult:
    return ScanResult(
        server_name="test-server",
        transport="stdio",
        tools=[],
        resources=[],
        risk_findings=findings or [],
        owasp_flags=[],
    )


class TestMCPScanResult:
    def test_no_findings(self):
        result = MCPScanResult(inner=_make_scan_result())
        assert result.critical == 0
        assert result.high == 0
        assert result.findings == []

    def test_critical_count(self):
        findings = [
            _make_finding("critical", "Crit 1"),
            _make_finding("high", "High 1"),
            _make_finding("critical", "Crit 2"),
        ]
        result = MCPScanResult(inner=_make_scan_result(findings))
        assert result.critical == 2
        assert result.high == 1

    def test_assert_no_critical_passes(self):
        result = MCPScanResult(inner=_make_scan_result([_make_finding("high")]))
        result.assert_no_critical()  # should not raise

    def test_assert_no_critical_fails(self):
        result = MCPScanResult(inner=_make_scan_result([_make_finding("critical", "Bad Thing")]))
        with pytest.raises(AssertionError, match="Bad Thing"):
            result.assert_no_critical()

    def test_assert_no_high_or_critical_passes(self):
        result = MCPScanResult(inner=_make_scan_result([_make_finding("medium")]))
        result.assert_no_high_or_critical()

    def test_assert_no_high_or_critical_fails(self):
        result = MCPScanResult(inner=_make_scan_result([_make_finding("high", "Risky")]))
        with pytest.raises(AssertionError, match="Risky"):
            result.assert_no_high_or_critical()


class TestFuzzMcpTool:
    @patch("khaos.testing.mcp.generate_fuzz_cases")
    def test_returns_cases(self, mock_gen):
        cases = [
            FuzzCase(
                tool_name="read_file",
                arguments={"path": "../../etc/passwd"},
                attack_category="path-traversal",
                owasp_id="MCP01",
                description="Path traversal",
                expected_safe_behavior="Reject",
            ),
            FuzzCase(
                tool_name="read_file",
                arguments={"path": "'; DROP TABLE --"},
                attack_category="sql-injection",
                owasp_id="MCP02",
                description="SQL injection",
                expected_safe_behavior="Reject",
            ),
        ]
        mock_gen.return_value = cases

        tool = ToolInfo(name="read_file", description="Read a file", input_schema={})
        result = fuzz_mcp_tool(tool)
        assert len(result) == 2

    @patch("khaos.testing.mcp.generate_fuzz_cases")
    def test_category_filter(self, mock_gen):
        cases = [
            FuzzCase(
                tool_name="read_file",
                arguments={"path": "../../etc/passwd"},
                attack_category="path-traversal",
                owasp_id="MCP01",
                description="Path traversal",
                expected_safe_behavior="Reject",
            ),
            FuzzCase(
                tool_name="query",
                arguments={"sql": "'; DROP TABLE --"},
                attack_category="sql-injection",
                owasp_id="MCP02",
                description="SQL injection",
                expected_safe_behavior="Reject",
            ),
        ]
        mock_gen.return_value = cases

        tool = ToolInfo(name="read_file", description="Read", input_schema={})
        result = fuzz_mcp_tool(tool, categories=["path-traversal"])
        assert len(result) == 1
        assert result[0].attack_category == "path-traversal"
