"""Tests for khaos.evaluator.mcp.report — report formatting and OWASP coverage."""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from khaos.evaluator.mcp.client import ToolInfo
from khaos.evaluator.mcp.analyzer import AnalysisResult, Finding
from khaos.evaluator.mcp.fuzzer import FuzzCase
from khaos.evaluator.mcp.scanner import RiskFinding, ScanResult
from khaos.evaluator.mcp.report import (
    OWASP_MCP_TOP_10,
    TestResultCollector,
    _owasp_status,
    scan_to_json,
    results_to_json,
    print_scan_report,
    print_test_report,
)


def _case(category: str, owasp_id: str) -> FuzzCase:
    return FuzzCase("tool", {}, category, owasp_id, "test", "test")


def _finding(owasp_id: str, severity: str = "critical") -> Finding:
    return Finding("cat", severity, owasp_id, "title", "detail")


def _scan(findings: list[RiskFinding] | None = None) -> ScanResult:
    return ScanResult(
        server_name="test",
        transport="stdio",
        tools=[ToolInfo("t", "desc", {"type": "object", "properties": {}})],
        resources=[],
        risk_findings=findings or [],
        owasp_flags=sorted(set(f.owasp_id for f in (findings or []))),
    )


# ---------------------------------------------------------------------------
# TestResultCollector
# ---------------------------------------------------------------------------


class TestCollector:
    """Tests for TestResultCollector."""

    def test_tracks_tested_owasp_ids(self):
        c = TestResultCollector()
        c.add(_case("path-traversal", "MCP05"), AnalysisResult("safe"))
        c.add(_case("secret-scanning", "MCP01"), AnalysisResult("safe"))
        assert c.tested_owasp_ids == {"MCP05", "MCP01"}

    def test_counts(self):
        c = TestResultCollector()
        c.add(_case("a", "MCP05"), AnalysisResult("vulnerable", [_finding("MCP05")]))
        c.add(_case("b", "MCP05"), AnalysisResult("safe"))
        c.add(_case("c", "MCP05"), AnalysisResult("error"))
        c.add(_case("d", "MCP05"), AnalysisResult("inconclusive"))
        assert c.total == 4
        assert c.vulnerable_count == 1
        assert c.safe_count == 1
        assert c.error_count == 1
        assert c.inconclusive_count == 1

    def test_findings_by_owasp(self):
        c = TestResultCollector()
        c.add(_case("a", "MCP05"), AnalysisResult("vulnerable", [_finding("MCP05")]))
        c.add(_case("b", "MCP01"), AnalysisResult("vulnerable", [_finding("MCP01")]))
        by_owasp = c.findings_by_owasp()
        assert "MCP05" in by_owasp
        assert "MCP01" in by_owasp
        assert len(by_owasp["MCP05"]) == 1

    def test_findings_by_severity(self):
        c = TestResultCollector()
        c.add(_case("a", "MCP05"), AnalysisResult("vulnerable", [
            _finding("MCP05", "critical"),
            _finding("MCP05", "high"),
            _finding("MCP05", "medium"),
        ]))
        sev = c.findings_by_severity()
        assert sev["critical"] == 1
        assert sev["high"] == 1
        assert sev["medium"] == 1


# ---------------------------------------------------------------------------
# _owasp_status
# ---------------------------------------------------------------------------


class TestOwaspStatus:
    """Tests for _owasp_status with SKIP/PASS/WARN/FAIL."""

    def test_untested_returns_skip(self):
        status = _owasp_status("MCP05", [], tested=False)
        assert "SKIP" in status

    def test_no_findings_returns_pass(self):
        status = _owasp_status("MCP05", [], tested=True)
        assert "PASS" in status

    def test_critical_finding_returns_fail(self):
        status = _owasp_status("MCP05", [_finding("MCP05", "critical")], tested=True)
        assert "FAIL" in status

    def test_medium_finding_returns_warn(self):
        status = _owasp_status("MCP05", [_finding("MCP05", "medium")], tested=True)
        assert "WARN" in status

    def test_advisory_only_returns_info(self):
        """Advisory-only findings should show INFO status."""
        advisory_finding = Finding("auth", "info", "MCP07", "Protocol note", "detail", advisory=True)
        status = _owasp_status("MCP07", [advisory_finding], tested=True)
        assert "INFO" in status

    def test_mixed_advisory_and_real_returns_warn_or_fail(self):
        """If there are both advisory and real findings, don't show INFO."""
        findings = [
            Finding("auth", "info", "MCP07", "Advisory", "detail", advisory=True),
            Finding("auth", "medium", "MCP07", "Real finding", "detail", advisory=False),
        ]
        status = _owasp_status("MCP07", findings, tested=True)
        assert "WARN" in status


# ---------------------------------------------------------------------------
# JSON output: scan_to_json
# ---------------------------------------------------------------------------


class TestScanToJson:
    """Tests for scan_to_json."""

    def test_structure(self):
        scan = _scan()
        j = scan_to_json(scan)
        assert j["server_name"] == "test"
        assert j["transport"] == "stdio"
        assert "tools" in j
        assert "risk_findings" in j
        assert "summary" in j

    def test_findings_included(self):
        scan = _scan([RiskFinding("cat", "high", "MCP05", "title", "detail", "tool")])
        j = scan_to_json(scan)
        assert len(j["risk_findings"]) == 1
        assert j["risk_findings"][0]["owasp_id"] == "MCP05"


# ---------------------------------------------------------------------------
# JSON output: results_to_json
# ---------------------------------------------------------------------------


class TestResultsToJson:
    """Tests for results_to_json."""

    def test_untested_categories_show_skip(self):
        """Regression: untested categories must NOT show 'pass'."""
        c = TestResultCollector()
        c.add(_case("path-traversal", "MCP05"), AnalysisResult("safe"))
        j = results_to_json("test", c)
        # MCP05 was tested
        assert j["owasp_coverage"]["MCP05"]["status"] == "pass"
        assert j["owasp_coverage"]["MCP05"]["tested"] is True
        # MCP01 was NOT tested (no scan provided, not in tested_owasp_ids)
        assert j["owasp_coverage"]["MCP01"]["tested"] is False
        assert j["owasp_coverage"]["MCP01"]["status"] == "skip"

    def test_scan_findings_merged(self):
        c = TestResultCollector()
        c.add(_case("path-traversal", "MCP05"), AnalysisResult("safe"))
        scan = _scan([RiskFinding("supply-chain", "medium", "MCP04", "npx", "detail")])
        j = results_to_json("test", c, scan=scan)
        # MCP04 should be tested (scanner always checks it) and show findings
        assert j["owasp_coverage"]["MCP04"]["tested"] is True
        assert j["owasp_coverage"]["MCP04"]["findings_count"] == 1
        assert j["owasp_coverage"]["MCP04"]["status"] == "warn"

    def test_scanner_only_categories_tested(self):
        """MCP02/03/04/07/08/09 should show as tested even without fuzz cases."""
        c = TestResultCollector()
        j = results_to_json("test", c)
        for mcp_id in ("MCP02", "MCP03", "MCP04", "MCP07", "MCP08", "MCP09"):
            assert j["owasp_coverage"][mcp_id]["tested"] is True, f"{mcp_id} should be tested"

    def test_severity_summary(self):
        c = TestResultCollector()
        c.add(_case("a", "MCP05"), AnalysisResult("vulnerable", [
            _finding("MCP05", "critical"),
        ]))
        j = results_to_json("test", c)
        assert j["severity_summary"]["critical"] == 1


# ---------------------------------------------------------------------------
# Rich output: smoke tests (don't crash)
# ---------------------------------------------------------------------------


class TestRichOutput:
    """Smoke tests that Rich report rendering doesn't crash."""

    def test_scan_report_renders(self):
        scan = _scan([RiskFinding("cat", "high", "MCP05", "title", "detail", "tool")])
        console = Console(file=None, force_terminal=False)
        # Should not raise
        print_scan_report(scan, console)

    def test_scan_report_no_findings(self):
        scan = _scan()
        console = Console(file=None, force_terminal=False)
        print_scan_report(scan, console)

    def test_test_report_renders(self):
        c = TestResultCollector()
        c.add(_case("path-traversal", "MCP05"), AnalysisResult("vulnerable", [_finding("MCP05")]))
        scan = _scan()
        console = Console(file=None, force_terminal=False)
        print_test_report("test", scan, c, console)

    def test_test_report_no_findings(self):
        c = TestResultCollector()
        c.add(_case("path-traversal", "MCP05"), AnalysisResult("safe"))
        scan = _scan()
        console = Console(file=None, force_terminal=False)
        print_test_report("test", scan, c, console)
