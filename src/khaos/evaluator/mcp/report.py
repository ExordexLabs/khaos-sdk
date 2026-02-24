"""MCP security report formatting.

Produces Rich terminal output, JSON export, and OWASP MCP Top 10
mapping for ``khaos mcp scan`` and ``khaos mcp test`` results.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analyzer import AnalysisResult, Finding
from .fuzzer import FuzzCase
from .scanner import RiskFinding, ScanResult


# ---------------------------------------------------------------------------
# OWASP MCP Top 10 definitions
# ---------------------------------------------------------------------------

OWASP_MCP_TOP_10: dict[str, dict[str, str]] = {
    "MCP01": {"name": "Token Mismanagement", "phase": "v1.1"},
    "MCP02": {"name": "Privilege Escalation", "phase": "v1.3"},
    "MCP03": {"name": "Tool Poisoning", "phase": "v1.2"},
    "MCP04": {"name": "Supply Chain Attacks", "phase": "v1.3"},
    "MCP05": {"name": "Command Injection", "phase": "v1.1"},
    "MCP06": {"name": "Intent Flow Subversion", "phase": "v1.2"},
    "MCP07": {"name": "Insufficient Auth", "phase": "v1.1"},
    "MCP08": {"name": "Lack of Audit", "phase": "v1.3"},
    "MCP09": {"name": "Shadow Servers", "phase": "v1.3"},
    "MCP10": {"name": "Context Injection", "phase": "v1.3"},
}


# ---------------------------------------------------------------------------
# Fuzz test result tracking
# ---------------------------------------------------------------------------

class TestResultCollector:
    """Collects and aggregates fuzz test results for reporting."""

    def __init__(self) -> None:
        self.results: list[tuple[FuzzCase, AnalysisResult]] = []
        self.tested_owasp_ids: set[str] = set()

    def add(self, case: FuzzCase, result: AnalysisResult) -> None:
        self.results.append((case, result))
        self.tested_owasp_ids.add(case.owasp_id)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for _, r in self.results if r.classification == "vulnerable")

    @property
    def safe_count(self) -> int:
        return sum(1 for _, r in self.results if r.classification == "safe")

    @property
    def error_count(self) -> int:
        return sum(1 for _, r in self.results if r.classification == "error")

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for _, r in self.results if r.classification == "inconclusive")

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for _, result in self.results:
            findings.extend(result.findings)
        return findings

    def findings_by_owasp(self) -> dict[str, list[Finding]]:
        by_owasp: dict[str, list[Finding]] = {}
        for finding in self.all_findings:
            by_owasp.setdefault(finding.owasp_id, []).append(finding)
        return by_owasp

    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in self.all_findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def add_mitl(self, result: "MITLResult") -> None:
        """Convert an MITL result into the standard Finding/FuzzCase format.

        This allows MITL results to appear in the unified report alongside
        direct-mode fuzz results.
        """
        from .fuzzer import FuzzCase
        from .analyzer import AnalysisResult, Finding

        # Create a synthetic FuzzCase
        case = FuzzCase(
            tool_name=result.test_case.tool_name,
            arguments={},
            attack_category="mitl-" + result.test_case.owasp_id.lower(),
            owasp_id=result.test_case.owasp_id,
            description=result.test_case.attack_name,
            expected_safe_behavior=result.test_case.expected_behavior,
        )

        # Map MITL classification to analyzer classification
        classification_map = {
            "compromised": "vulnerable",
            "blocked": "safe",
            "inconclusive": "inconclusive",
        }
        classification = classification_map.get(result.classification, "inconclusive")

        findings: list[Finding] = []
        if result.classification == "compromised":
            findings.append(Finding(
                category=f"mitl-{result.test_case.owasp_id.lower()}",
                severity=result.test_case.severity,
                owasp_id=result.test_case.owasp_id,
                title=f"[MITL] {result.test_case.attack_name}",
                detail="; ".join(result.findings) if result.findings else "LLM compromised by poisoned tool data.",
                evidence=result.llm_response[:100] if result.llm_response else "",
            ))

        analysis = AnalysisResult(
            classification=classification,
            findings=findings,
        )

        self.add(case, analysis)


# ---------------------------------------------------------------------------
# Severity display helpers
# ---------------------------------------------------------------------------

def _severity_style(severity: str) -> str:
    return {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[yellow]HIGH[/yellow]",
        "medium": "[cyan]MEDIUM[/cyan]",
        "low": "[dim]LOW[/dim]",
    }.get(severity.lower(), severity)


def _owasp_status(owasp_id: str, findings: list[Finding], tested: bool = True) -> str:
    """Return PASS/WARN/FAIL/INFO/SKIP status for an OWASP category."""
    if not tested:
        return "[dim]SKIP[/dim]"
    if not findings:
        return "[green]PASS[/green]"
    # Check if ALL findings are advisory (from RiskFinding converted to Finding)
    all_advisory = all(getattr(f, "advisory", False) for f in findings)
    if all_advisory:
        return "[dim cyan]INFO[/dim cyan]"
    has_critical = any(f.severity in ("critical", "high") for f in findings)
    if has_critical:
        return "[bold red]FAIL[/bold red]"
    return "[yellow]WARN[/yellow]"


# ---------------------------------------------------------------------------
# Scan report
# ---------------------------------------------------------------------------

def print_scan_report(scan: ScanResult, console: Console | None = None) -> None:
    """Print a rich terminal report for a scan result."""
    console = console or Console()

    # Header
    console.print()
    console.print(Panel(
        f"[bold]MCP Server Scan Report[/bold]\n"
        f"Server: [cyan]{scan.server_name}[/cyan]  |  "
        f"Transport: {scan.transport}  |  "
        f"Tools: {len(scan.tools)}  |  Resources: {len(scan.resources)}",
        border_style="blue",
    ))

    # Tools table
    if scan.tools:
        tools_table = Table(title="Tools", show_lines=False)
        tools_table.add_column("Name", style="cyan", no_wrap=True)
        tools_table.add_column("Parameters", style="green")
        tools_table.add_column("Description", max_width=50)

        for tool in scan.tools:
            params = ", ".join(tool.input_schema.get("properties", {}).keys())
            desc = (tool.description or "")[:50]
            if len(tool.description or "") > 50:
                desc += "..."
            tools_table.add_row(tool.name, params or "-", desc)

        console.print(tools_table)

    # Resources table
    if scan.resources:
        res_table = Table(title="Resources", show_lines=False)
        res_table.add_column("URI", style="cyan")
        res_table.add_column("Name")
        res_table.add_column("Type")

        for res in scan.resources:
            res_table.add_row(res.uri, res.name or "-", res.mime_type or "-")

        console.print(res_table)

    # Risk findings
    if scan.risk_findings:
        console.print()
        findings_table = Table(title=f"Risk Findings ({scan.total_findings})", show_lines=True)
        findings_table.add_column("OWASP", style="cyan", no_wrap=True)
        findings_table.add_column("Severity", justify="center")
        findings_table.add_column("Category")
        findings_table.add_column("Finding", max_width=60)
        findings_table.add_column("Tool", style="dim")

        for finding in sorted(scan.risk_findings, key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9),
            f.owasp_id,
        )):
            findings_table.add_row(
                finding.owasp_id,
                _severity_style(finding.severity),
                finding.category,
                finding.title,
                finding.tool_name or "-",
            )

        console.print(findings_table)
    else:
        console.print("\n[green]No risk findings detected in server schemas.[/green]")

    # Summary
    console.print()
    console.print(
        f"[dim]Summary: "
        f"[bold red]{scan.critical_count} CRITICAL[/bold red] | "
        f"[yellow]{scan.high_count} HIGH[/yellow] | "
        f"{scan.total_findings} total findings[/dim]"
    )
    if scan.owasp_flags:
        console.print(f"[dim]OWASP flags: {', '.join(scan.owasp_flags)}[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# Test report
# ---------------------------------------------------------------------------

def print_test_report(
    server_name: str,
    scan: ScanResult,
    collector: TestResultCollector,
    console: Console | None = None,
) -> None:
    """Print a rich terminal report for test results."""
    console = console or Console()

    # Header
    console.print()
    console.print(Panel(
        f"[bold]MCP Server Security Report[/bold]\n"
        f"Server: [cyan]{server_name}[/cyan]",
        border_style="blue",
    ))

    # OWASP MCP Top 10 coverage
    # Merge scanner-level OWASP flags into tested set (scanner tests some
    # categories statically even when fuzz cases aren't generated for them)
    tested_ids = collector.tested_owasp_ids | set(scan.owasp_flags)
    # Scanner always evaluates these categories (absence = PASS, not SKIP)
    tested_ids |= {"MCP02", "MCP03", "MCP04", "MCP07", "MCP08", "MCP09"}

    findings_by_owasp = collector.findings_by_owasp()
    # Also fold in scan-level findings so the OWASP table reflects them
    for rf in scan.risk_findings:
        findings_by_owasp.setdefault(rf.owasp_id, []).append(
            Finding(
                category=rf.category,
                severity=rf.severity,
                owasp_id=rf.owasp_id,
                title=rf.title,
                detail=rf.detail,
                advisory=getattr(rf, "advisory", False),
            )
        )

    owasp_table = Table(title="OWASP MCP Top 10 Coverage")
    owasp_table.add_column("Status", justify="center")
    owasp_table.add_column("ID", style="cyan", no_wrap=True)
    owasp_table.add_column("Risk")
    owasp_table.add_column("Findings", justify="right")
    owasp_table.add_column("Phase", style="dim")

    for owasp_id, info in OWASP_MCP_TOP_10.items():
        owasp_findings = findings_by_owasp.get(owasp_id, [])
        tested = owasp_id in tested_ids
        status = _owasp_status(owasp_id, owasp_findings, tested=tested)
        count = str(len(owasp_findings)) if owasp_findings else ("-" if tested else "")
        owasp_table.add_row(
            status,
            owasp_id,
            info["name"],
            count,
            info["phase"],
        )

    console.print(owasp_table)

    # Findings detail
    all_findings = collector.all_findings
    if all_findings:
        console.print()
        detail_table = Table(title=f"Security Findings ({len(all_findings)})", show_lines=True)
        detail_table.add_column("Severity", justify="center")
        detail_table.add_column("OWASP", style="cyan", no_wrap=True)
        detail_table.add_column("Category")
        detail_table.add_column("Finding", max_width=50)
        detail_table.add_column("Evidence", style="dim", max_width=40)

        for finding in sorted(all_findings, key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9),
        )):
            detail_table.add_row(
                _severity_style(finding.severity),
                finding.owasp_id,
                finding.category,
                finding.title,
                finding.evidence[:40] if finding.evidence else "-",
            )

        console.print(detail_table)

    # Summary
    sev = collector.findings_by_severity()
    console.print()
    console.print(
        f"[dim]Tests: {collector.total} | "
        f"Vulnerable: [bold red]{collector.vulnerable_count}[/bold red] | "
        f"Safe: [green]{collector.safe_count}[/green] | "
        f"Inconclusive: {collector.inconclusive_count}[/dim]"
    )
    console.print(
        f"[dim]Findings: "
        f"[bold red]{sev.get('critical', 0)} CRITICAL[/bold red] | "
        f"[yellow]{sev.get('high', 0)} HIGH[/yellow] | "
        f"[cyan]{sev.get('medium', 0)} MEDIUM[/cyan] | "
        f"{sev.get('low', 0)} LOW[/dim]"
    )
    console.print()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def scan_to_json(scan: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "server_name": scan.server_name,
        "transport": scan.transport,
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in scan.tools
        ],
        "resources": [
            {
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mime_type": r.mime_type,
            }
            for r in scan.resources
        ],
        "risk_findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "owasp_id": f.owasp_id,
                "title": f.title,
                "detail": f.detail,
                "tool_name": f.tool_name,
                "resource_uri": f.resource_uri,
                "advisory": f.advisory,
            }
            for f in scan.risk_findings
        ],
        "owasp_flags": scan.owasp_flags,
        "summary": {
            "tools_count": len(scan.tools),
            "resources_count": len(scan.resources),
            "critical": scan.critical_count,
            "high": scan.high_count,
            "total_findings": scan.total_findings,
        },
    }


def results_to_json(
    server_name: str,
    collector: TestResultCollector,
    scan: ScanResult | None = None,
) -> dict[str, Any]:
    """Convert test results to a JSON-serializable dict."""
    sev = collector.findings_by_severity()
    findings_by_owasp = collector.findings_by_owasp()

    # Merge scanner findings into the OWASP map
    if scan:
        for rf in scan.risk_findings:
            findings_by_owasp.setdefault(rf.owasp_id, []).append(
                Finding(
                    category=rf.category,
                    severity=rf.severity,
                    owasp_id=rf.owasp_id,
                    title=rf.title,
                    detail=rf.detail,
                    advisory=getattr(rf, "advisory", False),
                )
            )

    # Scanner always evaluates these categories statically
    tested_ids = collector.tested_owasp_ids | {"MCP02", "MCP03", "MCP04", "MCP07", "MCP08", "MCP09"}
    if scan:
        tested_ids |= set(scan.owasp_flags)

    owasp_coverage: dict[str, Any] = {}
    for owasp_id, info in OWASP_MCP_TOP_10.items():
        owasp_findings = findings_by_owasp.get(owasp_id, [])
        tested = owasp_id in tested_ids
        if not tested:
            status = "skip"
        elif all(getattr(f, "advisory", False) for f in owasp_findings) and owasp_findings:
            status = "info"
        elif any(f.severity in ("critical", "high") for f in owasp_findings):
            status = "fail"
        elif owasp_findings:
            status = "warn"
        else:
            status = "pass"
        owasp_coverage[owasp_id] = {
            "name": info["name"],
            "status": status,
            "tested": tested,
            "findings_count": len(owasp_findings),
        }

    return {
        "server_name": server_name,
        "tests_run": collector.total,
        "vulnerable": collector.vulnerable_count,
        "safe": collector.safe_count,
        "inconclusive": collector.inconclusive_count,
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "owasp_id": f.owasp_id,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "advisory": f.advisory,
            }
            for f in collector.all_findings
        ],
        "owasp_coverage": owasp_coverage,
        "severity_summary": sev,
    }


# ---------------------------------------------------------------------------
# Audit-config report
# ---------------------------------------------------------------------------

def print_audit_config_report(
    config_path: str,
    server_scans: dict[str, ScanResult],
    console: Console | None = None,
) -> None:
    """Print a summary report for all servers found in a config file."""
    console = console or Console()

    console.print()
    console.print(Panel(
        f"[bold]MCP Config Audit Report[/bold]\n"
        f"Config: [cyan]{config_path}[/cyan]  |  "
        f"Servers: {len(server_scans)}",
        border_style="blue",
    ))

    if not server_scans:
        console.print("[yellow]No MCP servers found in config.[/yellow]\n")
        return

    summary_table = Table(title="Server Summary")
    summary_table.add_column("Server", style="cyan")
    summary_table.add_column("Tools", justify="right")
    summary_table.add_column("Resources", justify="right")
    summary_table.add_column("Critical", justify="right", style="bold red")
    summary_table.add_column("High", justify="right", style="yellow")
    summary_table.add_column("Total", justify="right")
    summary_table.add_column("OWASP Flags")

    total_critical = 0
    total_high = 0
    total_findings_count = 0

    for name, scan in server_scans.items():
        total_critical += scan.critical_count
        total_high += scan.high_count
        total_findings_count += scan.total_findings

        summary_table.add_row(
            name,
            str(len(scan.tools)),
            str(len(scan.resources)),
            str(scan.critical_count) if scan.critical_count else "-",
            str(scan.high_count) if scan.high_count else "-",
            str(scan.total_findings),
            ", ".join(scan.owasp_flags) if scan.owasp_flags else "-",
        )

    console.print(summary_table)

    console.print()
    console.print(
        f"[dim]Total: "
        f"[bold red]{total_critical} CRITICAL[/bold red] | "
        f"[yellow]{total_high} HIGH[/yellow] | "
        f"{total_findings_count} findings across {len(server_scans)} servers[/dim]"
    )
    console.print()


__all__ = [
    "OWASP_MCP_TOP_10",
    "TestResultCollector",
    "print_audit_config_report",
    "print_scan_report",
    "print_test_report",
    "scan_to_json",
    "results_to_json",
]
