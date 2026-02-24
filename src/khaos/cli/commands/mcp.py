"""CLI commands for MCP server security testing.

Provides ``khaos mcp`` subcommands for scanning, testing, and auditing
MCP servers for security vulnerabilities.

Usage:
    khaos mcp scan "npx @modelcontextprotocol/server-filesystem /tmp"
    khaos mcp test "npx @modelcontextprotocol/server-filesystem /tmp"
    khaos mcp test <server> --category input-validation
    khaos mcp audit-config
    khaos mcp audit-config ~/Library/Application\\ Support/Claude/claude_desktop_config.json
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from khaos.evaluator.mcp.client import (
    MCPServerSpec,
    MCPTestClient,
    parse_server_spec,
    spec_from_config,
)
from khaos.evaluator.mcp.scanner import scan_server, ScanResult
from khaos.evaluator.mcp.fuzzer import generate_fuzz_cases_for_tools
from khaos.evaluator.mcp.analyzer import analyze_tool_response
from khaos.evaluator.mcp.report import (
    TestResultCollector,
    print_audit_config_report,
    print_scan_report,
    print_test_report,
    scan_to_json,
    results_to_json,
)
from khaos.mcp.config import (
    MCPConfigError,
    detect_claude_desktop_config,
    parse_claude_desktop_config,
)


mcp_app = typer.Typer(
    help="MCP server security testing.",
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_async(coro: Any) -> Any:
    """Run an async coroutine in the current or new event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _parse_spec(server: str) -> MCPServerSpec:
    """Parse a server string into an MCPServerSpec, handling errors."""
    try:
        return parse_server_spec(server)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# khaos mcp scan
# ---------------------------------------------------------------------------

@mcp_app.command("scan")
def scan(
    server: str = typer.Argument(
        ...,
        help='MCP server to scan. Command string or URL. '
             'Example: "npx @modelcontextprotocol/server-filesystem /tmp"',
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results as JSON.",
    ),
) -> None:
    """Connect to an MCP server, enumerate tools/resources, and assess risk.

    This performs static analysis on tool schemas without calling any tools.

    Examples:

        khaos mcp scan "npx @modelcontextprotocol/server-filesystem /tmp"

        khaos mcp scan "python my_server.py"

        khaos mcp scan http://localhost:3001/sse
    """
    console = Console()
    spec = _parse_spec(server)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Scanning {spec.name}...", total=None)
        try:
            result = _run_async(scan_server(spec))
        except Exception as exc:
            console.print(f"\n[bold red]Error:[/bold red] Failed to connect to server: {exc}")
            raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(scan_to_json(result), indent=2))
    else:
        print_scan_report(result, console)


# ---------------------------------------------------------------------------
# khaos mcp test
# ---------------------------------------------------------------------------

@mcp_app.command("test")
def test(
    server: str = typer.Argument(
        ...,
        help='MCP server to test. Command string or URL.',
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter fuzz cases by attack category (e.g., path-traversal, sql-injection).",
    ),
    owasp_id: str | None = typer.Option(
        None,
        "--owasp-id",
        help="Filter by OWASP MCP ID (e.g., MCP01, MCP05).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results as JSON.",
    ),
    max_cases: int | None = typer.Option(
        None,
        "--max-cases",
        "-n",
        help="Maximum number of fuzz cases to run.",
    ),
    timeout: float = typer.Option(
        30.0,
        "--timeout",
        help="Timeout in seconds for each tool call.",
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Enable model-in-the-loop testing (requires OPENAI_API_KEY or --llm-api-key).",
    ),
    llm_model: str = typer.Option(
        "gpt-4o-mini",
        "--llm-model",
        help="Model for MITL testing.",
    ),
    llm_api_key: str | None = typer.Option(
        None,
        "--llm-api-key",
        help="API key for MITL testing (defaults to OPENAI_API_KEY env).",
    ),
) -> None:
    """Run security tests against an MCP server (direct mode).

    Connects to the server, discovers tools, generates adversarial inputs
    based on tool schemas, and analyzes responses for vulnerabilities.

    This is direct-mode testing — no LLM needed, zero API cost.

    Examples:

        khaos mcp test "npx @modelcontextprotocol/server-filesystem /tmp"

        khaos mcp test <server> --category path-traversal

        khaos mcp test <server> --json

        khaos mcp test <server> --max-cases 50
    """
    console = Console()
    spec = _parse_spec(server)

    async def _run_tests() -> tuple[ScanResult, TestResultCollector]:
        # Phase 1: Scan
        scan_result = await scan_server(spec)

        # Phase 2: Generate fuzz cases
        fuzz_cases = generate_fuzz_cases_for_tools(scan_result.tools)

        # Apply filters
        if category:
            category_lower = category.lower()
            fuzz_cases = [c for c in fuzz_cases if category_lower in c.attack_category.lower()]

        if owasp_id:
            owasp_upper = owasp_id.upper()
            fuzz_cases = [c for c in fuzz_cases if c.owasp_id == owasp_upper]

        if max_cases is not None and max_cases > 0:
            fuzz_cases = fuzz_cases[:max_cases]

        # Phase 3: Execute fuzz cases
        collector = TestResultCollector()
        async with MCPTestClient() as client:
            await client.connect(spec)

            for case in fuzz_cases:
                try:
                    result = await asyncio.wait_for(
                        client.call_tool(case.tool_name, case.arguments),
                        timeout=timeout,
                    )
                    analysis = analyze_tool_response(case, result)
                except asyncio.TimeoutError:
                    from khaos.evaluator.mcp.analyzer import AnalysisResult
                    analysis = AnalysisResult(classification="error")
                except Exception:
                    from khaos.evaluator.mcp.analyzer import AnalysisResult
                    analysis = AnalysisResult(classification="error")

                collector.add(case, analysis)

        # Phase 4: MITL testing (if enabled)
        if llm:
            from khaos.evaluator.mcp.mitl import MITLConfig, run_mitl_suite
            mitl_config = MITLConfig(
                model=llm_model,
                api_key=llm_api_key,
            )
            mitl_results = await run_mitl_suite(
                scan_result.tools,
                mitl_config,
                owasp_filter=owasp_id,
                max_cases=max_cases,
            )
            for mitl_result in mitl_results:
                collector.add_mitl(mitl_result)

        return scan_result, collector

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Testing {spec.name}...", total=None)
        try:
            scan_result, collector = _run_async(_run_tests())
        except Exception as exc:
            console.print(f"\n[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if json_output:
        typer.echo(json.dumps(results_to_json(spec.name, collector, scan=scan_result), indent=2))
    else:
        print_test_report(spec.name, scan_result, collector, console)


# ---------------------------------------------------------------------------
# khaos mcp audit-config
# ---------------------------------------------------------------------------

@mcp_app.command("audit-config")
def audit_config(
    config_path: str | None = typer.Argument(
        None,
        help="Path to Claude Desktop config. Auto-detects if not provided.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results as JSON.",
    ),
) -> None:
    """Audit all MCP servers in a Claude Desktop config file.

    Auto-detects the Claude Desktop configuration file location on
    macOS, Linux, and Windows. Connects to each server, scans for risks.

    Examples:

        khaos mcp audit-config

        khaos mcp audit-config ~/Library/Application\\ Support/Claude/claude_desktop_config.json

        khaos mcp audit-config --json
    """
    console = Console()

    # Parse config
    try:
        path = Path(config_path) if config_path else None
        servers = parse_claude_desktop_config(path)
    except MCPConfigError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(1)

    if not servers:
        console.print("[yellow]No MCP servers found in config.[/yellow]")
        raise typer.Exit(0)

    resolved_path = config_path or str(detect_claude_desktop_config() or "auto-detected")

    console.print(f"\n[dim]Found {len(servers)} server(s) in config.[/dim]")

    # Scan each server
    async def _scan_all() -> dict[str, ScanResult]:
        results: dict[str, ScanResult] = {}
        for name, config in servers.items():
            spec = spec_from_config(name, config)
            try:
                result = await scan_server(spec)
                results[name] = result
            except Exception as exc:
                console.print(f"[yellow]Warning: Could not scan '{name}': {exc}[/yellow]")
        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Auditing MCP servers...", total=None)
        try:
            server_scans = _run_async(_scan_all())
        except Exception as exc:
            console.print(f"\n[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    if json_output:
        output = {
            "config_path": resolved_path,
            "servers": {
                name: scan_to_json(scan)
                for name, scan in server_scans.items()
            },
        }
        typer.echo(json.dumps(output, indent=2))
    else:
        print_audit_config_report(resolved_path, server_scans, console)


__all__ = ["mcp_app"]
