"""The ``test`` command — Run Khaos agent tests.

Discovers ``@khaostest``-decorated functions and executes them with shim
injection, agent resolution, and rich result reporting.

Usage::

    khaos test                          # auto-discover in tests/
    khaos test tests/test_security.py   # specific file
    khaos test -v                       # verbose output
    khaos test -k "resilience"          # filter by pattern
    khaos test --format junit -o results.xml
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional

import typer
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from khaos.cli.console import console

logger = logging.getLogger(__name__)


# ── Spinner frames ──────────────────────────────────────────────────

_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


# ── CLI command ─────────────────────────────────────────────────────

def test(
    paths: Optional[list[str]] = typer.Argument(
        None,
        help="Test files or directories to run (default: tests/).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including tracebacks.",
    ),
    filter_pattern: str = typer.Option(
        "",
        "--filter",
        "-k",
        help="Filter tests by name or tag pattern.",
    ),
    fail_fast: bool = typer.Option(
        False,
        "--fail-fast",
        "-x",
        help="Stop on first failure.",
    ),
    timeout: int = typer.Option(
        30000,
        "--timeout",
        help="Per-test timeout in milliseconds.",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, json, junit, markdown, or all.",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Write primary output to file (format inferred from extension).",
    ),
    json_file: Optional[Path] = typer.Option(
        None,
        "--json-file",
        help="Write JSON results to this file (in addition to primary format).",
    ),
) -> None:
    """Run Khaos agent tests.

    Auto-discovers @khaostest-decorated functions and executes them with
    fault injection, security attacks, and agent shims activated.

    Examples:

        khaos test
        khaos test tests/test_security.py
        khaos test -v -k "resilience"
        khaos test --fail-fast
        khaos test --format junit -o results.xml
        khaos test --format json
        khaos test --format all -o khaos-tests
    """
    from khaos.testing.runner import (
        DiscoveredTest,
        TestResult,
        TestSummary,
        discover_tests,
        filter_tests,
        run_tests,
    )

    # When machine-readable output goes to stdout, skip Rich display.
    skip_rich = (format != "text") and (output_file is None)

    # ── Header ──────────────────────────────────────────────────────
    if not skip_rich:
        console.print()
        header = Text()
        header.append("khaos", style="bold dodger_blue2")
        header.append(" ── ", style="dim dodger_blue2")
        header.append("agent tests", style="dim dodger_blue2")
        console.print(header)
        console.print()

    # ── Resolve paths ───────────────────────────────────────────────
    search_paths: list[Path] | None = None
    if paths:
        search_paths = [Path(p) for p in paths]
        for sp in search_paths:
            if not sp.exists():
                if not skip_rich:
                    console.print(f"[error]Path not found: {sp}[/error]")
                raise typer.Exit(code=1)

    # ── Discover ────────────────────────────────────────────────────
    if not skip_rich:
        console.print("[dim]Discovering tests...[/dim]")
    tests = discover_tests(search_paths)

    if not tests:
        if not skip_rich:
            console.print("[warning]No @khaostest tests found.[/warning]")
            console.print("[dim]Create test files with @khaostest decorators in tests/[/dim]")
        raise typer.Exit(code=0)

    # ── Filter ──────────────────────────────────────────────────────
    if filter_pattern:
        tests = filter_tests(tests, filter_pattern)
        if not tests:
            if not skip_rich:
                console.print(
                    f"[warning]No tests matching pattern {filter_pattern!r}.[/warning]"
                )
            raise typer.Exit(code=0)

    test_count = len(tests)
    agent_names = sorted({t.config.agent for t in tests if t.config.agent})

    if not skip_rich:
        agents_str = ", ".join(agent_names) if agent_names else "none"
        console.print(
            f"  [bold]{test_count}[/bold] test{'s' if test_count != 1 else ''}"
            f" across [bold]{len(agent_names) or '?'}[/bold] agent{'s' if len(agent_names) != 1 else ''}"
            f" [dim]({agents_str})[/dim]"
        )
        console.print()

    # ── Execute ─────────────────────────────────────────────────────
    if skip_rich:
        summary = _run_quiet(tests, verbose=verbose, fail_fast=fail_fast, timeout_ms=timeout)
    else:
        summary = _run_with_rich_display(tests, verbose=verbose, fail_fast=fail_fast, timeout_ms=timeout)
        _print_results(summary, verbose=verbose)

    # ── Output generation ───────────────────────────────────────────
    _output_test_results(
        summary=summary,
        format=format,
        output_file=output_file,
        json_file=json_file,
        skip_rich=skip_rich,
    )

    # ── GitHub Actions integration (best-effort) ────────────────────
    _write_github_test_outputs(summary)
    _write_github_test_summary(summary)

    # Exit code
    if summary.failed > 0:
        raise typer.Exit(code=1)


# ── Quiet execution (no Rich display) ───────────────────────────────

def _run_quiet(
    tests: list,
    *,
    verbose: bool,
    fail_fast: bool,
    timeout_ms: int,
) -> "TestSummary":
    from khaos.testing.runner import run_tests
    return run_tests(tests, verbose=verbose, fail_fast=fail_fast, timeout_ms=timeout_ms)


# ── Rich live execution ─────────────────────────────────────────────

def _run_with_rich_display(
    tests: list,
    *,
    verbose: bool,
    fail_fast: bool,
    timeout_ms: int,
) -> "TestSummary":
    """Run tests with an animated Rich Live progress display."""
    from khaos.testing.runner import DiscoveredTest, TestResult, run_tests

    completed: list[tuple[DiscoveredTest, TestResult]] = []
    frame = 0
    test_count = len(tests)
    run_start = time.perf_counter()

    def _build_progress_display() -> Table:
        nonlocal frame
        frame += 1

        grid = Table.grid(padding=(0, 2))
        grid.add_column(width=3)
        grid.add_column(width=50)
        grid.add_column(width=12)
        grid.add_column(width=10, justify="right")

        for disc_test, result in completed:
            icon = Text("\u2713", style="green") if result.passed else Text("\u2717", style="red")
            name_style = "" if result.passed else "red"
            grid.add_row(
                icon,
                Text(result.name, style=name_style),
                Text(result.agent, style="dim"),
                Text(f"{result.duration_ms:.0f}ms", style="dim"),
            )
            if not result.passed and result.error:
                grid.add_row(
                    Text(""),
                    Text(f"  {result.error}", style="red dim"),
                    Text(""),
                    Text(""),
                )

        done = len(completed)
        if done < test_count:
            current = tests[done]
            spinner = _SPINNER[frame % len(_SPINNER)]
            grid.add_row(
                Text(spinner, style="cyan"),
                Text(current.name, style="bold"),
                Text(current.config.agent, style="dim"),
                Text("...", style="dim"),
            )
            for queued in tests[done + 1:]:
                grid.add_row(
                    Text("\u00b7", style="dim"),
                    Text(queued.name, style="dim"),
                    Text(queued.config.agent, style="dim"),
                    Text("", style="dim"),
                )

        pct = done / test_count if test_count else 1.0
        bar_width = 30
        filled = int(pct * bar_width)
        empty = bar_width - filled
        elapsed_s = time.perf_counter() - run_start

        bar_line = Text()
        bar_line.append("  ")
        bar_line.append("\u2588" * filled, style="cyan" if done < test_count else "green")
        bar_line.append("\u2591" * empty, style="dim")
        bar_line.append(f"  {done}/{test_count}", style="dim")
        bar_line.append(f"  ({elapsed_s:.1f}s)", style="dim")
        grid.add_row(Text(""), bar_line, Text(""), Text(""))

        return grid

    def _on_result(disc_test: "DiscoveredTest", result: "TestResult") -> None:
        completed.append((disc_test, result))

    with Live(console=console, refresh_per_second=12, transient=True) as live:
        import threading

        summary_holder: list = []
        error_holder: list = []

        def _run() -> None:
            try:
                s = run_tests(
                    tests,
                    verbose=verbose,
                    fail_fast=fail_fast,
                    timeout_ms=timeout_ms,
                    on_result=_on_result,
                )
                summary_holder.append(s)
            except Exception as exc:
                error_holder.append(exc)

        runner_thread = threading.Thread(target=_run, daemon=True)
        runner_thread.start()

        while runner_thread.is_alive():
            live.update(_build_progress_display())
            time.sleep(0.08)

        live.update(_build_progress_display())

    if error_holder:
        console.print(f"[error]Runner error: {error_holder[0]}[/error]")
        raise typer.Exit(code=1)

    return summary_holder[0]


# ── Output generation ────────────────────────────────────────────────

def _output_test_results(
    *,
    summary: "TestSummary",
    format: str,
    output_file: Path | None,
    json_file: Path | None,
    skip_rich: bool,
) -> None:
    """Generate and output results in requested format(s)."""
    from khaos.testing.reporters import (
        TestJUnitReporter,
        TestJsonReporter,
        TestMarkdownReporter,
    )

    # Always write JSON sidecar if requested
    if json_file:
        TestJsonReporter(summary).write(json_file)
        if not skip_rich:
            console.print(f"[dim]JSON written to: {json_file}[/dim]")

    # Infer format from output_file extension when format is text
    effective_format = format
    if output_file and format == "text":
        ext = output_file.suffix.lower()
        if ext == ".xml":
            effective_format = "junit"
        elif ext == ".json":
            effective_format = "json"
        elif ext in (".md", ".markdown"):
            effective_format = "markdown"

    if effective_format == "junit":
        reporter = TestJUnitReporter(summary)
        if output_file:
            reporter.write(output_file)
            if not skip_rich:
                console.print(f"[dim]JUnit XML written to: {output_file}[/dim]")
        else:
            print(reporter.generate())

    elif effective_format == "markdown":
        reporter = TestMarkdownReporter(summary)
        if output_file:
            reporter.write(output_file)
            if not skip_rich:
                console.print(f"[dim]Markdown written to: {output_file}[/dim]")
        else:
            print(reporter.generate())

    elif effective_format == "json":
        reporter = TestJsonReporter(summary)
        if output_file:
            reporter.write(output_file)
            if not skip_rich:
                console.print(f"[dim]JSON written to: {output_file}[/dim]")
        else:
            print(reporter.generate())

    elif effective_format == "all":
        if output_file:
            base = output_file.stem
            parent = output_file.parent
            parent.mkdir(parents=True, exist_ok=True)
            TestJUnitReporter(summary).write(parent / f"{base}.xml")
            TestJsonReporter(summary).write(parent / f"{base}.json")
            TestMarkdownReporter(summary).write(parent / f"{base}.md")
            if not skip_rich:
                console.print(f"[dim]Reports written to: {parent}/{base}.[xml,json,md][/dim]")
        else:
            # Print JSON to stdout when --format all with no output file
            print(TestJsonReporter(summary).generate())


# ── GitHub Actions integration ───────────────────────────────────────

def _write_github_test_outputs(summary: "TestSummary") -> None:
    """Write test outputs to $GITHUB_OUTPUT (best-effort)."""
    output_path_raw = os.environ.get("GITHUB_OUTPUT")
    if not output_path_raw:
        return
    try:
        path = Path(output_path_raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        verdict = "pass" if summary.failed == 0 else "fail"
        with path.open("a", encoding="utf-8") as f:
            f.write(f"total={summary.total}\n")
            f.write(f"passed={summary.passed}\n")
            f.write(f"failed={summary.failed}\n")
            f.write(f"verdict={verdict}\n")
    except Exception:
        logger.debug("Failed to write GitHub test outputs", exc_info=True)


def _write_github_test_summary(summary: "TestSummary") -> None:
    """Write Markdown to $GITHUB_STEP_SUMMARY (best-effort)."""
    summary_path_raw = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path_raw:
        return
    try:
        from khaos.testing.reporters import TestMarkdownReporter

        path = Path(summary_path_raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        md = TestMarkdownReporter(summary).generate()
        with path.open("a", encoding="utf-8") as f:
            f.write(md + "\n")
    except Exception:
        logger.debug("Failed to write GitHub step summary", exc_info=True)


# ── Result display ──────────────────────────────────────────────────

def _print_results(summary: "TestSummary", *, verbose: bool = False) -> None:
    """Render final test results as a Rich table with a summary panel."""
    table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("", width=3, justify="center")
    table.add_column("Test", ratio=3)
    table.add_column("Agent", ratio=1, style="dim")
    table.add_column("Time", width=10, justify="right", style="dim")

    for r in summary.results:
        icon = "[green]\u2713[/green]" if r.passed else "[red]\u2717[/red]"
        name_style = "" if r.passed else "red"
        table.add_row(
            icon,
            f"[{name_style}]{r.name}[/{name_style}]" if name_style else r.name,
            r.agent,
            f"{r.duration_ms:.0f}ms",
        )
        if not r.passed and r.error:
            table.add_row("", f"  [dim red]{r.error}[/dim red]", "", "")
            if verbose and r.traceback:
                for line in r.traceback.strip().splitlines():
                    table.add_row("", f"  [dim]{line}[/dim]", "", "")

    console.print(table)
    console.print()

    # Summary panel
    total_time = summary.duration_ms
    if total_time >= 1000:
        time_str = f"{total_time / 1000:.1f}s"
    else:
        time_str = f"{total_time:.0f}ms"

    all_passed = summary.failed == 0

    parts: list[str] = []
    if summary.passed > 0:
        parts.append(f"[green]{summary.passed} passed[/green]")
    if summary.failed > 0:
        parts.append(f"[red]{summary.failed} failed[/red]")

    status_line = f"{', '.join(parts)}  [dim]\u00b7  {summary.total} total  \u00b7  {time_str}[/dim]"

    if all_passed:
        panel = Panel(
            status_line,
            title="[bold green]ALL TESTS PASSED[/bold green]",
            border_style="green",
            padding=(0, 2),
        )
    else:
        panel = Panel(
            status_line,
            title=f"[bold red]{summary.failed} TEST{'S' if summary.failed != 1 else ''} FAILED[/bold red]",
            border_style="red",
            padding=(0, 2),
        )

    console.print(panel)
    console.print()
