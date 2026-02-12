"""The `compare` command - Compare two agent runs.

Compares metrics, costs, and behavior between two runs to identify
regressions or improvements.

Usage:
    khaos compare                            # List recent runs (pick two to compare)
    khaos compare my-baseline my-candidate   # By name
    khaos compare run-abc123 run-def456      # By ID
    khaos compare abc123 --baseline          # Partial ID + stored baseline
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.table import Table

from khaos.cloud.queue import resolve_run_id, list_run_metadata, get_run_metadata
from khaos.evaluator import ComparisonEvaluator
from khaos.state import get_state_dir
from khaos.cli.console import console


def compare(
    run_a: str | None = typer.Argument(
        None,
        help="First run (name or ID). If omitted, shows recent runs.",
    ),
    run_b: str | None = typer.Argument(
        None,
        help="Second run (name or ID). The baseline to compare against.",
    ),
    baseline: bool = typer.Option(
        False,
        "--baseline",
        "-b",
        help="Compare against the stored baseline run.",
    ),
    recent: bool = typer.Option(
        False,
        "--recent",
        "-r",
        help="Show recent runs to select from for comparison.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON.",
    ),
    show_cost: bool = typer.Option(
        False,
        "--cost",
        "-c",
        help="Show cost comparison and savings projections.",
    ),
    monthly_runs: int = typer.Option(
        10000,
        "--monthly-runs",
        help="Assumed monthly run volume for cost projections.",
    ),
    limit: int = typer.Option(
        10,
        "--limit",
        "-l",
        help="Number of runs to show when listing (default: 10).",
    ),
) -> None:
    """Compare two agent runs and show differences.

    When called without arguments, shows recent runs so you can pick
    two to compare. Use --name with 'khaos run' to name runs for easy reference.

    Examples:

        # Show recent runs with easy-to-copy names
        khaos compare --recent

        # Compare by name
        khaos compare my-baseline my-candidate

        # Compare by ID
        khaos compare run-abc123 run-def456

        # Compare against stored baseline
        khaos compare my-candidate --baseline

        # Show cost comparison
        khaos compare baseline candidate --cost
    """
    # If --recent flag or no runs specified, list recent runs
    if recent or run_a is None:
        _list_runs_for_comparison(limit=limit, json_output=json_output)
        return

    runs_dir = get_state_dir() / "runs"

    # Resolve run IDs (supports names, partial IDs, full IDs)
    candidate_id = _resolve_run(run_a)

    if baseline and run_b is None:
        baseline_id = _get_baseline_run_id()
        if baseline_id is None:
            raise typer.BadParameter("No baseline run found. Run 'khaos run --baseline' first.")
    elif run_b:
        baseline_id = _resolve_run(run_b)
    else:
        console.print("[yellow]Missing second run to compare against.[/yellow]")
        console.print("\n[dim]Usage: khaos compare <run1> <run2>[/dim]")
        console.print("[dim]   or: khaos compare <run1> --baseline[/dim]")
        console.print("\n[dim]Run 'khaos compare' with no args to see recent runs.[/dim]")
        raise typer.Exit(code=1)

    # Load run data
    try:
        candidate_data = _load_run_data(runs_dir, candidate_id)
        baseline_data = _load_run_data(runs_dir, baseline_id)
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc))

    # Compare runs
    evaluator = ComparisonEvaluator()
    report = evaluator.compare(baseline_data, candidate_data)

    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        _print_comparison(
            baseline_id=baseline_id,
            candidate_id=candidate_id,
            report=report,
            show_cost=show_cost,
            monthly_runs=monthly_runs,
        )


def _resolve_run(name_or_id: str) -> str:
    """Resolve a run name or ID to a full run ID.

    Accepts:
    - User-provided name: my-baseline
    - Full run ID: run-abc123... or observe-abc123...
    - Partial ID: abc123 (first 6+ chars)
    - File path: ./trace-run-abc123.json
    """
    name_or_id = name_or_id.strip()

    # Try file path first
    path = Path(name_or_id)
    if path.exists():
        stem = path.stem
        if stem.startswith("trace-") or stem.startswith("metrics-"):
            return stem.split("-", 1)[1]
        return stem

    # Try resolving via metadata (supports names and partial IDs)
    resolved = resolve_run_id(name_or_id)
    if resolved:
        return resolved

    # Fallback: assume it's a run ID
    if name_or_id.startswith("run-") or name_or_id.startswith("observe-"):
        return name_or_id

    # Try with run- prefix
    return f"run-{name_or_id}"


def _list_runs_for_comparison(limit: int, json_output: bool) -> None:
    """List recent runs to help user pick runs to compare."""
    all_metadata = list_run_metadata(limit=limit)

    if json_output:
        output = [
            {
                "run_id": m.run_id,
                "name": m.name,
                "agent": m.agent_name,
                "created_at": m.created_at,
                "security_score": m.security_score,
                "resilience_score": m.resilience_score,
                "status": m.status,
            }
            for m in all_metadata
        ]
        typer.echo(json.dumps(output, indent=2))
        return

    if not all_metadata:
        console.print("[yellow]No runs found.[/yellow]")
        console.print("[dim]Run 'khaos run agent.py' to create your first run.[/dim]")
        return

    console.print("\n[bold cyan]Recent Runs[/bold cyan]")
    console.print("[dim]Copy a name/ID from the table below to compare runs[/dim]\n")

    # Build table with index numbers
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Name / ID", style="cyan", no_wrap=True, min_width=12)
    table.add_column("Agent", style="white", max_width=20, overflow="ellipsis")
    table.add_column("Time", style="dim", width=10)
    table.add_column("Sec", justify="right", width=5)
    table.add_column("Res", justify="right", width=5)
    table.add_column("", width=4)

    for idx, m in enumerate(all_metadata, 1):
        # Format name/ID - show what user should type to identify this run
        if m.name:
            # Named runs - user can type the name
            name_display = f"[bold white]{m.name}[/bold white]"
        else:
            # Unnamed runs - show short ID user can copy
            short_id = m.run_id.replace("observe-", "").replace("run-", "")[:8]
            name_display = f"[dim]{short_id}[/dim]"

        # Format time as relative
        time_display = _format_relative_time(m.created_at)

        # Format scores (compact)
        security_display = _format_score_compact(m.security_score)
        resilience_display = _format_score_compact(m.resilience_score)

        # Format status
        if m.status == "completed":
            status_display = "[green]ok[/green]"
        elif m.status == "failed":
            status_display = "[red]fail[/red]"
        else:
            status_display = "[yellow]...[/yellow]"

        table.add_row(
            str(idx),
            name_display,
            m.agent_name or "-",
            time_display,
            security_display,
            resilience_display,
            status_display,
        )

    console.print(table)

    # Build example command using actual run names/IDs
    run1 = _get_run_identifier(all_metadata[0]) if len(all_metadata) > 0 else "run1"
    run2 = _get_run_identifier(all_metadata[1]) if len(all_metadata) > 1 else "run2"

    console.print("\n[bold]Usage:[/bold]")
    console.print(f"  [dim]$[/dim] khaos compare [cyan]{run1}[/cyan] [cyan]{run2}[/cyan]")

    if any(m.name for m in all_metadata):
        console.print("\n[dim]Tip: Named runs are easier to compare. Use --name with 'khaos run'[/dim]")
    else:
        console.print("\n[dim]Tip: Name your runs for easier comparison: khaos run agent.py --name my-test[/dim]")


def _get_run_identifier(m) -> str:
    """Get the identifier to use for a run (name or short ID)."""
    if m.name:
        return m.name
    return m.run_id.replace("observe-", "").replace("run-", "")[:8]


def _format_score_compact(score: float | None) -> str:
    """Format a score with color (compact version without %)."""
    if score is None:
        return "[dim]-[/dim]"

    if score >= 90:
        return f"[green]{score:.0f}[/green]"
    elif score >= 70:
        return f"[yellow]{score:.0f}[/yellow]"
    else:
        return f"[red]{score:.0f}[/red]"


def _format_relative_time(iso_timestamp: str) -> str:
    """Format an ISO timestamp as relative time."""
    try:
        if iso_timestamp.endswith("Z"):
            dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(iso_timestamp)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        delta = now - dt
        seconds = delta.total_seconds()

        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m ago"
        elif seconds < 86400:
            return f"{int(seconds / 3600)}h ago"
        elif seconds < 604800:
            return f"{int(seconds / 86400)}d ago"
        else:
            return dt.strftime("%b %d")
    except (ValueError, TypeError):
        return iso_timestamp[:10] if iso_timestamp else "unknown"


def _format_score(score: float | None) -> str:
    """Format a score with color."""
    if score is None:
        return "[dim]—[/dim]"

    if score >= 90:
        return f"[green]{score:.0f}%[/green]"
    elif score >= 70:
        return f"[yellow]{score:.0f}%[/yellow]"
    else:
        return f"[red]{score:.0f}%[/red]"


def _get_baseline_run_id() -> str | None:
    """Get the stored baseline run ID."""
    baseline_path = get_state_dir() / "baseline_run_id"
    if baseline_path.exists():
        return baseline_path.read_text().strip()
    return None


def _load_run_data(runs_dir: Path, run_id: str) -> dict:
    """Load run data from disk."""
    metrics_path = runs_dir / f"metrics-{run_id}.json"
    trace_path = runs_dir / f"trace-{run_id}.json"

    if not metrics_path.exists() and not trace_path.exists():
        raise FileNotFoundError(f"Run data not found for: {run_id}")

    data = {"run_id": run_id}

    if metrics_path.exists():
        data["metrics"] = json.loads(metrics_path.read_text())

    if trace_path.exists():
        data["trace"] = json.loads(trace_path.read_text())

    return data


def _print_comparison(
    baseline_id: str,
    candidate_id: str,
    report,
    show_cost: bool,
    monthly_runs: int,
) -> None:
    """Print comparison report in a clean, interpretable format."""
    from khaos.comparison import ComparisonReport

    # Header
    console.print("\n[bold cyan]Comparison Report[/bold cyan]")
    console.print(f"[dim]Baseline:[/dim]  {_short_run_id(baseline_id)}")
    console.print(f"[dim]Candidate:[/dim] {_short_run_id(candidate_id)}")

    # Summary/verdict
    if report.summary:
        console.print(f"\n[bold]{report.summary}[/bold]")

    # Determine overall verdict based on trends
    has_regressions = _has_regressions(report)
    has_improvements = _has_improvements(report)

    if has_regressions:
        console.print("\n[bold red]REGRESSION DETECTED[/bold red]")
    elif has_improvements:
        console.print("\n[bold green]IMPROVED[/bold green]")
    else:
        console.print("\n[bold]NO SIGNIFICANT CHANGES[/bold]")

    # Structural metrics (cost, latency, tool calls)
    console.print("\n[bold]Performance[/bold]")
    _print_metric_row(report.structural.cost, "Cost", "$", precision=4)
    _print_metric_row(report.structural.latency, "Latency", "s", precision=2)
    _print_metric_row(report.structural.tool_calls, "Tool Calls", "", precision=0)

    # Resilience metrics
    console.print("\n[bold]Resilience[/bold]")
    _print_metric_row(report.resilience.resilience_score, "Overall", "", precision=1)
    _print_metric_row(report.resilience.goal_score, "Goal", "", precision=1)
    _print_metric_row(report.resilience.recovery_score, "Recovery", "", precision=1)
    _print_metric_row(report.resilience.stability_score, "Stability", "", precision=1)

    # Security metrics (if present)
    if report.security:
        console.print("\n[bold]Security[/bold]")
        _print_metric_row(report.security.security_score, "Overall", "", precision=1)
        _print_metric_row(report.security.prompt_injection_defense, "Prompt Injection", "", precision=1)
        _print_metric_row(report.security.tool_validation_score, "Tool Validation", "", precision=1)
        _print_metric_row(report.security.leakage_prevention_score, "Leakage Prevention", "", precision=1)

        # Show attack stats
        if report.security.attacks_tested > 0:
            baseline_blocked = report.security.attacks_blocked_baseline
            candidate_blocked = report.security.attacks_blocked_candidate
            total = report.security.attacks_tested
            console.print(f"  Attacks blocked: {baseline_blocked}/{total} -> {candidate_blocked}/{total}")

        # Show new/fixed vulnerabilities
        if report.security.new_vulnerabilities:
            console.print(f"  [red]New vulnerabilities: {', '.join(report.security.new_vulnerabilities)}[/red]")
        if report.security.fixed_vulnerabilities:
            console.print(f"  [green]Fixed vulnerabilities: {', '.join(report.security.fixed_vulnerabilities)}[/green]")

    # Functional comparison (output similarity)
    console.print("\n[bold]Functional[/bold]")
    similarity_pct = report.functional.output_similarity * 100
    if similarity_pct >= 95:
        sim_color = "green"
    elif similarity_pct >= 80:
        sim_color = "yellow"
    else:
        sim_color = "red"
    console.print(f"  Output similarity: [{sim_color}]{similarity_pct:.1f}%[/{sim_color}]")

    if report.functional.divergent_outputs:
        console.print(f"  [dim]Divergent outputs: {len(report.functional.divergent_outputs)}[/dim]")

    # Cost analysis (if requested)
    if show_cost:
        _print_cost_analysis(report.structural.cost, monthly_runs)


def _short_run_id(run_id: str) -> str:
    """Shorten a run ID for display."""
    if run_id.startswith("run-"):
        return run_id[:12] + "..."
    if run_id.startswith("observe-"):
        return run_id[:16] + "..."
    return run_id


def _has_regressions(report) -> bool:
    """Check if the report has any regressions."""
    metrics = [
        report.structural.cost,
        report.structural.latency,
        report.structural.tool_calls,
        report.resilience.resilience_score,
        report.resilience.goal_score,
        report.resilience.recovery_score,
        report.resilience.stability_score,
    ]
    if report.security:
        metrics.append(report.security.security_score)
    return any(m.trend == "regressed" for m in metrics)


def _has_improvements(report) -> bool:
    """Check if the report has any improvements."""
    metrics = [
        report.structural.cost,
        report.structural.latency,
        report.structural.tool_calls,
        report.resilience.resilience_score,
        report.resilience.goal_score,
        report.resilience.recovery_score,
        report.resilience.stability_score,
    ]
    if report.security:
        metrics.append(report.security.security_score)
    return any(m.trend == "improved" for m in metrics)


def _print_metric_row(metric, label: str, unit: str, precision: int = 2) -> None:
    """Print a single metric comparison row."""
    baseline = metric.baseline_value
    candidate = metric.candidate_value
    delta = metric.absolute_delta
    trend = metric.trend

    # Format values
    if baseline is None:
        base_str = "-"
    elif unit == "$":
        base_str = f"${baseline:.{precision}f}"
    elif unit:
        base_str = f"{baseline:.{precision}f}{unit}"
    else:
        base_str = f"{baseline:.{precision}f}"

    if candidate is None:
        cand_str = "-"
    elif unit == "$":
        cand_str = f"${candidate:.{precision}f}"
    elif unit:
        cand_str = f"{candidate:.{precision}f}{unit}"
    else:
        cand_str = f"{candidate:.{precision}f}"

    # Format delta with trend indicator
    if delta is None:
        delta_str = ""
    elif abs(delta) < 0.0001:
        delta_str = "[dim](no change)[/dim]"
    else:
        sign = "+" if delta > 0 else ""
        if trend == "improved":
            delta_str = f"[green]({sign}{delta:.{precision}f})[/green]"
        elif trend == "regressed":
            delta_str = f"[red]({sign}{delta:.{precision}f})[/red]"
        else:
            delta_str = f"[dim]({sign}{delta:.{precision}f})[/dim]"

    # Trend indicator
    if trend == "improved":
        indicator = "[green]improved[/green]"
    elif trend == "regressed":
        indicator = "[red]regressed[/red]"
    elif trend == "neutral":
        indicator = "[dim]same[/dim]"
    else:
        indicator = ""

    # Build output line
    console.print(f"  {label + ':':<18} {base_str:>10} -> {cand_str:<10} {delta_str} {indicator}")


def _print_cost_analysis(cost_metric, monthly_runs: int) -> None:
    """Print detailed cost analysis."""
    baseline = cost_metric.baseline_value
    candidate = cost_metric.candidate_value

    if baseline is None or candidate is None:
        return

    delta = candidate - baseline

    console.print("\n[bold]Cost Analysis[/bold]")
    console.print(f"  Baseline:  ${baseline:.4f}/run")
    console.print(f"  Candidate: ${candidate:.4f}/run")

    if abs(delta) < 0.0001:
        console.print("  [dim]No significant cost change[/dim]")
    elif delta < 0:
        savings_monthly = abs(delta) * monthly_runs
        savings_annual = savings_monthly * 12
        console.print(f"  [green]Savings: ${abs(delta):.4f}/run[/green]")
        console.print(f"  [green]Monthly savings ({monthly_runs:,} runs): ${savings_monthly:,.2f}[/green]")
        console.print(f"  [green]Annual savings: ${savings_annual:,.2f}[/green]")
    else:
        increase_monthly = delta * monthly_runs
        increase_annual = increase_monthly * 12
        console.print(f"  [red]Increase: ${delta:.4f}/run[/red]")
        console.print(f"  [red]Monthly increase ({monthly_runs:,} runs): ${increase_monthly:,.2f}[/red]")
        console.print(f"  [red]Annual increase: ${increase_annual:,.2f}[/red]")
