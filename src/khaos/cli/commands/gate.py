"""The `gate` command - CI/CD gate check with thresholds.

Checks if the last run (or specified run) meets quality thresholds.
Designed for CI/CD pipelines.

Thresholds are percentages:
- security: Minimum % of attacks defended (default: 80%)
- resilience: Minimum % recovery rate (default: 70%)

Exit codes:
- 0: All gates passed
- 1: Security threshold failed
- 2: Resilience threshold failed
- 3: Both failed

Usage:
    khaos gate                           # Check with defaults (80% security, 70% resilience)
    khaos gate --security 90             # Require 90% security
    khaos gate --resilience 85           # Require 85% resilience
    khaos gate --run run-abc123          # Check specific run
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.table import Table

from khaos.state import get_state_dir
from khaos.cli.console import console


def gate(
    run_id: str | None = typer.Option(
        None,
        "--run",
        "-r",
        help="Specific run ID to check. Defaults to last run.",
    ),
    security: int = typer.Option(
        80,
        "--security",
        "-s",
        min=0,
        max=100,
        help="Minimum % of attacks defended (default: 80%).",
    ),
    resilience: int = typer.Option(
        70,
        "--resilience",
        min=0,
        max=100,
        help="Minimum % recovery rate (default: 70%).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Fail on any warning, not just threshold breaches.",
    ),
) -> None:
    """CI/CD gate check with quality thresholds.

    Checks if the last run meets minimum quality scores.
    Returns non-zero exit code if thresholds are breached.

    Examples:

        # Check last run with default thresholds
        khaos gate

        # Custom thresholds
        khaos gate --security 90 --resilience 85

        # Check specific run
        khaos gate --run run-abc123

        # Use in CI/CD
        khaos gate --security 80 || exit 1
    """
    runs_dir = get_state_dir() / "runs"

    # Get run to check
    if run_id:
        check_run_id = run_id
    else:
        check_run_id = _get_last_run_id(runs_dir)
        if check_run_id is None:
            raise typer.BadParameter("No runs found. Run 'khaos run' first.")

    # Load run data
    try:
        run_data = _load_run_metrics(runs_dir, check_run_id)
    except FileNotFoundError:
        raise typer.BadParameter(f"Run not found: {check_run_id}")

    # Extract scores
    security_score = run_data.get("security_score")
    resilience_score = run_data.get("resilience_score")

    # Evaluate gates
    gates = {
        "security": {
            "score": security_score,
            "threshold": security,
            "passed": security_score is None or security_score >= security,
        },
        "resilience": {
            "score": resilience_score,
            "threshold": resilience,
            "passed": resilience_score is None or resilience_score >= resilience,
        },
    }

    # Determine exit code
    exit_code = 0
    if not gates["security"]["passed"]:
        exit_code |= 1
    if not gates["resilience"]["passed"]:
        exit_code |= 2

    if json_output:
        output = {
            "run_id": check_run_id,
            "passed": exit_code == 0,
            "exit_code": exit_code,
            "gates": gates,
        }
        typer.echo(json.dumps(output, indent=2))
    else:
        _print_gate_results(check_run_id, gates, exit_code)

    if exit_code != 0:
        raise typer.Exit(code=exit_code)


def _get_last_run_id(runs_dir: Path) -> str | None:
    """Get the most recent run ID."""
    if not runs_dir.exists():
        return None

    # Find most recent metrics file
    metrics_files = list(runs_dir.glob("metrics-*.json"))
    if not metrics_files:
        return None

    # Sort by modification time
    metrics_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    latest = metrics_files[0]

    # Extract run ID
    stem = latest.stem  # e.g., "metrics-run-abc123"
    if stem.startswith("metrics-"):
        return stem[8:]  # Remove "metrics-" prefix
    return None


def _load_run_metrics(runs_dir: Path, run_id: str) -> dict:
    """Load metrics for a run.

    Extracts percentage-based scores for gate checking.
    """
    metrics_path = runs_dir / f"metrics-{run_id}.json"
    if not metrics_path.exists() and not run_id.startswith("run-"):
        legacy = runs_dir / f"metrics-run-{run_id}.json"
        if legacy.exists():
            run_id = f"run-{run_id}"
            metrics_path = legacy
    if not metrics_path.exists():
        raise FileNotFoundError(f"Metrics not found for {run_id}")

    data = json.loads(metrics_path.read_text())

    # Extract scores from various possible locations
    result = {"run_id": run_id}

    # Try to find security metrics
    security = data.get("security", {})
    if "percent" in security:
        # New format: pass/fail counts with percent
        result["security_score"] = security["percent"]
        result["security_defended"] = security.get("defended", 0)
        result["security_total"] = security.get("total", 0)
    elif "security_score" in data:
        result["security_score"] = data["security_score"]
    elif "artifacts" in data:
        for artifact in data["artifacts"]:
            if artifact.get("name") == "security.score":
                result["security_score"] = artifact.get("value")
                # Try to extract counts from details
                details = artifact.get("details", {})
                result["security_defended"] = details.get("attacks_blocked", 0)
                result["security_total"] = details.get("attacks_tested", 0)
                break

    # Try to find resilience metrics
    resilience = data.get("resilience", {})
    if "recovery_component" in resilience:
        # Convert recovery component (0-1) to percentage
        result["resilience_score"] = resilience["recovery_component"] * 100
    elif "score" in resilience:
        result["resilience_score"] = resilience["score"]
    elif "resilience_score" in data:
        result["resilience_score"] = data["resilience_score"]
    elif "artifacts" in data:
        for artifact in data["artifacts"]:
            if artifact.get("name") == "resilience.score":
                result["resilience_score"] = artifact.get("value")
                break
            elif artifact.get("name") == "resilience.recovery_component":
                # Convert ratio to percentage
                result["resilience_score"] = artifact.get("value", 0) * 100
                break

    return result


def _print_gate_results(run_id: str, gates: dict, exit_code: int) -> None:
    """Print gate check results."""
    console.print(f"\n[bold]Gate Check: {run_id}[/bold]\n")

    # Results table
    table = Table()
    table.add_column("Gate", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Threshold", justify="right")
    table.add_column("Status", justify="center")

    for name, gate in gates.items():
        score = gate["score"]
        threshold = gate["threshold"]
        passed = gate["passed"]

        score_str = f"{score:.0f}" if score is not None else "N/A"
        threshold_str = f"{threshold}"

        if passed:
            status = "[bold green]PASS[/bold green]"
        else:
            status = "[bold red]FAIL[/bold red]"

        table.add_row(name.capitalize(), score_str, threshold_str, status)

    console.print(table)

    # Overall result
    if exit_code == 0:
        console.print("\n[bold green]All gates passed[/bold green]")
    else:
        console.print(f"\n[bold red]Gate check failed (exit code: {exit_code})[/bold red]")

        # Explain exit codes
        if exit_code & 1:
            console.print("[red]  Security threshold not met[/red]")
        if exit_code & 2:
            console.print("[red]  Resilience threshold not met[/red]")
