"""Artifacts command - show local artifact paths for a run."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from khaos.state import get_state_dir
from khaos.cli.console import console


def artifacts(
    run_id: str = typer.Argument(..., help="Run ID, name, or path (same resolver as `khaos compare`)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Print local artifact paths for a run (trace/metrics/stderr)."""

    from khaos.cli.commands.compare import _resolve_run as _resolve_run_id  # reuse resolver

    resolved = _resolve_run_id(run_id)
    runs_dir = get_state_dir() / "runs"
    trace_path = runs_dir / f"trace-{resolved}.json"
    metrics_path = runs_dir / f"metrics-{resolved}.json"
    stderr_path = runs_dir / f"stderr-{resolved}.log"
    llm_events_path = runs_dir / f"llm-events-{resolved}.jsonl"

    paths = {
        "trace": str(trace_path) if trace_path.exists() else None,
        "metrics": str(metrics_path) if metrics_path.exists() else None,
        "stderr": str(stderr_path) if stderr_path.exists() else None,
        "llm_events": str(llm_events_path) if llm_events_path.exists() else None,
    }
    if json_output:
        typer.echo(json.dumps({"run_id": resolved, "artifacts": paths}, indent=2))
        return

    console.print(f"[bold]Run[/bold] {resolved}")
    console.print()
    console.print("[bold]Artifacts[/bold]")
    any_found = False
    for key, value in paths.items():
        if value:
            any_found = True
            console.print(f"  [dim]{key}:[/dim] {value}")
    if not any_found:
        console.print("  [yellow]No artifacts found.[/yellow]")
        console.print("  [dim]If this was a pack run, re-run with --sync or use the latest CLI which persists artifacts by default.[/dim]")

