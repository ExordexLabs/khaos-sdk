"""Export local run artifacts (trace/metrics/stderr) into a single JSON bundle."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from khaos.state import get_state_dir
from khaos.cli.console import console


def export(
    run_id: str = typer.Argument(..., help="Run ID, name, or path (same resolver as `khaos compare`)."),
    out: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help="Output path for exported JSON (defaults to stdout).",
    ),
    include_stderr: bool = typer.Option(
        True,
        "--stderr/--no-stderr",
        help="Include stderr log contents when present.",
    ),
) -> None:
    """Export a run's local artifacts as a single JSON blob.

    Includes:
    - trace: contents of `trace-<run_id>.json` when present
    - metrics: contents of `metrics-<run_id>.json` when present
    - stderr: text of `stderr-<run_id>.log` when present (optional)
    """

    from khaos.cli.commands.compare import _resolve_run as _resolve_run_id  # reuse resolver

    resolved = _resolve_run_id(run_id)
    runs_dir = get_state_dir() / "runs"
    trace_path = runs_dir / f"trace-{resolved}.json"
    metrics_path = runs_dir / f"metrics-{resolved}.json"
    stderr_path = runs_dir / f"stderr-{resolved}.log"

    if not trace_path.exists() and not metrics_path.exists() and not stderr_path.exists():
        raise typer.BadParameter(f"No artifacts found for run '{resolved}'.")

    payload: dict = {"run_id": resolved}
    if trace_path.exists():
        payload["trace"] = json.loads(trace_path.read_text(encoding="utf-8"))
    if metrics_path.exists():
        payload["metrics"] = json.loads(metrics_path.read_text(encoding="utf-8"))
    if include_stderr and stderr_path.exists():
        payload["stderr"] = stderr_path.read_text(encoding="utf-8", errors="replace")

    output = json.dumps(payload, indent=2, ensure_ascii=False)
    if out is None:
        typer.echo(output)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(output, encoding="utf-8")
    console.print(f"[green]Exported[/green] {resolved} → {out}")

