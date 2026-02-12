"""Shared footer for console output: dashboard URL + export/artifacts."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from khaos.cloud.links import dashboard_evaluation_url
from khaos.cloud.config import load_cloud_config


def print_run_footer(
    console: Console,
    *,
    run_id: str,
    name: str | None = None,
    pack_name: str | None = None,
    scenario_identifier: str | None = None,
    agent_name: str | None = None,
    agent_version: str | None = None,
    trace_path: Path | None = None,
    metrics_path: Path | None = None,
    stderr_path: Path | None = None,
) -> None:
    if not run_id:
        return

    config = load_cloud_config()
    url = dashboard_evaluation_url(
        config,
        run_id=run_id,
        name=name,
        pack_name=pack_name,
        scenario_identifier=scenario_identifier,
        agent_name=agent_name,
        agent_version=agent_version,
    )

    console.print()
    console.print("[bold]Next[/bold]")
    if url:
        console.print(f"  [dim]View in dashboard:[/dim] {url}")
    else:
        console.print("  [dim]View in dashboard:[/dim] run `khaos sync --login` then `khaos sync`")
    console.print(f"  [dim]Export artifacts:[/dim] [bold]khaos export {run_id} --out {run_id}.json[/bold]")

    existing: list[Path] = []
    for candidate in (trace_path, metrics_path, stderr_path):
        if candidate is None:
            continue
        try:
            if candidate.exists():
                existing.append(candidate)
        except OSError:
            continue

    if existing:
        console.print()
        console.print("[dim]Artifacts:[/dim]")
        for path in existing:
            console.print(f"  [dim]• {path}[/dim]")

