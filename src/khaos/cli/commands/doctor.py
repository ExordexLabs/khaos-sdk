"""Doctor command - quick diagnostics for common CLI/cloud issues."""

from __future__ import annotations

import time

import typer
from rich.table import Table

from khaos.cloud import load_cloud_config
from khaos.cloud import queue as sync_queue
from khaos.cloud.config import DEFAULT_CLOUD_CONFIG_PATH
from khaos.state import get_state_dir
from khaos.cli.console import console


def doctor(
    ping_api: bool = typer.Option(
        True,
        "--ping-api/--no-ping-api",
        help="Ping the configured API health endpoints.",
    ),
    timeout: float = typer.Option(
        2.0,
        "--timeout",
        help="Timeout (seconds) for health pings.",
    ),
) -> None:
    """Diagnose common issues with local runs, sync, and cloud config."""

    config = load_cloud_config()
    state_dir = get_state_dir()
    runs_dir = state_dir / "runs"

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Check", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")

    def ok(check: str, details: str = "") -> None:
        table.add_row(check, "[green]OK[/green]", details)

    def warn(check: str, details: str) -> None:
        table.add_row(check, "[yellow]WARN[/yellow]", details)

    def fail(check: str, details: str) -> None:
        table.add_row(check, "[red]FAIL[/red]", details)

    ok("State dir", str(state_dir))
    ok("Runs dir", str(runs_dir) if runs_dir.exists() else f"{runs_dir} (missing)")
    ok("Cloud config", str(DEFAULT_CLOUD_CONFIG_PATH) if DEFAULT_CLOUD_CONFIG_PATH.exists() else "not created yet")

    logged_in = bool(config.token and config.project_id)
    if logged_in:
        ok("Cloud login", f"project={config.project_id} token={config.masked_token()}")
    else:
        warn("Cloud login", "not logged in (run `khaos sync --login`)")

    pending = sync_queue.list_jobs()
    if pending:
        warn("Sync queue", f"{len(pending)} pending job(s) (run `khaos sync`)")
    else:
        ok("Sync queue", "empty")

    if ping_api:
        try:
            import httpx

            api_url = config.api_url.rstrip("/")
            for path in ("/health/live", "/health/ready"):
                start = time.perf_counter()
                resp = httpx.get(f"{api_url}{path}", timeout=timeout)
                elapsed_ms = (time.perf_counter() - start) * 1000
                if resp.status_code == 200:
                    ok(f"API {path}", f"{resp.status_code} in {elapsed_ms:.0f}ms ({api_url})")
                else:
                    warn(f"API {path}", f"{resp.status_code} ({api_url})")
        except Exception as exc:
            fail("API health", f"{type(exc).__name__}: {exc}")

    console.print()
    console.print("[bold cyan]Diagnostics[/bold cyan]")
    console.print(table)

    if not logged_in or pending:
        console.print()
        console.print("[bold cyan]Next Steps[/bold cyan]")
        if not logged_in:
            console.print("  [cyan]khaos sync[/cyan] to authenticate and upload")
        elif pending:
            console.print("  [cyan]khaos sync[/cyan] to upload pending runs")
