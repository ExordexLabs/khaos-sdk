"""The `sync` command - Sync results to cloud dashboard.

Consolidates cloud-related functionality:
- Sync pending runs to cloud (auto-login if needed)
- Force re-login (reset credentials)
- Logout
- Status check

Usage:
    khaos sync                 # Sync pending runs (auto-login if needed)
    khaos sync --login         # Force re-login (reset credentials)
    khaos sync --status        # Check sync status
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from khaos.cloud import CloudSession, get_cloud_session, load_cloud_config
from khaos.cloud import queue as sync_queue
from khaos.cloud.client import RecoverableAuthError
from khaos.cloud.queue import UploadJob
from khaos.cloud.upload import UploadClient
from khaos.cloud.links import dashboard_evaluation_url_for_job
from khaos.state import get_state_dir
from khaos.cli.console import console

logger = logging.getLogger(__name__)


def sync(
    login: bool = typer.Option(
        False,
        "--login",
        "-l",
        help="Force re-login (reset credentials). Sync auto-logins if needed.",
    ),
    logout: bool = typer.Option(
        False,
        "--logout",
        help="Logout from cloud.",
    ),
    status: bool = typer.Option(
        False,
        "--status",
        "-s",
        help="Show sync status (pending jobs, login status).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force sync all pending jobs, even if previously failed.",
    ),
    run_id: str | None = typer.Option(
        None,
        "--run",
        "-r",
        help="Sync a specific run by ID.",
    ),
    cleanup: bool = typer.Option(
        False,
        "--cleanup",
        "-c",
        help="Delete local artifacts after successful sync.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON.",
    ),
    admin: bool = typer.Option(
        False,
        "--admin",
        help="Request an admin-scoped token during `--login` (requires owner/project admin).",
    ),
    scopes: list[str] = typer.Option(
        [],
        "--scope",
        help="Additional scopes to request during `--login` (can be repeated).",
    ),
) -> None:
    """Sync run results to cloud dashboard.

    Automatically logs in if not authenticated. Use --login to force
    re-login (reset credentials), --status to check current state,
    or --run to sync a specific run.

    Examples:

        # Sync all pending runs (auto-login if needed)
        khaos sync

        # Force re-login / reset credentials
        khaos sync --login

        # Check status
        khaos sync --status

        # Sync specific run
        khaos sync --run run-abc123

        # Sync and cleanup local files
        khaos sync --cleanup
    """
    # Handle logout
    if logout:
        _handle_logout(force)
        return

    # Handle login (force re-login if --login flag is used)
    if login:
        _handle_login(force=True, admin=admin, scopes=scopes)
        if not status and not run_id:
            return  # Just login, don't sync

    # Handle status
    if status:
        _show_status(json_output)
        return

    # Sync runs
    _sync_runs(run_id=run_id, force=force, cleanup=cleanup, json_output=json_output)


def _handle_login(*, force: bool = False, admin: bool = False, scopes: list[str] | None = None) -> None:
    """Handle cloud login.

    Args:
        force: If True, force re-login even if already authenticated.
    """
    from khaos.cloud.device import DeviceAuthConfig, DeviceAuthError, start_device_flow

    config = load_cloud_config()

    # Check if already logged in
    if config.token and config.project_id and not force:
        console.print(f"[green]Already logged in to {config.project_id}[/green]")
        return

    if force and config.token:
        console.print(f"[yellow]Re-authenticating (was: {config.project_id})...[/yellow]")

    # Interactive login via device flow
    try:
        requested_scopes = ["ingest:write"]
        if admin:
            requested_scopes.append("admin")
        if scopes:
            requested_scopes.extend([s for s in scopes if s])
        # Deduplicate while preserving order.
        seen: set[str] = set()
        requested_scopes = [s for s in requested_scopes if not (s in seen or seen.add(s))]

        auth_config = DeviceAuthConfig(
            api_url=config.api_url,
            dashboard_url=config.dashboard_url or "https://dashboard.khaos.dev",
            project=None,  # Will be selected in browser
            scopes=requested_scopes,
        )
        new_config = start_device_flow(auth_config)
        console.print(f"[green]Successfully logged in to {new_config.project_id}[/green]")
    except DeviceAuthError as exc:
        console.print(f"[red]Login failed: {exc}[/red]")
        raise typer.Exit(code=1)


def _handle_logout(force: bool) -> None:
    """Handle cloud logout."""
    from khaos.cloud.config import save_cloud_config, CloudConfig

    config = load_cloud_config()
    if not config.token:
        console.print("[yellow]Not logged in[/yellow]")
        return

    if not force:
        confirm = typer.confirm("Are you sure you want to logout?")
        if not confirm:
            console.print("[yellow]Logout cancelled[/yellow]")
            return

    # Clear credentials by saving empty config
    empty_config = CloudConfig(
        api_url=config.api_url,
        dashboard_url=config.dashboard_url,
    )
    save_cloud_config(empty_config)
    console.print("[green]Successfully logged out[/green]")


def _show_status(json_output: bool) -> None:
    """Show sync status."""
    # Load session
    config = load_cloud_config()
    logged_in = bool(config.token and config.project_id)

    # Load queue using module-level functions
    pending = sync_queue.list_jobs()
    failed = [j for j in pending if j.attempts > 0]
    ready = [j for j in pending if j.attempts == 0]

    if json_output:
        output = {
            "logged_in": logged_in,
            "project_id": config.project_id if logged_in else None,
            "pending_jobs": len(ready),
            "failed_jobs": len(failed),
            "jobs": [
                {
                    "run_id": j.run_id,
                    "attempts": j.attempts,
                }
                for j in pending
            ],
        }
        typer.echo(json.dumps(output, indent=2))
    else:
        console.print("\n[bold]Khaos Cloud Status[/bold]\n")

        # Login status
        if logged_in:
            console.print(f"[green]Logged in to project:[/green] {config.project_id}")
        else:
            console.print("[yellow]Not logged in[/yellow]")
            console.print("[dim]Run 'khaos sync --login' to authenticate[/dim]")

        # Queue status
        console.print(f"\n[bold]Sync Queue:[/bold]")
        console.print(f"  Pending: {len(ready)}")
        console.print(f"  Failed: {len(failed)}")

        if pending:
            table = Table(title="Pending Jobs")
            table.add_column("Run ID", style="cyan")
            table.add_column("Attempts", justify="right")

            for job in pending[:10]:
                table.add_row(job.run_id, str(job.attempts))

            console.print(table)

            if len(pending) > 10:
                console.print(f"[dim]... and {len(pending) - 10} more[/dim]")


def _sync_runs(
    run_id: str | None,
    force: bool,
    cleanup: bool,
    json_output: bool,
) -> None:
    """Sync runs to cloud."""
    # Check login - auto-login if needed
    config = load_cloud_config()
    if not config.token or not config.project_id:
        if bool(os.environ.get("GITHUB_ACTIONS")) or os.environ.get("KHAOS_CI") == "1":
            console.print(
                "[red]Not authenticated for cloud sync.[/red]\n"
                "[dim]In CI, set `KHAOS_API_URL`, `KHAOS_API_TOKEN`, and `KHAOS_PROJECT_SLUG` "
                "instead of using interactive login.[/dim]"
            )
            raise typer.Exit(code=2)

        console.print("[yellow]Not logged in. Starting login...[/yellow]")
        _handle_login()
        config = load_cloud_config()
        if not config.token or not config.project_id:
            console.print("[red]Login failed. Cannot sync.[/red]")
            raise typer.Exit(code=1)

    session = get_cloud_session()
    client = UploadClient(session)

    # Get jobs to sync
    if run_id:
        # Find specific run
        job = sync_queue.get_job(run_id)
        if not job:
            # Create a new job for this run
            runs_dir = get_state_dir() / "runs"
            trace_path = runs_dir / f"trace-{run_id}.json"
            metrics_path = runs_dir / f"metrics-{run_id}.json"

            if not trace_path.exists() and not metrics_path.exists():
                console.print(f"[red]Run not found: {run_id}[/red]")
                raise typer.Exit(code=1)

            scenario_id = "unknown"
            seed: int | None = None
            if metrics_path.exists():
                try:
                    metrics_payload = json.loads(metrics_path.read_text())
                    scenario_id = str(metrics_payload.get("scenario") or scenario_id)
                    seed_raw = metrics_payload.get("seed")
                    seed = int(seed_raw) if seed_raw is not None else None
                except Exception:
                    logger.debug("Failed to parse metrics file for run '%s'", run_id, exc_info=True)
                    scenario_id = "unknown"
                    seed = None

            job = UploadJob(
                run_id=run_id,
                scenario_id=scenario_id,
                trace_path=str(trace_path),
                metrics_path=str(metrics_path) if metrics_path.exists() else None,
                stderr_path=None,
                project_id=None,
                created_at=datetime.utcnow().isoformat(),
                attempts=0,
                seed=seed,
            )
            sync_queue.enqueue_job(job)

        jobs = [job]
    else:
        # Get all pending jobs
        jobs = sync_queue.list_jobs()
        if not force:
            # Only include jobs that haven't failed too many times
            jobs = [j for j in jobs if j.attempts < 3]

    if not jobs:
        if not json_output:
            console.print()
        console.print("[green]No pending jobs to sync[/green]")
        return

    # Sync jobs
    synced = 0
    failed_count = 0
    results = []

    for job in jobs:
        try:
            if not json_output:
                console.print(f"Syncing {job.run_id}...", end=" ")

            client.upload(job)
            sync_queue.delete_job(job.run_id)
            synced += 1

            if cleanup:
                sync_queue.cleanup_artifacts(job)

            if not json_output:
                console.print("[green]done[/green]")
                dashboard_url = dashboard_evaluation_url_for_job(load_cloud_config(), job)
                if dashboard_url:
                    console.print(f"[dim]View in dashboard:[/dim] {dashboard_url}")

            results.append({"run_id": job.run_id, "status": "success"})

        except RecoverableAuthError as exc:
            # Auth error that can be fixed by re-logging in
            if not json_output:
                console.print(f"[red]auth error[/red]")
                console.print(f"\n[yellow]{exc}[/yellow]")
                if exc.hint:
                    console.print(f"[dim]{exc.hint}[/dim]\n")

                # Offer to re-login (only in interactive mode)
                if not bool(os.environ.get("GITHUB_ACTIONS")) and os.environ.get("KHAOS_CI") != "1":
                    try:
                        re_login = typer.confirm("Would you like to re-authenticate now?", default=True)
                        if re_login:
                            _handle_login(force=True)
                            # Reload session and client with new credentials
                            config = load_cloud_config()
                            if config.token and config.project_id:
                                session = get_cloud_session()
                                client = UploadClient(session)
                                # Retry this job immediately
                                try:
                                    if not json_output:
                                        console.print(f"Retrying {job.run_id}...", end=" ")
                                    client.upload(job)
                                    sync_queue.delete_job(job.run_id)
                                    synced += 1
                                    if cleanup:
                                        sync_queue.cleanup_artifacts(job)
                                    if not json_output:
                                        console.print("[green]done[/green]")
                                        dashboard_url = dashboard_evaluation_url_for_job(load_cloud_config(), job)
                                        if dashboard_url:
                                            console.print(f"[dim]View in dashboard:[/dim] {dashboard_url}")
                                    results.append({"run_id": job.run_id, "status": "success"})
                                    continue  # Skip the failed path
                                except Exception as retry_exc:
                                    console.print(f"[red]failed: {retry_exc}[/red]")
                    except (KeyboardInterrupt, EOFError):
                        console.print("\n[yellow]Skipping re-authentication[/yellow]")

            sync_queue.increment_attempts(job)
            failed_count += 1
            results.append({"run_id": job.run_id, "status": "failed", "error": str(exc)})

        except Exception as exc:
            sync_queue.increment_attempts(job)
            failed_count += 1

            if not json_output:
                console.print(f"[red]failed: {exc}[/red]")

            results.append({"run_id": job.run_id, "status": "failed", "error": str(exc)})

    if json_output:
        output = {
            "synced": synced,
            "failed": failed_count,
            "results": results,
        }
        typer.echo(json.dumps(output, indent=2))
    else:
        console.print(f"\n[bold]Sync complete:[/bold] {synced} synced, {failed_count} failed")


def _cleanup_job(job: UploadJob) -> None:
    """Remove local artifacts for a synced job."""
    if job.trace_path:
        trace_path = Path(job.trace_path)
        if trace_path.exists():
            trace_path.unlink()
    if job.metrics_path:
        metrics_path = Path(job.metrics_path)
        if metrics_path.exists():
            metrics_path.unlink()
