"""Shared helpers for enqueueing and syncing runs to Khaos Cloud.

CLI commands should prefer these helpers over duplicating login/upload logic.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

import typer

from khaos.cloud import get_cloud_session, load_cloud_config
from khaos.cloud.client import RecoverableAuthError
from khaos.cloud.device import DeviceAuthConfig, DeviceAuthError, start_device_flow
from khaos.cloud.links import dashboard_evaluation_url_for_job
from khaos.cloud.queue import UploadJob
from khaos.cloud.upload import UploadClient
from khaos.cli.console import console

from . import queue as sync_queue


@dataclass(frozen=True, slots=True)
class SyncAttempt:
    job: UploadJob
    success: bool
    dashboard_url: str | None = None
    error: str | None = None


def _is_localhost_config(config: "CloudConfig") -> bool:
    """Return True if api_url or dashboard_url point to localhost (stale dev config)."""
    for url in (config.api_url or "", config.dashboard_url or ""):
        if "localhost" in url or "127.0.0.1" in url:
            return True
    return False


def ensure_logged_in(*, scopes: list[str] | None = None, force: bool = False) -> None:
    """Ensure a usable cloud config exists, starting device flow if needed.

    Also detects stale localhost configs (left over from local development)
    and forces re-login against the production API.  Set KHAOS_DEV=1 to
    skip this check when doing local development.
    """

    scopes = scopes or ["ingest:write"]
    config = load_cloud_config()

    # Detect stale localhost config (dev leftovers) — force re-login unless
    # the developer explicitly opted in via KHAOS_DEV=1.
    is_localhost = _is_localhost_config(config)
    if is_localhost and not os.environ.get("KHAOS_DEV"):
        force = True
        # Reset api_url/dashboard_url so the device flow targets production.
        config.api_url = "https://api.khaos.exordex.com"
        config.dashboard_url = "https://khaos.exordex.com"

    if config.token and config.project_id and not force:
        return

    # Never attempt an interactive device flow inside CI environments.
    if bool(os.environ.get("GITHUB_ACTIONS")) or os.environ.get("KHAOS_CI") == "1":
        raise DeviceAuthError(
            "Not authenticated for cloud sync. In CI, set `KHAOS_API_URL`, `KHAOS_API_TOKEN`, and "
            "`KHAOS_PROJECT_SLUG` as secrets/environment variables."
        )

    auth_config = DeviceAuthConfig(
        api_url=config.api_url,
        dashboard_url=config.dashboard_url or "https://khaos.exordex.com",
        project=None,  # Select in browser
        scopes=scopes,
    )
    start_device_flow(auth_config)


def enqueue(job: UploadJob) -> None:
    sync_queue.enqueue_job(job)


def enqueue_and_sync(job: UploadJob, *, cleanup: bool = False) -> SyncAttempt:
    """Enqueue a job then attempt an immediate upload.

    On success, removes the queued job (and optionally cleans artifacts).
    On failure, increments attempts and leaves the job queued.

    For recoverable auth errors (401, 403, project mismatch), prompts user
    to re-authenticate and retries automatically.
    """

    enqueue(job)
    try:
        ensure_logged_in()
    except DeviceAuthError as exc:
        sync_queue.increment_attempts(job)
        return SyncAttempt(job=job, success=False, error=str(exc))

    session = get_cloud_session()
    client = UploadClient(session)
    try:
        client.upload(job)
    except RecoverableAuthError as exc:
        # Auth error that can be fixed by re-logging in
        console.print(f"\n[yellow]{exc}[/yellow]")
        if exc.hint:
            console.print(f"[dim]{exc.hint}[/dim]\n")

        # Offer to re-login (only in interactive mode)
        is_ci = bool(os.environ.get("GITHUB_ACTIONS")) or os.environ.get("KHAOS_CI") == "1"
        if not is_ci:
            try:
                re_login = typer.confirm("Would you like to re-authenticate now?", default=True)
                if re_login:
                    ensure_logged_in(force=True)
                    # Reload session and client with new credentials
                    config = load_cloud_config()
                    if config.token and config.project_id:
                        session = get_cloud_session()
                        client = UploadClient(session)
                        # Retry upload with new credentials
                        try:
                            console.print(f"[dim]Retrying sync...[/dim]")
                            client.upload(job)
                            sync_queue.delete_job(job.run_id)
                            if cleanup:
                                sync_queue.cleanup_artifacts(job)
                            url = dashboard_evaluation_url_for_job(load_cloud_config(), job)
                            console.print(f"[green]Sync successful![/green]")
                            return SyncAttempt(job=job, success=True, dashboard_url=url)
                        except Exception as retry_exc:
                            console.print(f"[red]Retry failed: {retry_exc}[/red]")
                            sync_queue.increment_attempts(job)
                            return SyncAttempt(job=job, success=False, error=str(retry_exc))
            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Skipping re-authentication[/yellow]")

        sync_queue.increment_attempts(job)
        return SyncAttempt(job=job, success=False, error=str(exc))
    except Exception as exc:
        sync_queue.increment_attempts(job)
        return SyncAttempt(job=job, success=False, error=str(exc))

    sync_queue.delete_job(job.run_id)
    if cleanup:
        sync_queue.cleanup_artifacts(job)

    config = load_cloud_config()
    url = dashboard_evaluation_url_for_job(config, job)
    return SyncAttempt(job=job, success=True, dashboard_url=url)


def new_job(
    *,
    run_id: str,
    scenario_id: str,
    trace_path: str,
    metrics_path: str | None,
    stderr_path: str | None,
    project_id: str | None = None,
    attempts: int = 0,
    seed: int | None = None,
    agent_name: str = "agent",
    agent_version: str = "0.0.0",
    agent_code_hash: str = "",
    agent_metadata: dict | None = None,
    agent_category: str | None = None,
    agent_capabilities: list[str] | None = None,
    agent_signals: list[str] | None = None,
    pack_name: str | None = None,
    pack_version: str | None = None,
    evaluation_report: dict | None = None,
    name: str | None = None,
) -> UploadJob:
    """Convenience constructor for UploadJob."""

    return UploadJob(
        run_id=run_id,
        scenario_id=scenario_id,
        trace_path=trace_path,
        metrics_path=metrics_path,
        stderr_path=stderr_path,
        project_id=project_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        attempts=attempts,
        agent_name=agent_name,
        agent_version=agent_version,
        agent_code_hash=agent_code_hash,
        agent_metadata=dict(agent_metadata or {}),
        seed=seed,
        agent_category=agent_category,
        agent_capabilities=list(agent_capabilities or []),
        agent_signals=list(agent_signals or []),
        pack_name=pack_name,
        pack_version=pack_version,
        evaluation_report=dict(evaluation_report) if evaluation_report else None,
        name=name,
    )
