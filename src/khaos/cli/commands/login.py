"""The `login` command - Authenticate with Khaos Cloud.

Usage:
    khaos login              # Login (skips if already authenticated)
    khaos login --force      # Force re-login (reset credentials)
    khaos login --admin      # Request admin-scoped token
"""

from __future__ import annotations

import typer

from khaos.cloud import load_cloud_config
from khaos.cli.console import console


def login(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force re-login even if already authenticated.",
    ),
    admin: bool = typer.Option(
        False,
        "--admin",
        help="Request an admin-scoped token (requires owner/project admin).",
    ),
    scopes: list[str] = typer.Option(
        [],
        "--scope",
        help="Additional scopes to request (can be repeated).",
    ),
) -> None:
    """Authenticate with Khaos Cloud using device flow.

    Automatically opens a browser for authentication. If already logged in,
    shows the current project unless --force is used to re-authenticate.

    Examples:

        # Login (skips if already authenticated)
        khaos login

        # Force re-login / reset credentials
        khaos login --force

        # Login with admin scope
        khaos login --admin
    """
    _handle_login(force=force, admin=admin, scopes=scopes)


def _handle_login(
    *,
    force: bool = False,
    admin: bool = False,
    scopes: list[str] | None = None,
) -> None:
    """Handle cloud login.

    Args:
        force: If True, force re-login even if already authenticated.
        admin: If True, request admin scope.
        scopes: Additional scopes to request.
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
            dashboard_url=config.dashboard_url or "https://khaos.exordex.com",
            project=None,  # Will be selected in browser
            scopes=requested_scopes,
        )
        new_config = start_device_flow(auth_config)
        console.print(f"[green]Successfully logged in to {new_config.project_id}[/green]")
    except DeviceAuthError as exc:
        console.print(f"[red]Login failed: {exc}[/red]")
        raise typer.Exit(code=1)
