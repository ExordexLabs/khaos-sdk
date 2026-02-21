"""The `logout` command - Logout from Khaos Cloud.

Usage:
    khaos logout             # Logout (with confirmation)
    khaos logout --force     # Logout without confirmation
"""

from __future__ import annotations

import typer

from khaos.cloud import load_cloud_config
from khaos.cli.console import console


def logout(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Skip confirmation prompt.",
    ),
) -> None:
    """Logout from Khaos Cloud.

    Clears stored credentials. Use --force to skip the confirmation prompt.

    Examples:

        # Logout (asks for confirmation)
        khaos logout

        # Logout without confirmation
        khaos logout --force
    """
    _handle_logout(force=force)


def _handle_logout(*, force: bool = False) -> None:
    """Handle cloud logout.

    Args:
        force: If True, skip confirmation prompt.
    """
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
