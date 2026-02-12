"""Device code login flow for CLI browser-based authentication."""

from __future__ import annotations

import os
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import CloudConfig, load_cloud_config, save_cloud_config
from khaos.cli.console import console


@dataclass
class DeviceAuthConfig:
    """Configuration for device auth flow."""

    api_url: str
    dashboard_url: str
    project: str | None
    scopes: list[str]


class DeviceAuthError(Exception):
    """Raised when device auth fails."""

    pass


def start_device_flow(config: DeviceAuthConfig) -> CloudConfig:
    """
    Start the device authorization flow.

    1. Request a device code from the API
    2. Open browser to dashboard auth page
    3. Poll for token until user confirms or timeout

    Returns the CloudConfig with the new token on success.
    Raises DeviceAuthError on failure.
    """
    api_url = config.api_url.rstrip("/")
    dashboard_url = config.dashboard_url.rstrip("/")

    # Step 1: Request device code
    console.print("\n[dim]Starting device authorization flow...[/dim]\n")

    try:
        payload: dict[str, Any] = {
            "scopes": config.scopes,
        }
        if config.project:
            payload["project"] = config.project
        response = httpx.post(
            f"{api_url}/cli-auth/device/code",
            json=payload,
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPError as e:
        raise DeviceAuthError(f"Failed to start device flow: {e}")

    device_code = data["device_code"]
    user_code = data["user_code"]
    expires_in = data.get("expires_in", 600)
    poll_interval = data.get("interval", 5)

    # Step 2: Show code and open browser
    returned_dashboard_url = (data.get("dashboard_url") or "").strip()
    if (
        returned_dashboard_url
        and dashboard_url.rstrip("/") == "http://localhost:3000"
        and returned_dashboard_url.rstrip("/") != "http://localhost:3000"
    ):
        dashboard_url = returned_dashboard_url.rstrip("/")

    auth_url = f"{dashboard_url}/cli-auth?code={user_code}"
    if config.project:
        auth_url = f"{auth_url}&project={config.project}"

    console.print(
        Panel(
            f"[bold cyan]{user_code}[/bold cyan]\n\n"
            "[dim]This code is embedded in the link — you usually don't need to type it.[/dim]\n"
            "[dim]If the link doesn't work, open /cli-auth and paste the code.[/dim]",
            title="[bold]Authorize Khaos CLI[/bold]",
            subtitle="Approve the request in your browser",
            border_style="cyan",
            padding=(1, 4),
        )
    )

    console.print(f"\n[dim]Opening browser to:[/dim] {auth_url}\n")

    try:
        webbrowser.open(auth_url)
    except Exception:
        console.print(
            f"[yellow]Could not open browser automatically.[/yellow]\n"
            f"Please open this URL manually:\n{auth_url}"
        )

    console.print(
        "[dim]Waiting for you to confirm in the dashboard...[/dim]\n"
        "[dim]Press Ctrl+C to cancel.[/dim]\n"
    )

    # Step 3: Poll for token
    deadline = time.time() + expires_in

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Waiting for authorization...", total=None)

        while time.time() < deadline:
            try:
                poll_response = httpx.post(
                    f"{api_url}/cli-auth/device/token",
                    json={"device_code": device_code},
                    timeout=10.0,
                )

                if poll_response.status_code == 200:
                    poll_data = poll_response.json()

                    if poll_data.get("status") == "complete":
                        # Success!
                        progress.stop()
                        token = poll_data["token"]
                        project = poll_data["project"]
                        scopes = poll_data.get("scopes", config.scopes)
                        expires_at = poll_data.get("expires_at")
                        # Prefer the dashboard URL we actually opened (reliable in local dev where ports vary).
                        # Only override from API response when it is explicitly provided and differs from the
                        # local-dev default, which helps production deployments enforce canonical domains.
                        returned = (poll_data.get("dashboard_url") or "").strip()
                        if returned and returned.rstrip("/") != "http://localhost:3000":
                            returned_dashboard_url = returned
                        else:
                            returned_dashboard_url = dashboard_url

                        # Save to config
                        cloud_config = load_cloud_config()
                        cloud_config.token = token
                        cloud_config.project_id = project
                        cloud_config.api_url = api_url
                        cloud_config.dashboard_url = returned_dashboard_url  # Persist dashboard URL from API
                        cloud_config.scopes = scopes
                        cloud_config.token_preview = (
                            token[-6:] if len(token) > 6 else token
                        )
                        cloud_config.saved_at = datetime.utcnow().isoformat()
                        save_cloud_config(cloud_config)

                        console.print(
                            f"\n[bold green]✓[/bold green] Authenticated successfully for project [bold cyan]{project}[/bold cyan]"
                        )
                        if expires_at:
                            console.print(f"[dim]Token expires: {expires_at}[/dim]")

                        return cloud_config

                    elif poll_data.get("status") == "pending":
                        # Still waiting
                        pass
                    else:
                        # Unknown status
                        raise DeviceAuthError(
                            f"Unexpected status: {poll_data.get('status')}"
                        )

                elif poll_response.status_code == 403:
                    # User denied
                    progress.stop()
                    raise DeviceAuthError("Authorization was denied by the user.")

                elif poll_response.status_code == 404:
                    # Code expired or not found
                    progress.stop()
                    raise DeviceAuthError("Authorization code expired or not found.")

                else:
                    # Other error
                    progress.stop()
                    raise DeviceAuthError(
                        f"Poll failed with status {poll_response.status_code}"
                    )

            except httpx.HTTPError as e:
                # Network error, keep trying
                progress.update(task, description=f"Retrying... ({e})")

            time.sleep(poll_interval)

    raise DeviceAuthError("Authorization timed out. Please try again.")
