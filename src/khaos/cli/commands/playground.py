"""The `playground` command - Interactive agent testing interface.

Start an interactive playground session with your agent:

    khaos playground start my-agent

The playground opens a ChatGPT-like interface in your browser where you can:
- Send prompts to your agent in real-time
- Toggle fault injection (LLM timeouts, HTTP errors, etc.)
- Run security attacks manually
- Export the session as a Khaos pack YAML

Your agent runs locally while the CLI streams events to the hosted
Khaos dashboard (https://khaos.exordex.com) via WebSocket relay.

Note: Agents must be discovered first with `khaos discover`.

Session limits:
- Free users: 10 sessions per month
- Paid users: Unlimited sessions
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import typer

from khaos.cli.console import console
from .discover import resolve_agent_target


# Create playground app
playground_app = typer.Typer(
    name="playground",
    help="Interactive agent testing interface.",
    no_args_is_help=True,
)


def _resolve_dashboard_url() -> str:
    """Resolve the dashboard URL from env var, cloud config, or default.

    Uses the same resolution chain as playground auth to ensure consistency.
    """
    from khaos.cloud.config import load_cloud_config

    env_url = os.environ.get("KHAOS_DASHBOARD_URL")
    if env_url:
        return env_url.rstrip("/")

    config = load_cloud_config()
    return config.get_dashboard_url()


@playground_app.command("start")
def start(
    target: str = typer.Argument(
        ...,
        help="Agent name (discovered via `khaos discover`).",
    ),
    dashboard_url: str = typer.Option(
        "",
        "--dashboard",
        "-d",
        help="Dashboard base URL override (default: https://khaos.exordex.com).",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Don't open browser automatically.",
    ),
) -> None:
    """Start an interactive playground session with an agent.

    Opens a ChatGPT-like interface in your browser for real-time
    agent interaction, fault injection, and security testing.

    Agents must be discovered first with `khaos discover`.

    Free users get 10 playground sessions per month.
    Upgrade for unlimited sessions at https://khaos.exordex.com/pricing

    Examples:

        khaos playground start my-agent

        khaos playground start my-agent --no-browser
    """
    # Check for websockets dependency
    try:
        import websockets  # noqa: F401
    except ImportError:
        console.print(
            "[red]Error:[/red] websockets package required for playground.\n"
            "Install with: [cyan]pip install websockets[/cyan]"
        )
        raise typer.Exit(1)

    # Resolve dashboard URL: explicit flag > env var > cloud config > production default
    if not dashboard_url:
        dashboard_url = _resolve_dashboard_url()

    # Resolve agent from registry (same as `khaos run`)
    try:
        target_path, agent_name = resolve_agent_target(target)
    except typer.BadParameter as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    # Request cloud session
    session_token = _request_cloud_session(agent_name)

    # Railway WebSocket relay URL (env var override only)
    railway_ws_url = os.environ.get("KHAOS_RAILWAY_WS_URL", "wss://api.khaos.dev/ws")

    console.print(
        f"[bold cyan]Khaos Playground[/bold cyan] Starting interactive session...\n"
    )
    console.print(f"  Agent: [green]{agent_name}[/green]")
    console.print(f"  Script: [dim]{target_path}[/dim]")
    if no_browser:
        playground_url = f"{dashboard_url}/playground?token={session_token}"
        console.print(f"\n  [bold]Playground URL:[/bold] {playground_url}")
        console.print("  [yellow]Warning:[/yellow] URL contains a temporary session token.")
    else:
        console.print(f"\n  [bold]Dashboard:[/bold] {dashboard_url}/playground")
        console.print("  Opening browser with a temporary session token.")
    console.print()

    # Run the Railway client (NOT server)
    from khaos.playground.client import run_playground_client

    try:
        asyncio.run(
            run_playground_client(
                railway_ws_url=railway_ws_url,
                session_token=session_token,
                agent_script=str(target_path),
                agent_name=agent_name,
                handler=None,
                dashboard_url=dashboard_url,
                open_browser=not no_browser,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[dim]Playground session ended.[/dim]")


def _trigger_device_login() -> bool:
    """Trigger the device flow login and return True if successful."""
    from khaos.cloud.config import load_cloud_config
    from khaos.cloud.device import DeviceAuthConfig, DeviceAuthError, start_device_flow

    config = load_cloud_config()

    console.print("\n[yellow]Not logged in. Starting authentication...[/yellow]\n")

    try:
        auth_config = DeviceAuthConfig(
            api_url=config.api_url,
            dashboard_url=config.get_dashboard_url(),
            project=None,  # Will be selected in browser
            scopes=["ingest:write"],  # Standard scope for playground
        )
        new_config = start_device_flow(auth_config)
        console.print(f"\n[green]Successfully logged in to {new_config.project_id}[/green]\n")
        return True
    except DeviceAuthError as exc:
        console.print(f"[red]Login failed: {exc}[/red]")
        return False
    except KeyboardInterrupt:
        console.print("\n[yellow]Login cancelled.[/yellow]")
        return False


def _request_cloud_session(agent_name: str | None) -> str:
    """Request a playground session from the cloud API.

    Returns the session token if successful.
    Exits the CLI with an error if authentication fails or session limit is reached.

    If the user is not logged in, automatically triggers the device login flow.
    """
    from khaos.playground.auth import (
        request_playground_session_sync,
        NotLoggedInError,
        SessionLimitError,
        PlaygroundAuthError,
        is_authenticated,
    )

    # Check if user is authenticated - auto-login if not
    if not is_authenticated():
        if not _trigger_device_login():
            console.print(
                "\n[red]Error:[/red] Authentication required for playground.\n"
                "  Run [cyan]khaos sync --login[/cyan] to authenticate manually.\n"
            )
            raise typer.Exit(1)

    try:
        console.print("[dim]Authenticating with Khaos Cloud...[/dim]")
        session_info = request_playground_session_sync(agent_name)

        # Show session info
        if session_info.sessions_limit:
            console.print(
                f"[green]Session authorized[/green] "
                f"({session_info.sessions_used}/{session_info.sessions_limit} this month)"
            )
        else:
            console.print("[green]Session authorized[/green] (unlimited)")

        return session_info.session_token

    except SessionLimitError as e:
        console.print(
            f"\n[red]Session limit reached[/red] "
            f"({e.sessions_used}/{e.sessions_limit} sessions used)\n"
        )
        if e.resets_at:
            console.print(f"  Resets: {e.resets_at.strftime('%B 1, %Y')}")
        console.print(f"\n[blue]Upgrade for unlimited sessions:[/blue]")
        console.print(f"  {e.upgrade_url}\n")
        raise typer.Exit(1)

    except NotLoggedInError:
        # Token may have expired, try to re-login
        console.print("[yellow]Session expired. Re-authenticating...[/yellow]")
        if not _trigger_device_login():
            console.print(
                "\n[red]Error:[/red] Authentication required for playground.\n"
                "  Run [cyan]khaos sync --login[/cyan] to authenticate manually.\n"
            )
            raise typer.Exit(1)
        # Retry after re-login
        return _request_cloud_session(agent_name)

    except PlaygroundAuthError as e:
        console.print(
            f"[red]Error:[/red] Authentication failed: {e}\n"
            "  Please try again or check your connection.\n"
        )
        raise typer.Exit(1)


@playground_app.command("info")
def info() -> None:
    """Show playground feature information."""
    resolved_url = _resolve_dashboard_url()
    console.print(
        f"""
[bold cyan]Khaos Playground[/bold cyan]

Interactive agent testing interface with real-time streaming.

[bold]Features:[/bold]
  - ChatGPT-like interface for agent interaction
  - Real-time tool call visualization
  - Fault injection toggles (LLM, HTTP, filesystem)
  - Security attack injection
  - Session export to YAML for CI/CD

[bold]Usage:[/bold]
  khaos playground start my-agent
  khaos playground start my-agent --no-browser

[bold]Requirements:[/bold]
  - websockets package: pip install websockets

[bold]Dashboard:[/bold]
  {resolved_url}/playground
  Override with: KHAOS_DASHBOARD_URL env var or --dashboard flag

[bold]How it works:[/bold]
  Your agent runs locally. The CLI streams events to the hosted
  dashboard via a WebSocket relay at wss://api.khaos.dev/ws.
"""
    )
