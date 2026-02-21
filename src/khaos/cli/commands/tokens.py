"""Token management helpers for CI/CD provisioning (admin scope required)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import typer
from rich.table import Table

from khaos.cloud.client import CloudAuthError, get_authenticated_client, get_cloud_session
from khaos.cli.console import console
import json

tokens_app = typer.Typer(
    name="tokens",
    help="Manage project-scoped API tokens (create/list/rotate/revoke).",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def _split_project_path(project: str) -> tuple[str | None, str]:
    project = (project or "").strip()
    if "/" in project:
        owner, slug = project.split("/", 1)
        return owner.strip() or None, slug.strip()
    return None, project.strip()


def _project_tokens_endpoint(project: str) -> str:
    owner, slug = _split_project_path(project)
    if owner and slug:
        return f"/tokens/projects/{owner}/{slug}"
    if not slug:
        raise ValueError("project is required")
    return f"/tokens/projects/{slug}"


def _request_json(client: httpx.Client, method: str, url: str, **kwargs: Any) -> Any:
    try:
        response = client.request(method, url, **kwargs)
    except httpx.RequestError as exc:
        console.print(f"[red]Unable to reach ingestion API:[/red] {exc}")
        raise typer.Exit(code=2)
    if response.status_code >= 400:
        detail = response.text.strip()
        console.print(f"[red]API error {response.status_code}:[/red] {detail or 'Unknown error'}")
        raise typer.Exit(code=2)
    try:
        return response.json()
    except ValueError:
        return None


@tokens_app.command("list")
def list_tokens(
    project: str | None = typer.Option(
        None,
        "--project",
        help="Project path (owner/project). Defaults to the current cloud config project.",
    ),
) -> None:
    """List tokens for a project (admin scope required)."""
    session = get_cloud_session()
    config = session.config
    resolved_project = (project or config.project_id or "").strip()
    if not resolved_project:
        console.print("[red]No project configured.[/red] Set `KHAOS_PROJECT_SLUG` or run `khaos login`.")
        raise typer.Exit(code=2)

    try:
        client = get_authenticated_client(config)
    except CloudAuthError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    endpoint = _project_tokens_endpoint(resolved_project)
    tokens = _request_json(client, "GET", endpoint)
    if not isinstance(tokens, list):
        console.print("[yellow]No tokens found.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Scopes")
    table.add_column("Preview", style="dim")
    table.add_column("Expires", style="dim")
    table.add_column("Revoked", style="dim")
    for token in tokens:
        if not isinstance(token, dict):
            continue
        table.add_row(
            str(token.get("id", "")),
            str(token.get("name", "")),
            ", ".join(token.get("scopes") or []),
            str(token.get("token_preview") or ""),
            str(token.get("expires_at") or "—"),
            str(token.get("revoked_at") or "—"),
        )
    console.print(table)


@tokens_app.command("create")
def create_token(
    name: str = typer.Option("CI", "--name", help="Token name (shown in the dashboard)."),
    project: str | None = typer.Option(
        None,
        "--project",
        help="Project path (owner/project). Defaults to the current cloud config project.",
    ),
    scopes: list[str] = typer.Option(
        [],
        "--scope",
        help="Token scope (repeatable). Default is ingest:write.",
    ),
    expires_days: int | None = typer.Option(
        90,
        "--expires-days",
        help="Token expiry in days. Use 0 for no expiry.",
    ),
    print_env: bool = typer.Option(
        False,
        "--print-env",
        help="Print env var lines to help update CI secrets (token is masked unless --show-token).",
    ),
    show_token: bool = typer.Option(
        False,
        "--show-token",
        help="Include the full token value when used with --print-env.",
    ),
) -> None:
    """Create a new token (admin scope required)."""
    session = get_cloud_session()
    config = session.config
    resolved_project = (project or config.project_id or "").strip()
    if not resolved_project:
        console.print("[red]No project configured.[/red] Set `KHAOS_PROJECT_SLUG` or run `khaos login`.")
        raise typer.Exit(code=2)

    try:
        client = get_authenticated_client(config)
    except CloudAuthError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    payload: dict[str, Any] = {"name": name, "scopes": [s for s in scopes if s]}
    if expires_days is not None and expires_days > 0:
        payload["expires_in_seconds"] = int(timedelta(days=expires_days).total_seconds())

    endpoint = _project_tokens_endpoint(resolved_project)
    created = _request_json(client, "POST", endpoint, json=payload)
    if not isinstance(created, dict) or not created.get("token"):
        console.print("[red]Token creation failed.[/red]")
        raise typer.Exit(code=2)

    raw_token = str(created["token"])
    masked = raw_token if show_token else f"…{raw_token[-6:]}" if len(raw_token) >= 8 else "********"

    console.print("[green]Created token[/green]")
    console.print(f"[dim]Project:[/dim] {created.get('project_id')}")
    console.print(f"[dim]Name:[/dim] {created.get('name')}")
    console.print(f"[dim]Scopes:[/dim] {', '.join(created.get('scopes') or [])}")
    console.print(f"[dim]Expires:[/dim] {created.get('expires_at') or '—'}")
    console.print()
    console.print("[bold]Copy this into your CI secret `KHAOS_API_TOKEN`:[/bold]")
    console.print(raw_token)

    if print_env:
        console.print()
        console.print("[bold]CI env vars[/bold]")
        console.print(f"[dim]KHAOS_API_URL=[/dim]{config.api_url.rstrip('/')}")
        if created.get("project_id"):
            console.print(f"[dim]KHAOS_PROJECT_SLUG=[/dim]{created.get('project_id')}")
        console.print(f"[dim]KHAOS_API_TOKEN=[/dim]{masked}")


@tokens_app.command("rotate")
def rotate_token(
    token_id: str = typer.Argument(..., help="Token ID to rotate."),
    name: str | None = typer.Option(None, "--name", help="Optional new name for the rotated token."),
    expires_days: int | None = typer.Option(
        None,
        "--expires-days",
        help="Optional new expiry in days (keeps prior expiry when omitted). Use 0 for no expiry.",
    ),
    print_env: bool = typer.Option(
        False,
        "--print-env",
        help="Print env var lines to help update CI secrets (token is masked unless --show-token).",
    ),
    show_token: bool = typer.Option(
        False,
        "--show-token",
        help="Include the full token value when used with --print-env.",
    ),
) -> None:
    """Rotate a token: revoke old token and mint a new one (admin scope required)."""
    session = get_cloud_session()
    config = session.config
    try:
        client = get_authenticated_client(config)
    except CloudAuthError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    payload: dict[str, Any] = {}
    if name:
        payload["name"] = name
    if expires_days is not None and expires_days > 0:
        payload["expires_in_seconds"] = int(timedelta(days=expires_days).total_seconds())

    rotated = _request_json(client, "POST", f"/tokens/{token_id}/rotate", json=payload)
    if not isinstance(rotated, dict) or not rotated.get("token"):
        console.print("[red]Token rotation failed.[/red]")
        raise typer.Exit(code=2)

    raw_token = str(rotated["token"])
    masked = raw_token if show_token else f"…{raw_token[-6:]}" if len(raw_token) >= 8 else "********"

    console.print("[green]Rotated token[/green]")
    console.print(f"[dim]Token ID:[/dim] {rotated.get('id')}")
    console.print(f"[dim]Rotated from:[/dim] {rotated.get('rotated_from')}")
    console.print()
    console.print("[bold]New token value (update your CI secret):[/bold]")
    console.print(raw_token)

    if print_env:
        console.print()
        console.print("[bold]CI env vars[/bold]")
        console.print(f"[dim]KHAOS_API_URL=[/dim]{config.api_url.rstrip('/')}")
        if config.project_id:
            console.print(f"[dim]KHAOS_PROJECT_SLUG=[/dim]{config.project_id}")
        console.print(f"[dim]KHAOS_API_TOKEN=[/dim]{masked}")


@tokens_app.command("revoke")
def revoke_token(
    token_id: str = typer.Argument(..., help="Token ID to revoke."),
) -> None:
    """Revoke a token (admin scope required)."""
    session = get_cloud_session()
    config = session.config
    try:
        client = get_authenticated_client(config)
    except CloudAuthError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    response = client.delete(f"/tokens/{token_id}")
    if response.status_code not in (200, 204):
        console.print(f"[red]Failed to revoke token ({response.status_code}).[/red] {response.text.strip()}")
        raise typer.Exit(code=2)
    console.print("[green]Revoked token[/green]")


@tokens_app.command("whoami")
def whoami(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Show the currently configured cloud identity (project + scopes)."""
    session = get_cloud_session()
    config = session.config
    try:
        client = get_authenticated_client(config)
    except CloudAuthError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2)

    try:
        response = client.get("/ingest/status")
    except httpx.RequestError as exc:
        console.print(f"[red]Unable to reach ingestion API:[/red] {exc}")
        raise typer.Exit(code=2)

    if response.status_code >= 400:
        console.print(f"[red]Auth check failed ({response.status_code}).[/red] {response.text.strip()}")
        raise typer.Exit(code=2)

    payload = {}
    try:
        payload = response.json()
    except ValueError:
        payload = {"status": "unknown", "raw": response.text}

    if json_output:
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    console.print("[bold]Cloud Identity[/bold]")
    console.print(f"[dim]API:[/dim] {config.api_url.rstrip('/')}")
    console.print(f"[dim]Project:[/dim] {payload.get('project') or config.project_id or '—'}")
    scopes = payload.get("scopes")
    if isinstance(scopes, list) and scopes:
        console.print(f"[dim]Scopes:[/dim] {', '.join([str(s) for s in scopes])}")
    else:
        console.print(f"[dim]Scopes:[/dim] {', '.join(config.scopes) if config.scopes else '—'}")
    if payload.get("label"):
        console.print(f"[dim]Label:[/dim] {payload.get('label')}")
