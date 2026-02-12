"""The `discover` command - Scan and register agents.

Scans directories for @khaosagent decorated functions/classes and
registers them in the local agent registry (~/.khaos/agents.json).

Usage:
    khaos discover              # Scan current directory
    khaos discover ./project    # Scan specific directory
    khaos discover --dry-run    # Preview without registering
    khaos discover --list       # List registered agents
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.table import Table

from khaos.agent import (
    discover_agents_in_file,
    register_discovered_agent,
    list_local_agents,
    find_agent_by_name,
    AgentMetadata,
)
from khaos.cli.console import console


def discover(
    path: str | None = typer.Argument(
        None,
        help="Directory or file to scan (default: current directory).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        "-n",
        help="Preview discovered agents without registering.",
    ),
    list_agents: bool = typer.Option(
        False,
        "--list",
        "-l",
        help="List all registered agents.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON.",
    ),
    recursive: bool = typer.Option(
        True,
        "--recursive/--no-recursive",
        "-r/-R",
        help="Recursively scan subdirectories (default: True).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output.",
    ),
) -> None:
    """Discover and register @khaosagent decorated agents.

    Scans Python files for @khaosagent decorators and registers them
    in the local agent registry. This enables running agents by name
    with `khaos run <agent-name>`.

    Examples:

        # Discover agents in current directory
        khaos discover

        # Preview without registering
        khaos discover --dry-run

        # List registered agents
        khaos discover --list

        # Discover in specific directory
        khaos discover ./agents/
    """
    # Handle --list flag
    if list_agents:
        _list_registered_agents(json_output=json_output)
        return

    # Determine scan path
    scan_path = Path(path).expanduser().resolve() if path else Path.cwd()

    if not scan_path.exists():
        console.print(f"[red]Path not found: {scan_path}[/red]")
        raise typer.Exit(code=1)

    # Collect Python files to scan
    if scan_path.is_file():
        if scan_path.suffix == ".py":
            files = [scan_path]
        else:
            console.print(f"[red]Not a Python file: {scan_path}[/red]")
            raise typer.Exit(code=1)
    else:
        if recursive:
            files = list(scan_path.rglob("*.py"))
        else:
            files = list(scan_path.glob("*.py"))

        # Exclude common directories
        exclude_dirs = {".venv", "venv", "__pycache__", ".git", "node_modules", "build", "dist", ".eggs"}
        files = [f for f in files if not any(exc in f.parts for exc in exclude_dirs)]

    if not files:
        console.print(f"[yellow]No Python files found in {scan_path}[/yellow]")
        return

    if not json_output and not dry_run:
        console.print(f"\n[bold cyan]Scanning for @khaosagent decorators...[/bold cyan]")
        console.print(f"[dim]Path: {scan_path}[/dim]")
        console.print(f"[dim]Files: {len(files)} Python files[/dim]\n")

    # Discover agents
    discovered: list[AgentMetadata] = []
    scanned = 0

    for file_path in files:
        try:
            agents = discover_agents_in_file(file_path)
            discovered.extend(agents)
            scanned += 1
            if verbose and agents:
                console.print(f"[dim]Found {len(agents)} agent(s) in {file_path.name}[/dim]")
        except Exception as e:
            if verbose:
                console.print(f"[yellow]Error scanning {file_path}: {e}[/yellow]")

    if not discovered:
        if json_output:
            typer.echo(json.dumps({"scanned": scanned, "discovered": 0, "agents": []}, indent=2))
        else:
            console.print(f"[yellow]No @khaosagent decorated agents found in {scanned} files.[/yellow]")
        return

    # Register discovered agents (unless dry-run)
    if not dry_run:
        for agent in discovered:
            register_discovered_agent(agent)

    # Output results
    if json_output:
        output = {
            "scanned": scanned,
            "discovered": len(discovered),
            "dry_run": dry_run,
            "agents": [a.to_dict() for a in discovered],
        }
        typer.echo(json.dumps(output, indent=2))
    else:
        _print_discovered_agents(discovered, dry_run=dry_run)


def _print_discovered_agents(agents: list[AgentMetadata], dry_run: bool = False) -> None:
    """Pretty print discovered agents."""
    action = "Discovered" if dry_run else "Registered"

    console.print(f"\n[bold green]{action} {len(agents)} agent(s):[/bold green]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Target", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Version")
    table.add_column("Function")
    table.add_column("File", style="dim")
    table.add_column("Category")

    for agent in agents:
        file_display = Path(agent.entrypoint).name if agent.entrypoint else "-"
        category = agent.category.value if agent.category else "-"
        target = f"{agent.name}@{agent.version}" if agent.version else agent.name

        table.add_row(
            target,
            agent.name,
            agent.version,
            agent.function_name or "-",
            file_display,
            category,
        )

    console.print(table)

    if not dry_run:
        console.print(f"\n[dim]Agents registered. Run with: khaos run <agent-name> (or <agent-name>@<version>)[/dim]")


def _list_registered_agents(json_output: bool = False) -> None:
    """List all registered agents."""
    agents = list_local_agents()

    if json_output:
        typer.echo(json.dumps([a.to_dict() for a in agents], indent=2))
        return

    if not agents:
        console.print("[yellow]No registered agents found.[/yellow]")
        console.print("[dim]Run 'khaos discover' to scan for agents.[/dim]")
        return

    console.print(f"\n[bold cyan]Registered Agents ({len(agents)}):[/bold cyan]\n")

    # Compute "latest" per name by discovered_at (fall back to last_run_at).
    def _sort_key(agent: AgentMetadata) -> tuple[str, str, str]:
        return (agent.discovered_at or "", agent.last_run_at or "", agent.version or "")

    latest_by_name: dict[str, AgentMetadata] = {}
    for agent in agents:
        current = latest_by_name.get(agent.name)
        if current is None or _sort_key(agent) > _sort_key(current):
            latest_by_name[agent.name] = agent

    # Sort for stable display: group by name, latest first within a name.
    agents_sorted = sorted(
        agents,
        key=lambda a: (a.name, a.version or "", a.discovered_at or ""),
        reverse=False,
    )
    agents_sorted = sorted(
        agents_sorted,
        key=lambda a: (a.name, _sort_key(a)),
        reverse=True,
    )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Target", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Version")
    table.add_column("Function")
    table.add_column("File")
    table.add_column("Latest", justify="center")
    table.add_column("Last Run", style="dim")

    for agent in agents_sorted:
        entrypoint = Path(agent.entrypoint) if agent.entrypoint else None
        file_display = entrypoint.name if entrypoint else "-"
        if entrypoint is not None and not entrypoint.exists():
            file_display = f"{file_display} (missing)"
        last_run = agent.last_run_at[:10] if agent.last_run_at else "Never"
        target = f"{agent.name}@{agent.version}" if agent.version else agent.name
        is_latest = latest_by_name.get(agent.name) == agent

        table.add_row(
            target,
            agent.name,
            agent.version,
            agent.function_name or "-",
            file_display,
            "✓" if is_latest else "",
            last_run,
        )

    console.print(table)
    console.print("\n[dim]Run agent: khaos run <agent-name> (or pin: <agent-name>@<version>)[/dim]")
    console.print("[dim]Refresh registry: khaos discover[/dim]")


def resolve_agent_target(target: str) -> tuple[Path, str]:
    """Resolve an agent name (optionally with @version) to a file path and selector.

    Args:
        target: Agent name (e.g., "my-agent") discovered via `khaos discover`.
            Optionally pin a specific version: "my-agent@1.2.3".

    Returns:
        Tuple of (file_path, agent_name).

    Raises:
        typer.BadParameter: If target cannot be resolved
    """
    requested_name = target
    requested_version: str | None = None
    if "@" in target:
        name_part, version_part = target.rsplit("@", 1)
        if name_part.strip() and version_part.strip():
            requested_name = name_part.strip()
            requested_version = version_part.strip()

    # GA UX: target must be an agent name, not a file path.
    if "/" in requested_name or "\\" in requested_name or requested_name.endswith(".py"):
        raise typer.BadParameter(
            "Khaos runs agents by name (not by script path).\n"
            "Run `khaos discover` to register agents, then:\n"
            "  khaos run <agent-name>\n"
            f"Got: {target}"
        )

    # Otherwise, look up by name in registry
    matches = find_agent_by_name(requested_name)

    if not matches:
        raise typer.BadParameter(
            f"Agent '{requested_name}' not found in registry.\n"
            f"  - To discover agents, run: khaos discover\n"
            f"  - To list registered agents, run: khaos discover --list"
        )

    if requested_version is not None:
        version_matches = [a for a in matches if (a.version or "") == requested_version]
        if not version_matches:
            available = ", ".join(sorted({a.version for a in matches if a.version})) or "—"
            raise typer.BadParameter(
                f"Agent '{requested_name}' has no registered version '{requested_version}'.\n"
                f"Available versions: {available}"
            )
        matches = version_matches

    agent = matches[0]  # Already sorted by discovered_at descending
    path = Path(agent.entrypoint)
    if not path.exists():
        raise typer.BadParameter(
            f"Agent '{requested_name}' is registered but file no longer exists: {agent.entrypoint}\n"
            "Fix:\n"
            "  - Re-run discovery from your repo root: khaos discover\n"
            "  - List registry entries: khaos discover --list\n"
            "  - If this is a stale entry, remove it from your registry file (~/.khaos/agents.json) and re-run discovery."
        )

    # If the user didn't pin a version and multiple are present, be explicit about what we chose.
    if requested_version is None and len(matches) > 1:
        console.print(
            f"[dim]Using {agent.name} v{agent.version or '—'} "
            f"(pin with {agent.name}@{agent.version or '<version>'}).[/dim]"
        )

    return path, agent.name
