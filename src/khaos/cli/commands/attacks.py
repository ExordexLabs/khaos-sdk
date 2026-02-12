"""CLI commands for attack discovery and documentation.

Provides `khaos attacks` subcommands for listing, searching, and
inspecting the attack corpus. This helps users understand what
security tests are available and their characteristics.

Usage:
    khaos attacks list                    # List all attacks
    khaos attacks list --tier agent       # High-value agent attacks
    khaos attacks list --tier tool        # Tool/MCP attacks
    khaos attacks list --category rag     # RAG poisoning attacks
    khaos attacks list --canary           # Quick-scan canary attacks
    khaos attacks stats                   # Show statistics
    khaos attacks show <attack_id>        # Show attack details
"""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from khaos.evaluator.attack_registry import AttackMetadata, get_attack_registry
from khaos.security.models import AttackTier


attacks_app = typer.Typer(
    help="Explore and list security attacks.",
    no_args_is_help=True,
)


def _tier_display(tier: AttackTier) -> str:
    """Format tier for display with color."""
    colors = {
        AttackTier.AGENT: "[bold green]AGENT[/bold green]",
        AttackTier.TOOL: "[bold blue]TOOL[/bold blue]",
        AttackTier.MODEL: "[dim]MODEL[/dim]",
    }
    return colors.get(tier, tier.value)


def _severity_display(severity: str) -> str:
    """Format severity for display with color."""
    colors = {
        "critical": "[bold red]critical[/bold red]",
        "high": "[yellow]high[/yellow]",
        "medium": "[cyan]medium[/cyan]",
        "low": "[dim]low[/dim]",
    }
    return colors.get(severity.lower(), severity)


def _filter_attacks(
    attacks: list[AttackMetadata],
    *,
    tier: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    canary_only: bool = False,
) -> list[AttackMetadata]:
    """Apply filters to attack list."""
    result = attacks

    if tier:
        try:
            tier_enum = AttackTier(tier.lower())
            result = [a for a in result if a.tier == tier_enum]
        except ValueError:
            pass

    if category:
        category_lower = category.lower()
        result = [a for a in result if category_lower in a.category.lower()]

    if severity:
        severity_lower = severity.lower()
        result = [a for a in result if a.severity.lower() == severity_lower]

    if canary_only:
        result = [a for a in result if a.is_canary]

    return result


@attacks_app.command("list")
def list_attacks(
    tier: str | None = typer.Option(
        None,
        "--tier",
        "-t",
        help="Filter by tier: agent, tool, model",
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (partial match)",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity: critical, high, medium, low",
    ),
    canary_only: bool = typer.Option(
        False,
        "--canary",
        help="Show only canary (quick-scan) attacks",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        "-n",
        help="Limit number of results",
    ),
) -> None:
    """List available security attacks.

    Examples:

        khaos attacks list                      # List all attacks

        khaos attacks list --tier agent         # High-value agent attacks

        khaos attacks list --tier tool          # Tool/MCP attacks

        khaos attacks list --category rag       # RAG poisoning attacks

        khaos attacks list --canary             # Quick-scan canary attacks

        khaos attacks list --severity critical  # Critical severity only
    """
    console = Console()
    registry = get_attack_registry()

    # Get all attacks and filter
    attacks = list(registry.all())
    attacks = _filter_attacks(
        attacks,
        tier=tier,
        category=category,
        severity=severity,
        canary_only=canary_only,
    )

    # Sort by tier (agent first), then category, then id
    tier_order = {AttackTier.AGENT: 0, AttackTier.TOOL: 1, AttackTier.MODEL: 2}
    attacks.sort(key=lambda a: (tier_order.get(a.tier, 9), a.category, a.attack_id))

    # Apply limit
    if limit is not None and limit > 0:
        attacks = attacks[:limit]

    if json_output:
        data = [
            {
                "attack_id": a.attack_id,
                "name": a.name,
                "tier": a.tier.value,
                "category": a.category,
                "severity": a.severity,
                "injection_vector": a.injection_vector,
                "is_canary": a.is_canary,
                "is_multi_turn": a.is_multi_turn,
            }
            for a in attacks
        ]
        typer.echo(json.dumps(data, indent=2))
        return

    # Build filter description
    filters = []
    if tier:
        filters.append(f"tier={tier}")
    if category:
        filters.append(f"category={category}")
    if severity:
        filters.append(f"severity={severity}")
    if canary_only:
        filters.append("canary=true")
    filter_str = f" ({', '.join(filters)})" if filters else ""

    # Rich table output
    table = Table(title=f"Security Attacks ({len(attacks)} total){filter_str}")
    table.add_column("ID", style="cyan", no_wrap=True, max_width=35)
    table.add_column("Tier", justify="center")
    table.add_column("Category", style="green", max_width=25)
    table.add_column("Sev", justify="center")
    table.add_column("Name", max_width=40)

    for attack in attacks:
        name_display = attack.name
        if len(name_display) > 40:
            name_display = name_display[:37] + "..."

        table.add_row(
            attack.attack_id,
            _tier_display(attack.tier),
            attack.category,
            _severity_display(attack.severity),
            name_display,
        )

    console.print(table)

    # Show tier summary if no tier filter
    if not tier:
        console.print()
        stats = registry.stats()
        agent_count = stats["by_tier"].get("agent", 0)
        tool_count = stats["by_tier"].get("tool", 0)
        model_count = stats["by_tier"].get("model", 0)
        console.print(
            f"[dim]Tiers: "
            f"[green]AGENT[/green]={agent_count} (high value) | "
            f"[blue]TOOL[/blue]={tool_count} (high value) | "
            f"MODEL={model_count} (labs red-team)[/dim]"
        )


@attacks_app.command("stats")
def attack_stats(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
) -> None:
    """Show attack statistics by tier, category, and severity.

    Displays a breakdown of the attack corpus to understand coverage
    and prioritization of different attack types.
    """
    console = Console()
    registry = get_attack_registry()
    stats = registry.stats()

    if json_output:
        typer.echo(json.dumps(stats, indent=2))
        return

    console.print("\n[bold cyan]Attack Registry Statistics[/bold cyan]\n")
    console.print(f"Total attacks: [bold]{stats['total_attacks']}[/bold]")

    # Tier breakdown
    console.print("\n[bold]By Tier:[/bold]")
    tier_colors = {"agent": "green", "tool": "blue", "model": "dim"}
    for tier_name in ["agent", "tool", "model"]:
        count = stats["by_tier"].get(tier_name, 0)
        color = tier_colors.get(tier_name, "white")
        label = "(high value)" if tier_name in ("agent", "tool") else "(labs red-team)"
        console.print(f"  [{color}]{tier_name.upper()}[/{color}]: {count} {label}")

    # Severity breakdown
    console.print("\n[bold]By Severity:[/bold]")
    severity_order = ["critical", "high", "medium", "low"]
    for sev in severity_order:
        count = stats["by_severity"].get(sev, 0)
        if count > 0:
            console.print(f"  {_severity_display(sev)}: {count}")

    # Category breakdown (top 10)
    console.print("\n[bold]By Category (top 10):[/bold]")
    sorted_cats = sorted(stats["by_category"].items(), key=lambda x: -x[1])
    for cat, count in sorted_cats[:10]:
        console.print(f"  {cat}: {count}")

    if len(sorted_cats) > 10:
        remaining = len(sorted_cats) - 10
        console.print(f"  [dim]... and {remaining} more categories[/dim]")


@attacks_app.command("show")
def show_attack(
    attack_id: str = typer.Argument(
        ...,
        help="Attack ID to show details for",
    ),
) -> None:
    """Show detailed information about a specific attack.

    Displays the attack's tier, category, severity, injection vector,
    capability requirements, and description.
    """
    console = Console()
    registry = get_attack_registry()

    attack = registry.get(attack_id)
    if not attack:
        # Try search
        results = registry.search(attack_id)
        if results:
            console.print(f"[yellow]Attack '{attack_id}' not found. Did you mean:[/yellow]")
            for r in results[:5]:
                console.print(f"  - [cyan]{r.attack_id}[/cyan]: {r.name}")
        else:
            console.print(f"[red]Attack '{attack_id}' not found[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]{attack.attack_id}[/bold cyan]")
    console.print(f"[bold]{attack.name}[/bold]\n")

    # Details table
    console.print(f"Tier:         {_tier_display(attack.tier)}")
    console.print(f"Category:     [green]{attack.category}[/green]")
    console.print(f"Severity:     {_severity_display(attack.severity)}")
    console.print(f"Vector:       {attack.injection_vector}")
    console.print(f"Canary:       {'Yes' if attack.is_canary else 'No'}")
    console.print(f"Multi-turn:   {'Yes' if attack.is_multi_turn else 'No'}")

    if attack.required_capabilities:
        console.print(f"Requires:     {', '.join(attack.required_capabilities)}")

    if attack.owasp_mapping:
        console.print(f"OWASP:        {attack.owasp_mapping}")

    if attack.research_reference:
        console.print(f"Reference:    {attack.research_reference}")

    if attack.tags:
        console.print(f"Tags:         {', '.join(attack.tags)}")

    console.print(f"\n[dim]Expected Behavior:[/dim]")
    console.print(f"  {attack.description}")


@attacks_app.command("categories")
def list_categories(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output as JSON",
    ),
) -> None:
    """List all attack categories with counts."""
    console = Console()
    registry = get_attack_registry()
    stats = registry.stats()

    if json_output:
        typer.echo(json.dumps(stats["by_category"], indent=2))
        return

    console.print("\n[bold cyan]Attack Categories[/bold cyan]\n")

    # Sort by count descending
    sorted_cats = sorted(stats["by_category"].items(), key=lambda x: -x[1])

    table = Table()
    table.add_column("Category", style="green")
    table.add_column("Count", justify="right")

    for cat, count in sorted_cats:
        table.add_row(cat, str(count))

    console.print(table)


__all__ = ["attacks_app"]
