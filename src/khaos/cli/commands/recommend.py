"""The `recommend` command - suggest next test commands for an agent."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from khaos.capabilities import security_attack_categories_for_bundles
from khaos.cli.console import console

from .capability_probe import detect_agent_metadata, infer_agent_capabilities
from .discover import resolve_agent_target


def _active_capabilities(capabilities: dict[str, Any]) -> list[str]:
    ordered = [
        "llm",
        "http",
        "web_fetch",
        "tool_calling",
        "mcp",
        "multi_turn",
        "rag",
        "files",
        "code_execution",
        "db",
        "email",
    ]
    return [cap for cap in ordered if bool(capabilities.get(cap))]


def _recommendations_for_target(target: str, capabilities: dict[str, Any]) -> list[dict[str, str]]:
    quoted_target = shlex.quote(target)
    has_tool_surface = any(
        bool(capabilities.get(cap))
        for cap in ("tool_calling", "mcp", "rag", "files", "code_execution", "db", "email", "web_fetch", "http")
    )

    recommendations = [
        {
            "goal": "Fastest first signal",
            "command": f"khaos start {quoted_target}",
            "reason": "Auto-selects the most relevant tests and finds likely failures quickly.",
        },
        {
            "goal": "Security deep-dive",
            "command": f"khaos run {quoted_target} --eval security --verbose",
            "reason": "Shows per-attack outcomes and detailed traces for hardening.",
        },
    ]

    if has_tool_surface:
        recommendations.append(
            {
                "goal": "Pre-release confidence",
                "command": f"khaos start {quoted_target} --intent assess",
                "reason": "Runs broader resilience + security checks for agents that can take actions.",
            }
        )
    else:
        recommendations.append(
            {
                "goal": "Baseline regression check",
                "command": f"khaos run {quoted_target} --eval baseline",
                "reason": "Validates deterministic behavior before adding broader attack/fault coverage.",
            }
        )

    return recommendations


def recommend(
    target: str = typer.Argument(
        ...,
        help="Agent name (from `khaos discover`), optionally pinned as name@version.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output recommendation payload as JSON.",
    ),
) -> None:
    """Recommend the best next Khaos commands for this agent."""
    target_path, agent_name = resolve_agent_target(target)
    agent_metadata = detect_agent_metadata(str(target_path), handler_name=agent_name)
    target_source = Path(target_path).read_text() if Path(target_path).exists() else ""
    capabilities = infer_agent_capabilities(agent_metadata, target_source, probe_events=None)

    active_caps = _active_capabilities(capabilities)
    bundles = [str(b) for b in capabilities.get("bundles", []) if str(b).strip()]
    categories = security_attack_categories_for_bundles(bundles) if bundles else []
    recommendations = _recommendations_for_target(target, capabilities)

    if json_output:
        typer.echo(json.dumps({
            "target": target,
            "capabilities": active_caps,
            "bundles": bundles,
            "security_categories": categories,
            "recommendations": recommendations,
        }, indent=2))
        return

    console.print()
    console.print("[bold cyan]Recommended Next Commands[/bold cyan]")
    if active_caps:
        console.print(f"[dim]Detected capabilities:[/dim] {', '.join(active_caps)}")
    else:
        console.print("[dim]Detected capabilities:[/dim] basic llm")
    if categories:
        preview = ", ".join(categories[:6])
        suffix = ", ..." if len(categories) > 6 else ""
        console.print(f"[dim]Security categories selected:[/dim] {len(categories)} ({preview}{suffix})")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Goal", style="white", no_wrap=True)
    table.add_column("Command", style="cyan")
    table.add_column("Why", style="dim")

    for rec in recommendations:
        table.add_row(rec["goal"], rec["command"], rec["reason"])

    console.print()
    console.print(table)


__all__ = ["recommend"]
