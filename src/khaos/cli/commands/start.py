"""The `start` command - Smart, capability-aware agent evaluation.

This is the recommended entry point for new users. It:
1. Automatically detects agent capabilities
2. Generates a targeted pack optimized for finding vulnerabilities
3. Shows a preview of what will be tested
4. Runs with progressive difficulty (easy tests first)

Usage:
    khaos start my-agent              # Smart evaluation (recommended)
    khaos start my-agent --preview    # Show what will be tested
    khaos start my-agent --intent break   # Find vulnerabilities fast (default)
    khaos start my-agent --intent assess  # Pre-release assessment
    khaos start my-agent --intent audit   # Full security audit
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from khaos.packs import (
    PackIntent,
    SmartPackConfig,
    generate_smart_pack,
    get_pack_preview,
    format_preview_for_display,
    get_builtin_pack,
    list_builtin_packs,
)

from .discover import resolve_agent_target
from .run_packs import run_with_pack
from .capability_probe import (
    detect_agent_metadata,
    infer_agent_capabilities,
)


console = Console()


def _detect_capabilities_for_agent(
    target_path: str,
    handler_name: str | None = None,
) -> dict[str, bool]:
    """Detect agent capabilities for smart pack generation.

    Returns a dict of capability_name -> bool.
    """
    agent_metadata = detect_agent_metadata(target_path, handler_name=handler_name)
    target_source = Path(target_path).read_text() if Path(target_path).exists() else ""

    # Get capabilities dict
    caps_dict = infer_agent_capabilities(agent_metadata, target_source, probe_events=None)

    # Convert to bool dict for SmartPackConfig
    return {
        "llm": bool(caps_dict.get("llm", False)),
        "http": bool(caps_dict.get("http", False)),
        "web_fetch": bool(caps_dict.get("web_fetch", False)),
        "tool_calling": bool(caps_dict.get("tool_calling", False)),
        "mcp": bool(caps_dict.get("mcp", False)),
        "multi_turn": bool(caps_dict.get("multi_turn", False)),
        "rag": bool(caps_dict.get("rag", False)),
        "files": bool(caps_dict.get("files", False)),
        "db": bool(caps_dict.get("db", False)),
        "email": bool(caps_dict.get("email", False)),
    }


def _show_pack_preview(pack: Any, capabilities: dict[str, bool]) -> None:
    """Show a rich preview of what will be tested."""
    preview = get_pack_preview(pack)

    # Header panel
    console.print()
    console.print(Panel(
        f"[bold]{preview['description']}[/bold]\n\n"
        f"[cyan]Estimated time:[/cyan] {preview['estimated_time']}\n"
        f"[cyan]Total tests:[/cyan] {preview['total_tests']}",
        title=f"[bold cyan]{preview['name'].upper()} Pack[/bold cyan]",
        style="cyan",
    ))

    # Detected capabilities
    active_caps = [k for k, v in capabilities.items() if v]
    if active_caps:
        console.print(f"\n[bold]Detected Capabilities:[/bold] {', '.join(active_caps)}")
    else:
        console.print("\n[bold]Detected Capabilities:[/bold] [dim]basic LLM (no tools detected)[/dim]")

    # Phases table
    console.print("\n[bold]Evaluation Phases:[/bold]")
    phases_table = Table(show_header=True, header_style="bold", box=None)
    phases_table.add_column("Phase", style="cyan")
    phases_table.add_column("Details")

    for phase in preview["phases"]:
        details = ""
        if phase["name"] == "baseline":
            details = f"{phase['runs']} run(s) - pure observation"
        elif phase["name"] == "resilience":
            fault_count = phase.get("fault_count", 0)
            details = f"{fault_count} fault types injected"
        elif phase["name"] == "security":
            tier = phase.get("security_tier", "standard")
            details = f"{tier} tier - attack testing"
        phases_table.add_row(phase["name"].capitalize(), details)

    console.print(phases_table)

    # Tests preview
    console.print("\n[bold]Tests to Run:[/bold]")
    for inp in preview["inputs_preview"]:
        if inp["id"] == "...":
            console.print(f"  [dim]{inp['description']}[/dim]")
        else:
            diff = inp.get("difficulty", "medium")
            diff_colors = {
                "trivial": "green",
                "easy": "green",
                "medium": "yellow",
                "hard": "red",
                "extreme": "magenta",
            }
            color = diff_colors.get(diff, "white")
            console.print(f"  [{color}]{diff[:1].upper()}[/{color}] [bold]{inp['id']}[/bold]: {inp.get('description', inp.get('category', ''))}")

    console.print()


def _show_simplified_pack_list() -> None:
    """Show the simplified pack selection guide."""
    console.print("\n[bold cyan]Quick Start Guide[/bold cyan]\n")

    console.print("[bold]Choose your evaluation intent:[/bold]\n")

    # Intent table
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Command", style="cyan")
    table.add_column("Intent", style="bold")
    table.add_column("Time")
    table.add_column("Use Case")

    table.add_row(
        "khaos start agent.py",
        "break",
        "~2 min",
        "Find your first vulnerability fast",
    )
    table.add_row(
        "khaos start agent.py --intent assess",
        "assess",
        "~8 min",
        "Pre-release readiness check",
    )
    table.add_row(
        "khaos start agent.py --intent audit",
        "audit",
        "~15 min",
        "Comprehensive security audit",
    )

    console.print(table)

    console.print("\n[bold]Or use built-in packs directly:[/bold]\n")

    # Built-in packs
    for pack_name in ["break", "assess", "audit"]:
        if pack_name in list_builtin_packs():
            pack = get_builtin_pack(pack_name)
            console.print(f"  [cyan]khaos run agent.py --pack {pack_name}[/cyan]")
            console.print(f"    {pack.description}")
            console.print()

    console.print("[dim]Tip: khaos start auto-detects your agent's capabilities and selects relevant tests.[/dim]\n")


def start(
    target: str = typer.Argument(
        ...,
        help="Agent name (from `khaos discover`) or path to agent file.",
    ),
    intent: str = typer.Option(
        "break",
        "--intent",
        "-i",
        help="Evaluation intent: break (fast vulnerability finding), assess (pre-release), audit (comprehensive).",
    ),
    preview: bool = typer.Option(
        False,
        "--preview",
        "-P",
        help="Show what will be tested without running.",
    ),
    dynamic: bool = typer.Option(
        False,
        "--dynamic",
        "-d",
        help="Generate pack dynamically based on capabilities (vs. using built-in pack).",
    ),
    # Output options
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show full debug output.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Minimal output (errors only).",
    ),
    # Execution options
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help="Maximum execution time per test in seconds.",
    ),
    env: list[str] = typer.Option(
        [],
        "--env",
        "-e",
        help="Environment variables (KEY=VALUE). Repeat for multiple.",
    ),
    python: str = typer.Option(
        sys.executable,
        "--python",
        help="Python interpreter to use.",
    ),
    name: str | None = typer.Option(
        None,
        "--name",
        "-n",
        help="Name for this run (for easy identification).",
    ),
    sync_cloud: bool = typer.Option(
        False,
        "--sync",
        help="Sync results to the cloud dashboard.",
    ),
    guide: bool = typer.Option(
        False,
        "--guide",
        "-g",
        help="Show quick start guide and exit.",
    ),
) -> None:
    """Smart agent evaluation - find vulnerabilities fast.

    Automatically detects your agent's capabilities and runs targeted tests
    designed to find vulnerabilities quickly.

    Examples:

        # Find vulnerabilities fast (default)
        khaos start my-agent

        # Preview what will be tested
        khaos start my-agent --preview

        # Pre-release readiness assessment
        khaos start my-agent --intent assess

        # Full security audit
        khaos start my-agent --intent audit

        # Show quick start guide
        khaos start --guide
    """
    # Show guide if requested
    if guide:
        _show_simplified_pack_list()
        raise typer.Exit(0)

    # Parse environment variables
    extra_env: dict[str, str] = {}
    for item in env:
        if "=" not in item:
            raise typer.BadParameter(f"Environment entry must be KEY=VALUE (got '{item}')")
        key, value = item.split("=", 1)
        extra_env[key] = value

    # Resolve agent target
    target_path, agent_name = resolve_agent_target(target)
    extra_env["KHAOS_AGENT_HANDLER"] = agent_name

    # Parse intent
    intent_lower = intent.lower()
    if intent_lower not in ["break", "assess", "audit"]:
        raise typer.BadParameter(
            f"Unknown intent '{intent}'. Choose from: break, assess, audit"
        )

    pack_intent = {
        "break": PackIntent.BREAK,
        "assess": PackIntent.ASSESS,
        "audit": PackIntent.AUDIT,
    }[intent_lower]

    # Detect capabilities
    if not quiet:
        console.print(f"\n[dim]Scanning agent capabilities...[/dim]")

    capabilities = _detect_capabilities_for_agent(str(target_path), handler_name=agent_name)

    active_caps = [k for k, v in capabilities.items() if v]
    if not quiet and active_caps:
        console.print(f"[dim]Detected: {', '.join(active_caps)}[/dim]")

    # Generate or load pack
    if dynamic:
        # Generate pack dynamically
        config = SmartPackConfig(
            intent=pack_intent,
            capabilities=capabilities,
            include_security=True,
            include_resilience=True,
            progressive_difficulty=True,
            prioritize_by_failure_rate=True,
        )
        pack = generate_smart_pack(config)
    else:
        # Use built-in pack matching intent
        pack_name = intent_lower  # "break", "assess", or "audit"
        if pack_name not in list_builtin_packs():
            # Fall back to quickstart/full-eval if new packs not available
            fallback_map = {
                "break": "quickstart",
                "assess": "full-eval",
                "audit": "full-eval",
            }
            pack_name = fallback_map.get(pack_name, "quickstart")
            if not quiet:
                console.print(f"[dim]Using pack: {pack_name}[/dim]")

        pack = get_builtin_pack(pack_name)

    # Preview mode
    if preview:
        _show_pack_preview(pack, capabilities)
        console.print("[dim]Run without --preview to execute these tests.[/dim]\n")
        raise typer.Exit(0)

    # Run the pack
    if not quiet:
        console.print(f"\n[bold cyan]Starting {pack.name.upper()} evaluation[/bold cyan]")
        console.print(f"[dim]{pack.description}[/dim]")
        console.print(f"[dim]Estimated time: {pack.estimated_time}[/dim]\n")

    run_with_pack(
        target=str(target_path),
        pack_name=pack.name if not dynamic else "break",  # Use intent name for dynamic
        python=python,
        extra_env=extra_env,
        timeout=timeout,
        json_output=json_output,
        verbose=verbose,
        quiet=quiet,
        custom_inputs=pack.inputs if dynamic else None,  # Pass dynamic pack inputs
        sync_cloud=sync_cloud,
        name=name,
    )


def guide() -> None:
    """Show quick start guide for choosing the right evaluation."""
    _show_simplified_pack_list()


__all__ = ["start", "guide"]
