"""Custom input test results formatting.

Pretty-prints results from custom input tests.
"""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table

from khaos.cli.console import console


def print_custom_input_results(results: list[dict[str, Any]], verbose: bool = False) -> None:
    """Print custom input test results."""
    success_count = sum(1 for r in results if r["success"])
    total = len(results)

    console.print()
    console.print(Panel(
        f"[bold]{success_count}/{total} tests passed[/bold]",
        title="Custom Input Results",
        style="green" if success_count == total else "yellow",
    ))

    # Results table
    table = Table(title="Test Results")
    table.add_column("Input", style="cyan", max_width=30)
    table.add_column("Status", justify="center")
    table.add_column("Latency", justify="right")
    table.add_column("Output", max_width=40)

    for r in results:
        status = "[green]✓[/green]" if r["success"] else "[red]✗[/red]"
        output = r["output"][:40] + "..." if len(r["output"]) > 40 else r["output"]
        if r["error"]:
            output = f"[red]{r['error'][:40]}[/red]"

        table.add_row(
            r["input_id"],
            status,
            f"{r['latency_ms']:.0f}ms",
            output,
        )

    console.print(table)

    if verbose:
        _print_verbose_results(results)


def _print_verbose_results(results: list[dict[str, Any]]) -> None:
    """Print verbose output for each test result."""
    for r in results:
        if not r["success"] or len(r["output"]) > 40:
            console.print(f"\n[bold]{r['input_id']}:[/bold]")
            console.print(f"  Input: {r['input_text'][:100]}")
            console.print(f"  Output: {r['output'][:200]}")
            if r["error"]:
                console.print(f"  [red]Error: {r['error']}[/red]")
