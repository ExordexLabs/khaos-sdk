"""Shared formatting helpers for CLI output."""

from __future__ import annotations
from collections.abc import Iterable

from rich.console import Console

def format_ratio(numerator: int | None, denominator: int | None) -> str:
    if numerator is None or denominator is None or denominator <= 0:
        return "—"
    return f"{numerator}/{denominator}"

def format_rate(numerator: int | None, denominator: int | None) -> str:
    if numerator is None or denominator is None or denominator <= 0:
        return "—"
    return f"{numerator}/{denominator} ({(numerator / denominator):.0%})"

def print_key_rates(console: Console, rates: Iterable[tuple[str, str]]) -> None:
    rates_list = list(rates)
    if not rates_list:
        return
    console.print()
    console.print("[bold]Key Rates[/bold]")
    for label, value in rates_list:
        console.print(f"  [dim]{label}:[/dim] {value}")
