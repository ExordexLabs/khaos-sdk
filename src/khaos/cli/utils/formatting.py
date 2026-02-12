"""Formatting utilities for CLI output."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from khaos.comparison.models import MetricDelta


def format_score(value: float | None) -> str:
    """Format a score value for display."""
    if value is None:
        return "-"
    try:
        return f"{float(value):.1f}"
    except Exception:
        return "-"


def format_value(value: float | None, unit: str | None = None) -> str:
    """Format a numeric value with optional unit."""
    if value is None:
        return "-"
    suffix = f" {unit}" if unit else ""
    return f"{value:.2f}{suffix}"


def trend_symbol(value: float) -> str:
    """Return an arrow symbol indicating trend direction."""
    if value > 0:
        return " ▲"
    if value < 0:
        return " ▼"
    return ""


def format_delta(metric: "MetricDelta") -> str:
    """Format a metric delta with trend symbol."""
    if metric.absolute_delta is None:
        return "-"
    symbol = trend_symbol(metric.absolute_delta if metric.trend != "neutral" else 0)
    return f"{metric.absolute_delta:+.2f}{symbol}"


def format_cost_summary(
    structural: Any, monthly_runs: int
) -> dict[str, float] | None:
    """Calculate cost summary from structural comparison data.

    Args:
        structural: Structural comparison object with cost attribute
        monthly_runs: Number of runs per month for projections

    Returns:
        Dict with baseline, candidate, delta, per_run_savings, annual_savings
        or None if cost data unavailable
    """
    baseline = structural.cost.baseline_value
    candidate = structural.cost.candidate_value
    if baseline is None or candidate is None:
        return None
    delta = candidate - baseline
    per_run_savings = baseline - candidate
    annual_savings = per_run_savings * monthly_runs * 12
    return {
        "baseline": baseline,
        "candidate": candidate,
        "delta": delta,
        "per_run_savings": per_run_savings,
        "annual_savings": annual_savings,
    }


def status_label(score: float | None) -> str:
    """Return a Rich-styled status label for a score."""
    if score is None:
        return "[dim]-[/dim]"
    if score >= 90:
        return "[green]excellent[/green]"
    if score >= 70:
        return "[yellow]warning[/yellow]"
    return "[red]risk[/red]"
