"""Shared footer for CLI output: dashboard URL + export/artifacts."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.rule import Rule

from khaos.cloud.links import dashboard_evaluation_url
from khaos.cloud.config import load_cloud_config


def _shorten_url(url: str, max_length: int = 60) -> tuple[str, str]:
    """Return (display_url, full_url) - shortens the display if too long.

    Dashboard URLs can be very long. This keeps the essential parts visible:
    - The domain
    - The project ID (first few chars)
    - The evaluation slug (truncated)
    """
    if len(url) <= max_length:
        return url, url

    # Parse URL parts
    if "/evaluations/" in url:
        base, eval_part = url.rsplit("/evaluations/", 1)
        # The eval_part is like "slug__run_id" - keep slug, shorten run_id
        if "__" in eval_part:
            slug, run_id = eval_part.rsplit("__", 1)
            # Truncate slug if very long, keep short run_id suffix
            if len(slug) > 25:
                slug = slug[:22] + "..."
            short_eval = f"{slug}__{run_id[:8]}"
            short_url = f"{base}/evaluations/{short_eval}"
            return short_url, url

    # Fallback: just truncate
    return url[:max_length - 3] + "...", url


def print_run_footer(
    console: Console,
    *,
    run_id: str,
    name: str | None = None,
    pack_name: str | None = None,
    scenario_identifier: str | None = None,
    agent_name: str | None = None,
    agent_version: str | None = None,
    trace_path: Path | None = None,
    metrics_path: Path | None = None,
    stderr_path: Path | None = None,
) -> None:
    """Print a clean, compact footer with dashboard link."""
    if not run_id:
        return

    config = load_cloud_config()
    url = dashboard_evaluation_url(
        config,
        run_id=run_id,
        name=name,
        pack_name=pack_name,
        scenario_identifier=scenario_identifier,
        agent_name=agent_name,
        agent_version=agent_version,
    )

    console.print()
    console.print(Rule(style="dim"))

    # Dashboard link - clean and prominent
    if url:
        short_url, _ = _shorten_url(url)
        console.print(f"[dim]View results:[/dim] [link={url}]{short_url}[/link]")
    else:
        console.print(f"[dim]Cloud features:[/dim] [link=https://exordex.com/khaos]exordex.com/khaos[/link] (waitlist)")

    # Run reference - minimal, only if useful
    console.print(f"[dim]Run {run_id[:8]}[/dim]")
