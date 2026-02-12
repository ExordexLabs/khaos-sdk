"""High-signal failure summaries for CLI output."""

from __future__ import annotations

from typing import Any


def _extract_error_snippet(error: str, max_len: int = 60) -> str:
    """Extract a meaningful error snippet from a potentially long error message."""
    if not error:
        return "unknown error"
    # Get last line (usually the actual error)
    lines = error.strip().splitlines()
    for line in reversed(lines):
        line = line.strip()
        if line and not line.startswith(('File ', 'Traceback ', '  ')):
            if len(line) > max_len:
                return line[:max_len - 3] + "..."
            return line
    return error[:max_len] if len(error) > max_len else error


def summarize_pack_failures(
    *,
    report: Any,
    failed_inputs: list[Any],
    vulnerabilities: list[Any],
    issues: list[str],
) -> list[str]:
    """Return concise, actionable failure bullets (max 3)."""

    bullets: list[str] = []

    error_failures = [r for r in failed_inputs if getattr(r, "error", None)]
    check_failures = [r for r in failed_inputs if getattr(r, "checks_met", None) is False]
    goal_failures = [r for r in failed_inputs if getattr(r, "goal_met", None) is False]

    # Agent errors - most critical
    if error_failures:
        sample = _extract_error_snippet(str(getattr(error_failures[0], "error", "") or ""))
        bullets.append(f"[red]{len(error_failures)} agent error(s)[/red]: {sample}")

    # Check failures
    if check_failures:
        bullets.append(f"[yellow]{len(check_failures)} check failure(s)[/yellow]")

    # Goal misses
    if goal_failures:
        bullets.append(f"[yellow]{len(goal_failures)} goal miss(es)[/yellow]")

    # Security vulnerabilities
    if vulnerabilities:
        attack_types: list[str] = []
        for v in vulnerabilities:
            t = str(getattr(v, "attack_type", "") or "").replace("_", " ").strip()
            if t and t not in attack_types:
                attack_types.append(t)
        if attack_types:
            bullets.append(f"[red]{len(vulnerabilities)} security issue(s)[/red]: {', '.join(attack_types[:2])}")
        else:
            bullets.append(f"[red]{len(vulnerabilities)} security issue(s)[/red]")

    # Fallback to structured issues
    if not bullets and issues:
        bullets.extend([i for i in issues[:3] if i])

    return bullets[:3]

