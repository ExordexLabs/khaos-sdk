"""Shared Rich Console singleton for consistent CLI output.

All CLI modules should import `console` from this module rather than
creating their own Console instances. This ensures:
1. Consistent output formatting with Khaos theme
2. Proper handling of Rich context managers
3. Centralized control over output (e.g., for testing)
"""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

# Khaos CLI Theme - Clean, professional, focused
# Minimal color palette for clarity and readability
KHAOS_THEME = Theme({
    # Base colors
    "default": "white",
    "dim": "dim white",

    # Semantic colors - used consistently across output
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "success": "green",

    # UI elements
    "header": "bold cyan",
    "label": "dim",
    "value": "white",
    "muted": "dim",
    "link": "cyan underline",

    # Panel/table styling - subtle borders
    "panel.border": "dim",
    "table.header": "bold cyan",
    "table.border": "dim",

    # Status indicators
    "status.pass": "green",
    "status.fail": "red",
    "status.warn": "yellow",

    # Severity levels for failures
    "severity.critical": "bold red",
    "severity.high": "red",
    "severity.medium": "yellow",
    "severity.low": "dim",

    # Score gauge colors (gradient)
    "gauge.excellent": "bold green",
    "gauge.good": "green",
    "gauge.fair": "yellow",
    "gauge.poor": "red",
    "gauge.empty": "dim",

    # Branded elements
    "brand": "bold dodger_blue2",
    "brand.dim": "dim dodger_blue2",
    "rule": "dim dodger_blue2",

    # Error panel
    "error.border": "red",
    "error.title": "bold red",
    "tip.border": "dim cyan",
    "tip.title": "dim cyan",
})

# Shared console instance - use this throughout the CLI
console = Console(theme=KHAOS_THEME)

# For testing: a null console that suppresses output
_null_console: Console | None = None


def get_console() -> Console:
    """Get the active console instance.

    Returns the null console if set (for testing), otherwise the shared console.
    """
    if _null_console is not None:
        return _null_console
    return console


def set_null_console(quiet: bool = True) -> None:
    """Set a null console for testing (suppresses output)."""
    global _null_console
    if quiet:
        _null_console = Console(quiet=True, force_terminal=False)
    else:
        _null_console = None


def reset_console() -> None:
    """Reset to the default shared console."""
    global _null_console
    _null_console = None


__all__ = ["console", "get_console", "set_null_console", "reset_console"]
