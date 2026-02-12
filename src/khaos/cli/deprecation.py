"""Deprecation timeline and utilities for Khaos CLI.

This module documents deprecated commands and their removal timeline.
All deprecations should be added here for tracking.

Deprecation Policy:
1. Deprecated commands remain functional but hidden from help
2. Deprecation warnings are shown when deprecated commands are used
3. Commands are removed after 2 minor versions (e.g., 0.8.0 -> 0.10.0)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from ..console import get_console


@dataclass
class DeprecatedCommand:
    """A deprecated CLI command with migration info."""

    old_command: str
    new_command: str
    deprecated_in: str  # Version when deprecated
    remove_in: str  # Version when will be removed
    migration_guide: str
    deprecated_date: date | None = None


# Registry of all deprecated commands
DEPRECATED_COMMANDS: list[DeprecatedCommand] = [
    DeprecatedCommand(
        old_command="observe",
        new_command="run",
        deprecated_in="0.8.0",
        remove_in="0.10.0",
        migration_guide=(
            "Replace 'khaos observe agent.py' with 'khaos run agent.py'.\n"
            "The run command now includes all observe functionality plus "
            "security and resilience testing."
        ),
        deprecated_date=date(2024, 11, 1),
    ),
    DeprecatedCommand(
        old_command="cloud login",
        new_command="sync --login",
        deprecated_in="0.8.0",
        remove_in="0.10.0",
        migration_guide=(
            "Replace 'khaos cloud login' with 'khaos sync --login'.\n"
            "The sync command auto-logins when needed, so explicit login "
            "is rarely required."
        ),
        deprecated_date=date(2024, 11, 1),
    ),
    DeprecatedCommand(
        old_command="cloud status",
        new_command="sync --status",
        deprecated_in="0.8.0",
        remove_in="0.10.0",
        migration_guide=(
            "Replace 'khaos cloud status' with 'khaos sync --status'."
        ),
        deprecated_date=date(2024, 11, 1),
    ),
    DeprecatedCommand(
        old_command="cloud logout",
        new_command="sync --logout",
        deprecated_in="0.8.0",
        remove_in="0.10.0",
        migration_guide=(
            "Replace 'khaos cloud logout' with 'khaos sync --logout'."
        ),
        deprecated_date=date(2024, 11, 1),
    ),
]


def get_deprecated_command(command: str) -> DeprecatedCommand | None:
    """Look up deprecation info for a command.

    Args:
        command: The command name (e.g., "observe" or "cloud login")

    Returns:
        DeprecatedCommand if found, None otherwise
    """
    for dep in DEPRECATED_COMMANDS:
        if dep.old_command == command:
            return dep
    return None


def show_deprecation_warning(command: str) -> None:
    """Show a deprecation warning for a command.

    Args:
        command: The deprecated command name
    """
    console = get_console()
    dep = get_deprecated_command(command)

    if dep:
        console.print(f"\n[yellow]⚠ Deprecation Warning[/yellow]")
        console.print(f"[yellow]'{dep.old_command}' is deprecated and will be removed in v{dep.remove_in}[/yellow]")
        console.print(f"[dim]Use '{dep.new_command}' instead.[/dim]\n")


def print_deprecation_timeline() -> None:
    """Print the full deprecation timeline."""
    console = get_console()

    console.print("\n[bold]Khaos CLI Deprecation Timeline[/bold]\n")

    if not DEPRECATED_COMMANDS:
        console.print("[green]No deprecated commands.[/green]")
        return

    for dep in DEPRECATED_COMMANDS:
        console.print(f"[yellow]• {dep.old_command}[/yellow]")
        console.print(f"  [dim]Deprecated in:[/dim] v{dep.deprecated_in}")
        console.print(f"  [dim]Remove in:[/dim] v{dep.remove_in}")
        console.print(f"  [dim]Replacement:[/dim] {dep.new_command}")
        console.print(f"  [dim]Migration:[/dim] {dep.migration_guide.split(chr(10))[0]}")
        console.print()


# Export for documentation generation
DEPRECATION_DOCS = """
# Khaos CLI Deprecation Timeline

This document tracks deprecated CLI commands and their planned removal.

## Deprecation Policy

1. **Warning Period**: Deprecated commands show a warning but continue to work
2. **Migration Period**: Two minor versions (e.g., 0.8.0 → 0.10.0)
3. **Removal**: Commands are removed after the migration period

## Currently Deprecated

### `observe` → `run`

- **Deprecated in**: v0.8.0
- **Remove in**: v0.10.0
- **Migration**: Replace `khaos observe agent.py` with `khaos run agent.py`

The `run` command now includes all `observe` functionality plus security
and resilience testing. The `observe` command was redundant.

### `cloud` subcommands → `sync`

- **Deprecated in**: v0.8.0
- **Remove in**: v0.10.0
- **Migration**:
  - `khaos cloud login` → `khaos sync --login`
  - `khaos cloud status` → `khaos sync --status`
  - `khaos cloud logout` → `khaos sync --logout`

The `sync` command consolidates all cloud operations and auto-logins
when needed, reducing the need for explicit login commands.

## Removed Commands

(None yet)

## Future Deprecations

(Planning phase - not yet deprecated)

- Consider: `--quick` flag may be replaced with `--pack baseline`
"""


__all__ = [
    "DeprecatedCommand",
    "DEPRECATED_COMMANDS",
    "get_deprecated_command",
    "show_deprecation_warning",
    "print_deprecation_timeline",
    "DEPRECATION_DOCS",
]
