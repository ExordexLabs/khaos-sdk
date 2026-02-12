"""Khaos CLI - Agent testing and observability platform.

Design Principles:
1. Minimalist - Core commands, each with clear purpose
2. Sensible defaults - Security ON, full evaluation by default
3. Progressive disclosure - Simple usage → advanced flags
4. Consistent - Same patterns across all commands

Core Commands:
    start      - Smart, capability-aware evaluation (recommended for new users)
    run        - Full control with explicit eval selection
    evals      - List and manage evaluations
    compare    - Compare runs (or list recent runs with no args)
    ci         - CI/CD pipeline command (run + gate + report in one)
    gate       - CI/CD gate check with thresholds
    sync       - Sync results to cloud dashboard
    guide      - Quick start guide for choosing evaluations

See khaos.cli.deprecation for deprecated command timeline.
"""

from __future__ import annotations

import typer

from khaos import __version__

# Use shared console singleton
from .console import console, get_console

# Create the main app
app = typer.Typer(
    name="khaos",
    help="Agent testing and observability platform.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_enable=True,
    add_completion=True,
)


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"[bold cyan]khaos[/bold cyan] [dim]{__version__}[/dim]")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Khaos - Agent testing and observability platform.

    Run your agent with full security and resilience evaluation:

        khaos run agent.py

    Compare two runs:

        khaos compare run-abc run-def

    CI/CD gate check:

        khaos gate --security 80
    """
    pass


def _register_commands() -> None:
    """Register all CLI commands."""
    # Import new clean commands
    from khaos.cli.commands.run import run, list_evals
    from khaos.cli.commands.start import start, guide
    from khaos.cli.commands.discover import discover
    from khaos.cli.commands.compare import compare
    from khaos.cli.commands.gate import gate
    from khaos.cli.commands.sync import sync
    from khaos.cli.commands.ci import ci
    from khaos.cli.commands.doctor import doctor
    from khaos.cli.commands.export import export
    from khaos.cli.commands.artifacts import artifacts
    from khaos.cli.commands.tokens import tokens_app
    from khaos.cli.commands.attacks import attacks_app
    from khaos.cli.commands.playground import playground_app
    from khaos.cli.commands.demo import demo
    from khaos.cli.commands.test import test

    # Register core commands - start is the recommended entry point
    app.command("start")(start)  # Smart, capability-aware evaluation (recommended)
    app.command("run")(run)  # Full control with explicit eval selection
    app.command("discover")(discover)  # Scan and register agents
    app.command("compare")(compare)  # Also lists runs when called with no args
    app.command("ci")(ci)  # CI/CD pipeline command
    app.command("guide")(guide)  # Quick start guide
    app.command("demo")(demo)  # Zero-config demo
    app.command("test")(test)  # Python-native agent testing
    app.command("gate")(gate)
    app.command("sync")(sync)
    app.command("doctor")(doctor)
    app.command("export")(export)
    app.command("artifacts")(artifacts)

    # Create evals subcommand group
    evals_app = typer.Typer(help="Manage evaluations.")
    evals_app.command("list")(list_evals)
    app.add_typer(evals_app, name="evals")

    app.add_typer(tokens_app, name="tokens")

    # Attack discovery commands
    app.add_typer(attacks_app, name="attacks")

    # Interactive playground
    app.add_typer(playground_app, name="playground")

    # Hidden commands for backward compatibility
    # These will be removed in a future version
    _register_legacy_commands()


def _register_legacy_commands() -> None:
    """Register legacy commands as hidden for backward compatibility.

    See khaos.cli.deprecation for the full deprecation timeline.
    These commands will be removed in v0.10.0.
    """
    try:
        from .deprecation import show_deprecation_warning

        # Keep observe as hidden alias for run
        from khaos.cli.commands.run import run as run_cmd

        @app.command("observe", hidden=True, deprecated=True)
        def observe_alias(
            target: str = typer.Argument(...),
            python: str = typer.Option("python", "--python"),
            env: list[str] = typer.Option([], "--env"),
            security: bool = typer.Option(False, "--security"),
            timeout: float = typer.Option(120.0, "--timeout"),
            verbose: bool = typer.Option(False, "--verbose", "-v"),
        ) -> None:
            """[Deprecated] Use 'khaos run' instead. Will be removed in v0.10.0."""
            show_deprecation_warning("observe")
            # Map to new run command
            run_cmd(
                target=target,
                python=python,
                env=env,
                security=security,
                timeout=timeout,
                verbose=verbose,
            )

        # Keep cloud subcommands accessible via sync
        from khaos.cli.commands.sync import sync as sync_cmd

        cloud_app = typer.Typer(hidden=True, deprecated=True)

        @cloud_app.command("login")
        def cloud_login_alias() -> None:
            """[Deprecated] Use 'khaos sync --login' instead. Will be removed in v0.10.0."""
            show_deprecation_warning("cloud login")
            sync_cmd(login=True)

        @cloud_app.command("status")
        def cloud_status_alias() -> None:
            """[Deprecated] Use 'khaos sync --status' instead. Will be removed in v0.10.0."""
            show_deprecation_warning("cloud status")
            sync_cmd(status=True)

        @cloud_app.command("logout")
        def cloud_logout_alias() -> None:
            """[Deprecated] Use 'khaos sync --logout' instead. Will be removed in v0.10.0."""
            show_deprecation_warning("cloud logout")
            sync_cmd(logout=True)

        app.add_typer(cloud_app, name="cloud")

        # Keep list-packs as hidden alias for evals list
        from khaos.cli.commands.run import list_evals

        @app.command("list-packs", hidden=True, deprecated=True)
        def list_packs_alias() -> None:
            """[Deprecated] Use 'khaos evals list' instead. Will be removed in v0.10.0."""
            show_deprecation_warning("list-packs")
            list_evals()

        # Keep scenarios as hidden subcommand group (deprecated)
        from khaos.cli.commands.scenarios import scenarios_app
        scenarios_app.info.deprecated = True  # type: ignore
        app.add_typer(scenarios_app, name="scenarios", hidden=True, deprecated=True)

    except ImportError:
        pass


# Register commands on import
_register_commands()


# Export constants for use by command modules
from .constants import (
    VALID_SCOPES,
    DEFAULT_SCOPE,
    DEFAULT_DASHBOARD_URL,
    LLM_CONTENT_MODES,
    MODULE_ROOT,
    PROJECT_ROOT,
    STATE_RUNS_DIR,
    EXAMPLES_ROOT,
    SCENARIOS_ROOT,
    FAULT_TYPE_DESCRIPTIONS,
    resolve_data_dir,
)

# Export utilities
from .utils import (
    env_flag,
    env_int,
    coerce_float,
    coerce_option_value,
    resolve_cache_dir,
    format_score,
    format_value,
    format_delta,
    format_cost_summary,
    trend_symbol,
)

__all__ = [
    "app",
    # Console
    "console",
    "get_console",
    # Constants
    "VALID_SCOPES",
    "DEFAULT_SCOPE",
    "DEFAULT_DASHBOARD_URL",
    "LLM_CONTENT_MODES",
    "MODULE_ROOT",
    "PROJECT_ROOT",
    "STATE_RUNS_DIR",
    "EXAMPLES_ROOT",
    "SCENARIOS_ROOT",
    "FAULT_TYPE_DESCRIPTIONS",
    "resolve_data_dir",
    # Utils
    "env_flag",
    "env_int",
    "coerce_float",
    "coerce_option_value",
    "resolve_cache_dir",
    "format_score",
    "format_value",
    "format_delta",
    "format_cost_summary",
    "trend_symbol",
]
