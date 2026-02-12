"""Unified error handling for the Khaos CLI.

This module provides a consistent error hierarchy and user-friendly error messages
with actionable suggestions for common failure modes.
"""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar
from collections.abc import Callable

import typer

from khaos.ui import console, print_error, print_warning, print_tip, print_error_panel

class ErrorCategory(str, Enum):
    """Categories of errors for consistent handling and messaging."""

    # User input errors
    INVALID_INPUT = "invalid_input"
    MISSING_ARGUMENT = "missing_argument"
    FILE_NOT_FOUND = "file_not_found"

    # Configuration errors
    CONFIG_INVALID = "config_invalid"
    CONFIG_MISSING = "config_missing"
    ENV_MISSING = "env_missing"

    # Authentication errors
    AUTH_MISSING = "auth_missing"
    AUTH_EXPIRED = "auth_expired"
    AUTH_INVALID = "auth_invalid"

    # Transport/Agent errors
    TRANSPORT_FAILED = "transport_failed"
    TRANSPORT_TIMEOUT = "transport_timeout"
    TRANSPORT_PROTOCOL = "transport_protocol"
    AGENT_CRASHED = "agent_crashed"

    # API/Network errors
    NETWORK_ERROR = "network_error"
    API_ERROR = "api_error"
    RATE_LIMITED = "rate_limited"

    # Internal errors
    INTERNAL = "internal"
    NOT_IMPLEMENTED = "not_implemented"

@dataclass
class KhaosError(Exception):
    """Base exception for all Khaos errors with user-friendly messaging.

    Attributes:
        message: The main error message
        category: Error category for consistent handling
        suggestion: Optional actionable suggestion for the user
        details: Optional technical details (shown in verbose mode)
        exit_code: Exit code to use when this error terminates the CLI
    """

    message: str
    category: ErrorCategory = ErrorCategory.INTERNAL
    suggestion: str | None = None
    details: str | None = None
    exit_code: int = 1
    cause: Exception | None = field(default=None, repr=False)

    def __str__(self) -> str:
        return self.message

    def __post_init__(self) -> None:
        super().__init__(self.message)
        if self.cause:
            self.__cause__ = self.cause

    def display(self, verbose: bool = False) -> None:
        """Display the error with formatting."""
        print_error_panel(
            message=self.message,
            suggestion=self.suggestion,
            details=self.details if verbose else None,
        )

        if verbose and self.cause:
            console.print("\n[dim]Traceback:[/dim]")
            console.print(f"[dim]{traceback.format_exception(type(self.cause), self.cause, self.cause.__traceback__)}[/dim]")

# Convenience subclasses for common error types

@dataclass
class InputError(KhaosError):
    """Error caused by invalid user input."""
    category: ErrorCategory = ErrorCategory.INVALID_INPUT

@dataclass
class ConfigError(KhaosError):
    """Error in configuration files or environment."""
    category: ErrorCategory = ErrorCategory.CONFIG_INVALID

@dataclass
class AuthError(KhaosError):
    """Authentication or authorization error."""
    category: ErrorCategory = ErrorCategory.AUTH_MISSING
    exit_code: int = 2

@dataclass
class TransportError(KhaosError):
    """Error communicating with an agent."""
    category: ErrorCategory = ErrorCategory.TRANSPORT_FAILED

@dataclass
class AgentError(KhaosError):
    """Error caused by agent behavior."""
    category: ErrorCategory = ErrorCategory.AGENT_CRASHED

@dataclass
class NetworkError(KhaosError):
    """Network or API communication error."""
    category: ErrorCategory = ErrorCategory.NETWORK_ERROR

# Error message templates for common scenarios

SUGGESTIONS = {
    # Transport errors
    "vanilla_agent": (
        "This agent doesn't implement the Khaos transport protocol.\n"
        "Try: khaos run {target}\n"
        "This will capture LLM telemetry without requiring protocol changes."
    ),
    "agent_no_output": (
        "The agent produced no output. Check that:\n"
        "  1. The agent script runs successfully on its own\n"
        "  2. The agent writes JSON to stdout\n"
        "  3. API keys are set (use --env KEY=VALUE)"
    ),
    "agent_timeout": (
        "The agent took too long to respond.\n"
        "Try: --timeout 300 to increase the timeout\n"
        "Or check if the agent is waiting for input."
    ),

    # Auth errors
    "no_credentials": (
        "No cloud credentials found.\n"
        "Run: khaos sync (it will auto-login)"
    ),
    "expired_token": (
        "Your authentication token has expired.\n"
        "Run: khaos sync (it will auto-login)\n"
        "Or: khaos sync --login to force reset credentials"
    ),
    "invalid_token": (
        "The API token is invalid.\n"
        "Run: khaos sync --login to reset credentials"
    ),

    # API key errors
    "missing_openai_key": (
        "OpenAI API key not found.\n"
        "Set it with: --env OPENAI_API_KEY=sk-xxx\n"
        "Or export OPENAI_API_KEY in your shell."
    ),
    "missing_anthropic_key": (
        "Anthropic API key not found.\n"
        "Set it with: --env ANTHROPIC_API_KEY=sk-ant-xxx\n"
        "Or export ANTHROPIC_API_KEY in your shell."
    ),

    # File errors
    "scenario_not_found": (
        "Scenario file not found.\n"
        "List available scenarios: khaos scenarios list\n"
        "Or provide a path to a YAML file: --scenario-file path/to/scenario.yaml"
    ),
    "agent_not_found": (
        "Agent script not found.\n"
        "Check the path and ensure the file exists."
    ),

    # Config errors
    "invalid_yaml": (
        "Failed to parse YAML configuration.\n"
        "Validate syntax at: https://yamlchecker.com"
    ),
    "invalid_scenario": (
        "Scenario validation failed.\n"
        "Run: khaos scenarios validate <file> for details\n"
        "See docs: https://khaos.dev/docs/scenarios"
    ),

    # Rate limiting
    "rate_limited": (
        "API rate limit exceeded.\n"
        "Wait a few seconds and try again, or:\n"
        "  - Reduce --concurrency if running parallel tests\n"
        "  - Use a different API key with higher limits"
    ),

    # Security test failures
    "security_threshold_failed": (
        "Security score below threshold.\n"
        "Review the security report to identify vulnerabilities.\n"
        "Use --no-security to skip security testing if needed."
    ),

    # Import errors
    "import_error": (
        "Failed to import agent module.\n"
        "Check that all dependencies are installed:\n"
        "  pip install -r requirements.txt"
    ),

    # Pack errors
    "pack_not_found": (
        "Evaluation pack not found.\n"
        "Available packs: baseline, quickstart, full-eval, security\n"
        "Use: khaos run agent.py --pack <pack-name>"
    ),
}

def get_suggestion(key: str, **kwargs: str) -> str:
    """Get a suggestion template, optionally formatting with kwargs."""
    template = SUGGESTIONS.get(key, "")
    if kwargs and template:
        return template.format(**kwargs)
    return template

T = TypeVar("T")

def handle_errors(
    verbose: bool = False,
    exit_on_error: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator to handle KhaosError exceptions consistently.

    Usage:
        @handle_errors(verbose=ctx.obj.verbose)
        def my_command():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except KhaosError as exc:
                exc.display(verbose=verbose)
                if exit_on_error:
                    raise typer.Exit(code=exc.exit_code)
                raise
            except typer.Exit:
                raise
            except typer.Abort:
                raise
            except Exception as exc:
                # Wrap unexpected errors
                wrapped = KhaosError(
                    message=f"Unexpected error: {exc}",
                    category=ErrorCategory.INTERNAL,
                    suggestion="This may be a bug. Please report it at https://github.com/ordokhaos/khaos/issues",
                    cause=exc,
                )
                wrapped.display(verbose=verbose)
                if exit_on_error:
                    raise typer.Exit(code=1)
                raise wrapped from exc
        return wrapper
    return decorator

def detect_api_key_error(stderr: str, env: dict[str, str] | None = None) -> KhaosError | None:
    """Detect missing API key errors from agent stderr output.

    Returns a KhaosError with appropriate suggestion if an API key error is detected.
    """
    stderr_lower = stderr.lower()
    env = env or {}

    # OpenAI patterns
    openai_patterns = [
        "openai api key",
        "api_key",
        "missing api key",
        "invalid api key",
        "authentication",
        "401",
    ]

    if any(pattern in stderr_lower for pattern in openai_patterns):
        if "OPENAI_API_KEY" not in env and "OPENAI_API_KEY" not in __import__("os").environ:
            return InputError(
                message="Agent failed - likely missing OpenAI API key",
                category=ErrorCategory.ENV_MISSING,
                suggestion=get_suggestion("missing_openai_key"),
                details=f"Agent stderr: {stderr[:500]}",
            )

    # Anthropic patterns
    anthropic_patterns = [
        "anthropic api key",
        "x-api-key",
        "authentication_error",
    ]

    if any(pattern in stderr_lower for pattern in anthropic_patterns):
        if "ANTHROPIC_API_KEY" not in env and "ANTHROPIC_API_KEY" not in __import__("os").environ:
            return InputError(
                message="Agent failed - likely missing Anthropic API key",
                category=ErrorCategory.ENV_MISSING,
                suggestion=get_suggestion("missing_anthropic_key"),
                details=f"Agent stderr: {stderr[:500]}",
            )

    return None

def detect_protocol_error(stdout: str, stderr: str) -> KhaosError | None:
    """Detect when an agent doesn't implement the Khaos protocol.

    Returns a KhaosError with suggestion to use `khaos observe` instead.
    """
    # Check if output looks like it's not JSON protocol
    stdout_stripped = stdout.strip()

    if not stdout_stripped:
        return TransportError(
            message="Agent produced no output",
            category=ErrorCategory.TRANSPORT_PROTOCOL,
            suggestion=get_suggestion("agent_no_output"),
            details=f"stderr: {stderr[:500]}" if stderr else None,
        )

    # Check if it's clearly not JSON
    if stdout_stripped and not stdout_stripped.startswith("{") and not stdout_stripped.startswith("["):
        # Looks like plain text output, not JSON
        preview = stdout_stripped[:200] + ("..." if len(stdout_stripped) > 200 else "")
        return TransportError(
            message="Agent output is not valid JSON - this agent may not implement the Khaos protocol",
            category=ErrorCategory.TRANSPORT_PROTOCOL,
            suggestion=get_suggestion("vanilla_agent", target="<your-agent.py>"),
            details=f"Output preview: {preview}",
        )

    return None
