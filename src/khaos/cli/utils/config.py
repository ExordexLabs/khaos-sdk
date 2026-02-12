"""Configuration and environment utilities for the CLI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# .env file discovery and loading
# ---------------------------------------------------------------------------

def discover_env_file(start_path: Path, max_depth: int = 10) -> Path | None:
    """Walk up directory tree to find a .env file.

    Similar to how git finds .git - starts at start_path and walks up
    until it finds a .env file or hits the filesystem root.

    Args:
        start_path: Starting directory or file path
        max_depth: Maximum number of parent directories to check

    Returns:
        Path to .env file if found, None otherwise
    """
    # If start_path is a file, start from its parent directory
    if start_path.is_file():
        current = start_path.parent
    else:
        current = start_path

    current = current.resolve()

    for _ in range(max_depth):
        env_file = current / ".env"
        if env_file.exists() and env_file.is_file():
            return env_file

        # Stop at filesystem root
        parent = current.parent
        if parent == current:
            break
        current = parent

    return None


def load_env_file(env_file: Path) -> dict[str, str]:
    """Parse a .env file and return key-value pairs.

    Args:
        env_file: Path to .env file

    Returns:
        Dict of environment variable names to values
    """
    env_vars: dict[str, str] = {}

    try:
        with env_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                # Parse KEY=VALUE (handle quoted values)
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    # Remove surrounding quotes if present
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                        value = value[1:-1]
                    env_vars[key] = value
    except OSError:
        pass

    return env_vars


def discover_and_load_env(agent_path: Path) -> dict[str, str]:
    """Discover .env file from agent path and load its contents.

    Searches for .env starting from the agent's directory and walking
    up the directory tree. Also checks ~/.khaos/.env as a fallback
    for global API key configuration.

    Args:
        agent_path: Path to the agent script

    Returns:
        Dict of environment variables from .env file(s)
    """
    env_vars: dict[str, str] = {}

    # First, check for global ~/.khaos/.env
    global_env = Path.home() / ".khaos" / ".env"
    if global_env.exists():
        env_vars.update(load_env_file(global_env))

    # Then, discover project-level .env (overrides global)
    project_env = discover_env_file(agent_path)
    if project_env:
        env_vars.update(load_env_file(project_env))

    return env_vars


def merge_env_for_subprocess(
    agent_path: Path,
    extra_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build complete environment for running an agent subprocess.

    Merges in order (later overrides earlier):
    1. Current os.environ
    2. Global ~/.khaos/.env
    3. Project .env (discovered from agent path)
    4. Explicit extra_env passed to CLI

    Args:
        agent_path: Path to the agent script
        extra_env: Additional env vars from CLI --env flags

    Returns:
        Complete environment dict for subprocess
    """
    # Start with current environment
    env = dict(os.environ)

    # Layer in discovered .env files
    discovered = discover_and_load_env(agent_path)
    env.update(discovered)

    # Layer in explicit CLI overrides
    if extra_env:
        env.update(extra_env)

    return env


def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean flag from environment variable."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str) -> int | None:
    """Read an integer from environment variable."""
    value = os.environ.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def coerce_float(value: Any) -> float | None:
    """Safely convert a value to float, returning None on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def coerce_option_value(raw: Any, expected_type: type) -> Any:
    """Coerce a raw option value to the expected type.

    Handles common CLI option parsing edge cases.
    """
    if raw is None:
        return None

    if expected_type is bool:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            return raw.strip().lower() in {"1", "true", "yes", "on"}
        return bool(raw)

    if expected_type is int:
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    if expected_type is float:
        return coerce_float(raw)

    if expected_type is str:
        return str(raw) if raw is not None else None

    return raw


def resolve_cache_dir() -> Path | None:
    """Determine cache dir, honoring state overrides for tests and sandboxes."""
    cache_env = os.environ.get("KHAOS_CACHE_DIR")
    if cache_env:
        return Path(cache_env).expanduser()

    state_dir = os.environ.get("KHAOS_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser() / "cache"

    return None


# Environment-derived defaults (computed at import time)
DEFAULT_SYNC_CLEANUP = env_flag("KHAOS_SYNC_CLEANUP", False)
DEFAULT_SYNC_CLEANUP_LOGS = env_flag("KHAOS_SYNC_CLEANUP_LOGS", False)
ASSUME_YES = env_flag("KHAOS_SYNC_ASSUME_YES", False)
ENV_RETAIN_DAYS = env_int("KHAOS_SYNC_RETAIN_DAYS")
AUTO_SYNC_DEFAULT = env_flag("KHAOS_AUTO_SYNC", False)
AUTO_SYNC_CLEANUP_DEFAULT = env_flag("KHAOS_AUTO_SYNC_CLEANUP", False)
AUTO_SYNC_CLEANUP_LOGS_DEFAULT = env_flag("KHAOS_AUTO_SYNC_CLEANUP_LOGS", False)
