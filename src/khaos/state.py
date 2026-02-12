"""Shared helpers for resolving the local state directory."""

from __future__ import annotations

import os
from pathlib import Path

STATE_DIR_ENV = "KHAOS_STATE_DIR"


def get_state_dir() -> Path:
    """Resolve the base directory for CLI/runtime artifacts."""

    override = os.environ.get(STATE_DIR_ENV)
    if override:
        return Path(override)

    home_env = os.environ.get("HOME")
    if home_env:
        home = Path(home_env).expanduser()
    else:
        home = Path.home()

    if home.name == ".khaos":
        candidate = home
    else:
        candidate = home / ".khaos"

    # In some sandboxed/CI contexts HOME may exist but be read-only. Fall back to a
    # workspace-local state directory to keep CLI behavior functional.
    try:
        if home.exists() and os.access(str(home), os.W_OK):
            return candidate
    except OSError:
        pass

    return Path.cwd() / ".khaos"
