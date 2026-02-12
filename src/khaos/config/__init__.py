"""Configuration loading utilities."""

from pathlib import Path
from typing import Any
from collections.abc import Mapping

DEFAULT_CONFIG_PATH = Path.home() / ".khaos" / "config.yaml"

def load_config(path: Path | None = None) -> Mapping[str, Any]:
    """Placeholder configuration loader.

    The concrete loader will support layered sources (env vars, project files,
    MCP-provided overrides). Returning an empty mapping keeps call sites stable
    without committing to a parsing library yet.
    """
    _ = path or DEFAULT_CONFIG_PATH
    return {}
