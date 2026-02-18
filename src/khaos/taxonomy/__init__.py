"""Packaged taxonomy catalog access helpers for CLI tooling."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def packaged_taxonomy_root() -> Path:
    """Return the packaged taxonomy root path."""
    return Path(__file__).resolve().parent


def resolve_taxonomy_root(override: Path | None = None) -> Path:
    """Resolve taxonomy root from CLI override, env var, or packaged defaults."""
    if override is not None:
        return override

    env_root = os.environ.get("KHAOS_TAXONOMY_ROOT")
    if env_root:
        return Path(env_root).expanduser().resolve()

    return packaged_taxonomy_root()


def load_yaml(path: Path) -> dict[str, Any]:
    """Load YAML as mapping."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping at top level in {path}")
    return data


def catalog_path(root: Path, filename: str) -> Path:
    """Return a path under catalog/ for the selected taxonomy root."""
    return root / "catalog" / filename


def load_branches(root: Path) -> dict[str, Any]:
    """Load branches catalog."""
    return load_yaml(catalog_path(root, "branches.v1.yaml"))


def load_ideas(root: Path) -> dict[str, Any]:
    """Load ideas catalog."""
    return load_yaml(catalog_path(root, "ideas.seed.v1.yaml"))


def load_mapping_decisions(root: Path) -> dict[str, Any]:
    """Load mapping decisions catalog."""
    return load_yaml(catalog_path(root, "mapping.decisions.seed.v1.yaml"))


__all__ = [
    "packaged_taxonomy_root",
    "resolve_taxonomy_root",
    "catalog_path",
    "load_yaml",
    "load_branches",
    "load_ideas",
    "load_mapping_decisions",
]
