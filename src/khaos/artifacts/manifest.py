"""Unified artifact manifest for all Khaos execution modes.

The manifest provides:
- Reproducibility: seed and config_hash for exact reproduction
- Provenance: agent hash, pack version, scenario ID
- Environment: Khaos and Python versions for debugging
- Artifact listing: what files were produced
"""

from __future__ import annotations

import json
import logging
import platform
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from khaos.state import get_state_dir


def _get_khaos_version() -> str:
    """Get the installed Khaos version."""
    try:
        from importlib.metadata import version
        return version("khaos")
    except Exception:
        logger.debug("Failed to get khaos version from package metadata", exc_info=True)
        return "unknown"


def generate_run_id(mode: str) -> str:
    """Generate a standardized run ID.

    Format: khaos-{mode}-{YYYYMMDD}-{uuid8}

    Args:
        mode: Execution mode (scenario, pack, observe)

    Returns:
        Standardized run ID string
    """
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    uuid_suffix = uuid.uuid4().hex[:8]
    return f"khaos-{mode}-{date_str}-{uuid_suffix}"


@dataclass
class RunManifest:
    """Unified artifact manifest for all execution modes.

    This manifest is written alongside run artifacts to provide:
    - Reproducibility through seed and config tracking
    - Provenance through hashes and version tracking
    - Environment capture for debugging
    """

    # Identity
    run_id: str
    execution_mode: str  # "scenario" | "pack" | "observe"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Reproducibility
    seed: int | None = None
    config_hash: str | None = None

    # Environment
    khaos_version: str = field(default_factory=_get_khaos_version)
    python_version: str = field(default_factory=lambda: platform.python_version())

    # Artifacts produced
    artifacts: list[str] = field(default_factory=list)

    # Provenance
    agent_code_hash: str | None = None
    pack_name: str | None = None
    pack_version: str | None = None
    scenario_id: str | None = None

    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "run_id": self.run_id,
            "execution_mode": self.execution_mode,
            "timestamp": self.timestamp,
            "seed": self.seed,
            "config_hash": self.config_hash,
            "khaos_version": self.khaos_version,
            "python_version": self.python_version,
            "artifacts": self.artifacts,
            "agent_code_hash": self.agent_code_hash,
            "pack_name": self.pack_name,
            "pack_version": self.pack_version,
            "scenario_id": self.scenario_id,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunManifest":
        """Deserialize from dictionary."""
        return cls(
            run_id=data["run_id"],
            execution_mode=data["execution_mode"],
            timestamp=data.get("timestamp", ""),
            seed=data.get("seed"),
            config_hash=data.get("config_hash"),
            khaos_version=data.get("khaos_version", "unknown"),
            python_version=data.get("python_version", "unknown"),
            artifacts=data.get("artifacts", []),
            agent_code_hash=data.get("agent_code_hash"),
            pack_name=data.get("pack_name"),
            pack_version=data.get("pack_version"),
            scenario_id=data.get("scenario_id"),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "RunManifest":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


def write_manifest(
    manifest: RunManifest,
    runs_dir: Path | None = None,
) -> Path:
    """Write manifest to the runs directory.

    Args:
        manifest: The manifest to write
        runs_dir: Optional custom runs directory (defaults to ~/.khaos/runs)

    Returns:
        Path to the written manifest file
    """
    if runs_dir is None:
        runs_dir = get_state_dir() / "runs"

    runs_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = runs_dir / f"manifest-{manifest.run_id}.json"
    manifest_path.write_text(manifest.to_json())

    return manifest_path


def load_manifest(run_id: str, runs_dir: Path | None = None) -> RunManifest | None:
    """Load a manifest by run ID.

    Args:
        run_id: The run ID to load
        runs_dir: Optional custom runs directory (defaults to ~/.khaos/runs)

    Returns:
        RunManifest if found, None otherwise
    """
    if runs_dir is None:
        runs_dir = get_state_dir() / "runs"

    manifest_path = runs_dir / f"manifest-{run_id}.json"
    if not manifest_path.exists():
        return None

    try:
        return RunManifest.from_json(manifest_path.read_text())
    except (json.JSONDecodeError, KeyError):
        return None
