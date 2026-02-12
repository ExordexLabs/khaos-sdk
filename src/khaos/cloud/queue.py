"""Filesystem-backed queue for pending run uploads."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ..state import get_state_dir

STATE_DIR = get_state_dir()
QUEUE_DIR = STATE_DIR / "queue"
RUNS_DIR = STATE_DIR / "runs"
QUEUE_DIR.mkdir(parents=True, exist_ok=True)
RUNS_DIR.mkdir(parents=True, exist_ok=True)

def _ensure_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def _job_path(run_id: str) -> Path:
    return QUEUE_DIR / f"{run_id}.json"

@dataclass
class UploadJob:
    run_id: str
    scenario_id: str
    trace_path: str
    metrics_path: str | None
    stderr_path: str | None
    project_id: str | None
    created_at: str
    attempts: int = 0
    agent_name: str = "agent"
    agent_version: str = "0.0.0"
    agent_code_hash: str = ""
    agent_metadata: dict[str, Any] = field(default_factory=dict)
    seed: int | None = None
    agent_category: str | None = None
    agent_capabilities: list[str] = field(default_factory=list)
    agent_signals: list[str] = field(default_factory=list)
    # Pack evaluation fields
    pack_name: str | None = None
    pack_version: str | None = None
    evaluation_report: dict[str, Any] | None = None
    # Evaluation primitive (Phase 0) - groups pack scenario runs
    evaluation_id: str | None = None
    scenario_order: int | None = None
    total_scenarios: int | None = None
    # User-provided run name for easier identification
    name: str | None = None

    @classmethod
    def from_json(cls, data: dict) -> "UploadJob":
        return cls(
            run_id=data["run_id"],
            scenario_id=data.get("scenario_id", "unknown"),
            trace_path=data["trace_path"],
            metrics_path=data.get("metrics_path"),
            stderr_path=data.get("stderr_path"),
            project_id=data.get("project_id"),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            attempts=data.get("attempts", 0),
            agent_name=data.get("agent_name", "agent"),
            agent_version=data.get("agent_version", "0.0.0"),
            agent_code_hash=data.get("agent_code_hash", ""),
            agent_metadata=data.get("agent_metadata", {}),
            seed=data.get("seed"),
            agent_category=data.get("agent_category"),
            agent_capabilities=data.get("agent_capabilities", []),
            agent_signals=data.get("agent_signals", []),
            pack_name=data.get("pack_name"),
            pack_version=data.get("pack_version"),
            evaluation_report=data.get("evaluation_report"),
            evaluation_id=data.get("evaluation_id"),
            scenario_order=data.get("scenario_order"),
            total_scenarios=data.get("total_scenarios"),
            name=data.get("name"),
        )

def enqueue_job(job: UploadJob) -> Path:
    path = _job_path(job.run_id)
    path.write_text(json.dumps(asdict(job), indent=2))
    _ensure_permissions(path)
    return path

def list_jobs() -> list[UploadJob]:
    jobs: list[UploadJob] = []
    for entry in sorted(QUEUE_DIR.glob("*.json")):
        try:
            payload = json.loads(entry.read_text())
            jobs.append(UploadJob.from_json(payload))
        except json.JSONDecodeError:
            continue
    jobs.sort(key=lambda job: job.created_at)
    return jobs

def delete_job(run_id: str) -> None:
    path = _job_path(run_id)
    if path.exists():
        path.unlink()

def get_job(run_id: str) -> UploadJob | None:
    path = _job_path(run_id)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    return UploadJob.from_json(payload)

def increment_attempts(job: UploadJob) -> UploadJob:
    updated = replace(job, attempts=job.attempts + 1)
    enqueue_job(updated)
    return updated

def cleanup_artifacts(job: UploadJob, *, delete_stderr: bool = False) -> list[Path]:
    """Delete run artifacts after a successful sync.

    Only files that live under the managed runs directory will be removed to avoid
    accidentally deleting arbitrary paths when users override locations.
    """

    removed: list[Path] = []
    candidates: list[tuple[str | None, bool]] = [
        (job.trace_path, True),
        (job.metrics_path, True),
        (job.stderr_path, delete_stderr),
    ]

    for raw_path, allowed in candidates:
        if not raw_path or not allowed:
            continue
        path = Path(raw_path)
        if not path.exists() or not path.is_file():
            continue
        try:
            path.relative_to(RUNS_DIR)
        except ValueError:
            # Skip anything outside the managed runs directory
            continue
        try:
            path.unlink()
            removed.append(path)
        except OSError:
            continue
    return removed

def prune_runs_dir(retention_days: int) -> list[Path]:
    """Remove artifacts older than the retention window."""

    if retention_days <= 0:
        return []
    if not RUNS_DIR.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed: list[Path] = []

    file_patterns = (
        "trace-*.json",
        "metrics-*.json",
        "stderr-*.log",
        "llm-events-*.jsonl",
        "reliability-*.json",
    )
    for pattern in file_patterns:
        for path in RUNS_DIR.glob(pattern):
            try:
                mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            except OSError:
                continue
            if mtime < cutoff:
                try:
                    path.unlink()
                    removed.append(path)
                except OSError:
                    continue

    for path in RUNS_DIR.glob("agent-*"):
        if not path.is_dir():
            continue
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            continue
        if mtime < cutoff:
            try:
                shutil.rmtree(path)
                removed.append(path)
            except OSError:
                continue

    return removed

# ============================================================================
# Run Metadata Storage
# ============================================================================
# Stores metadata for each run to enable listing and searching runs locally.

@dataclass
class RunMetadata:
    """Metadata for a local run, enabling listing and searching."""

    run_id: str
    name: str | None  # User-provided name for easy identification
    agent_path: str  # Path to the agent script that was run
    agent_name: str  # Detected or provided agent name
    created_at: str  # ISO timestamp
    pack_name: str | None  # Evaluation pack used (if any)
    scenario_id: str | None  # Scenario identifier
    security_score: float | None  # Quick reference scores
    resilience_score: float | None
    status: str  # completed, failed, etc.
    synced: bool  # Whether uploaded to cloud

    @classmethod
    def from_json(cls, data: dict) -> "RunMetadata":
        return cls(
            run_id=data["run_id"],
            name=data.get("name"),
            agent_path=data.get("agent_path", ""),
            agent_name=data.get("agent_name", "agent"),
            created_at=data.get("created_at", ""),
            pack_name=data.get("pack_name"),
            scenario_id=data.get("scenario_id"),
            security_score=data.get("security_score"),
            resilience_score=data.get("resilience_score"),
            status=data.get("status", "completed"),
            synced=data.get("synced", False),
        )

def _metadata_path(run_id: str) -> Path:
    """Get the path to a run's metadata file."""
    return RUNS_DIR / f"metadata-{run_id}.json"

def save_run_metadata(metadata: RunMetadata) -> Path:
    """Save run metadata to disk."""
    path = _metadata_path(metadata.run_id)
    path.write_text(json.dumps(asdict(metadata), indent=2))
    _ensure_permissions(path)
    return path

def get_run_metadata(run_id: str) -> RunMetadata | None:
    """Load metadata for a specific run."""
    path = _metadata_path(run_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return RunMetadata.from_json(data)
    except (json.JSONDecodeError, KeyError):
        return None

def list_run_metadata(limit: int = 50) -> list[RunMetadata]:
    """List recent runs with metadata, sorted by creation time (newest first)."""
    metadata_files: list[tuple[Path, float]] = []

    # Collect all metadata files with their modification times
    for path in RUNS_DIR.glob("metadata-*.json"):
        try:
            mtime = path.stat().st_mtime
            metadata_files.append((path, mtime))
        except OSError:
            continue

    # Sort by modification time (newest first) and limit
    metadata_files.sort(key=lambda x: x[1], reverse=True)
    metadata_files = metadata_files[:limit]

    # Parse metadata
    results: list[RunMetadata] = []
    for path, _ in metadata_files:
        try:
            data = json.loads(path.read_text())
            results.append(RunMetadata.from_json(data))
        except (json.JSONDecodeError, KeyError):
            continue

    return results

def find_run_by_name(name: str) -> RunMetadata | None:
    """Find a run by its user-provided name (exact match)."""
    for path in RUNS_DIR.glob("metadata-*.json"):
        try:
            data = json.loads(path.read_text())
            if data.get("name") == name:
                return RunMetadata.from_json(data)
        except (json.JSONDecodeError, KeyError):
            continue
    return None

def resolve_run_id(name_or_id: str) -> str | None:
    """Resolve a run name or ID to a run ID.

    Accepts:
    - Full run ID: run-abc123...
    - Short run ID: abc123 (first 6+ chars)
    - User-provided name: my-baseline

    Returns the full run ID or None if not found.
    """
    # Already a full run ID?
    if name_or_id.startswith("run-") or name_or_id.startswith("observe-"):
        path = _metadata_path(name_or_id)
        if path.exists():
            return name_or_id
        # Try without prefix
        if name_or_id.startswith("run-"):
            name_or_id = name_or_id[4:]

    # Try as a name first
    by_name = find_run_by_name(name_or_id)
    if by_name:
        return by_name.run_id

    # Try as a partial run ID (prefix match)
    for path in RUNS_DIR.glob("metadata-*.json"):
        try:
            data = json.loads(path.read_text())
            run_id = data.get("run_id", "")
            # Match against run ID without prefix
            bare_id = run_id.replace("run-", "").replace("observe-", "")
            if bare_id.startswith(name_or_id) or run_id.endswith(name_or_id):
                return run_id
        except (json.JSONDecodeError, KeyError):
            continue

    return None

def mark_run_synced(run_id: str) -> None:
    """Mark a run as synced to cloud."""
    metadata = get_run_metadata(run_id)
    if metadata:
        metadata.synced = True
        save_run_metadata(metadata)
