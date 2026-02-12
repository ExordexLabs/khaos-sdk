"""State retention and cleanup policies for Khaos CLI.

Provides:
- Automatic cleanup of old run artifacts
- Disk usage warnings
- Configurable retention policies
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from khaos.state import get_state_dir
from ..console import get_console


# Default retention settings
DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_RUNS = 1000
DEFAULT_WARN_DISK_MB = 500  # Warn if state dir exceeds this size


@dataclass
class RetentionPolicy:
    """Configuration for artifact retention."""
    retention_days: int = DEFAULT_RETENTION_DAYS
    max_runs: int = DEFAULT_MAX_RUNS
    warn_disk_mb: int = DEFAULT_WARN_DISK_MB
    dry_run: bool = False


@dataclass
class CleanupResult:
    """Result of a cleanup operation."""
    runs_deleted: int
    bytes_freed: int
    runs_remaining: int
    errors: list[str]


def get_retention_policy() -> RetentionPolicy:
    """Get retention policy from environment or defaults."""
    return RetentionPolicy(
        retention_days=int(os.environ.get("KHAOS_RETENTION_DAYS", DEFAULT_RETENTION_DAYS)),
        max_runs=int(os.environ.get("KHAOS_MAX_RUNS", DEFAULT_MAX_RUNS)),
        warn_disk_mb=int(os.environ.get("KHAOS_WARN_DISK_MB", DEFAULT_WARN_DISK_MB)),
        dry_run=os.environ.get("KHAOS_CLEANUP_DRY_RUN", "").lower() in ("1", "true", "yes"),
    )


def get_runs_dir() -> Path:
    """Get the runs directory path."""
    return get_state_dir() / "runs"


def get_queue_path() -> Path:
    """Get the sync queue file path."""
    return get_state_dir() / "queue.json"


def list_run_artifacts(runs_dir: Path | None = None) -> list[dict]:
    """List all run artifacts with their metadata.

    Returns:
        List of dicts with run_id, paths, size_bytes, mtime
    """
    runs_dir = runs_dir or get_runs_dir()
    if not runs_dir.exists():
        return []

    # Group artifacts by run_id
    runs: dict[str, dict] = {}

    for path in runs_dir.iterdir():
        if not path.is_file():
            continue

        name = path.name
        run_id = None

        # Extract run_id from filename patterns
        for prefix in ("trace-", "metrics-", "stderr-", "llm-events-"):
            if name.startswith(prefix):
                # Handle .json and .log extensions
                suffix = name[len(prefix):]
                for ext in (".json", ".log", ".jsonl"):
                    if suffix.endswith(ext):
                        run_id = suffix[:-len(ext)]
                        break
                break

        if not run_id:
            continue

        if run_id not in runs:
            runs[run_id] = {
                "run_id": run_id,
                "paths": [],
                "size_bytes": 0,
                "mtime": 0,
            }

        stat = path.stat()
        runs[run_id]["paths"].append(path)
        runs[run_id]["size_bytes"] += stat.st_size
        runs[run_id]["mtime"] = max(runs[run_id]["mtime"], stat.st_mtime)

    return list(runs.values())


def get_disk_usage(runs_dir: Path | None = None) -> int:
    """Get total disk usage of runs directory in bytes."""
    runs_dir = runs_dir or get_runs_dir()
    if not runs_dir.exists():
        return 0

    total = 0
    for path in runs_dir.rglob("*"):
        if path.is_file():
            total += path.stat().st_size
    return total


def check_disk_usage_warning(policy: RetentionPolicy | None = None) -> str | None:
    """Check if disk usage exceeds warning threshold.

    Returns:
        Warning message if threshold exceeded, None otherwise
    """
    policy = policy or get_retention_policy()
    usage_bytes = get_disk_usage()
    usage_mb = usage_bytes / (1024 * 1024)

    if usage_mb > policy.warn_disk_mb:
        return (
            f"Khaos state directory is using {usage_mb:.1f}MB "
            f"(threshold: {policy.warn_disk_mb}MB). "
            f"Run 'khaos artifacts --cleanup' to free space."
        )
    return None


def get_runs_in_queue() -> set[str]:
    """Get set of run_ids that are pending in the sync queue."""
    queue_path = get_queue_path()
    if not queue_path.exists():
        return set()

    try:
        data = json.loads(queue_path.read_text())
        jobs = data.get("jobs", [])
        return {job.get("run_id") for job in jobs if job.get("run_id")}
    except Exception:
        return set()


def cleanup_old_runs(
    policy: RetentionPolicy | None = None,
    quiet: bool = False,
) -> CleanupResult:
    """Clean up old run artifacts based on retention policy.

    Respects:
    - Retention days (delete runs older than N days)
    - Max runs (keep only N most recent runs)
    - Pending sync queue (never delete runs pending upload)

    Args:
        policy: Retention policy (uses defaults if None)
        quiet: If True, suppress console output

    Returns:
        CleanupResult with statistics
    """
    console = get_console()
    policy = policy or get_retention_policy()
    runs_dir = get_runs_dir()

    if not runs_dir.exists():
        return CleanupResult(runs_deleted=0, bytes_freed=0, runs_remaining=0, errors=[])

    # Get all runs sorted by mtime (newest first)
    all_runs = list_run_artifacts(runs_dir)
    all_runs.sort(key=lambda r: r["mtime"], reverse=True)

    # Get runs pending sync (never delete these)
    queued_runs = get_runs_in_queue()

    # Calculate cutoff time
    cutoff = time.time() - (policy.retention_days * 24 * 3600)

    runs_to_delete: list[dict] = []
    runs_to_keep: list[dict] = []

    for i, run in enumerate(all_runs):
        run_id = run["run_id"]

        # Never delete queued runs
        if run_id in queued_runs:
            runs_to_keep.append(run)
            continue

        # Check age
        is_old = run["mtime"] < cutoff

        # Check count (keep newest max_runs)
        is_excess = i >= policy.max_runs

        if is_old or is_excess:
            runs_to_delete.append(run)
        else:
            runs_to_keep.append(run)

    # Perform deletion
    bytes_freed = 0
    errors: list[str] = []

    for run in runs_to_delete:
        if policy.dry_run:
            if not quiet:
                console.print(f"[dim]Would delete: {run['run_id']} ({run['size_bytes']} bytes)[/dim]")
            bytes_freed += run["size_bytes"]
            continue

        for path in run["paths"]:
            try:
                path.unlink()
                bytes_freed += path.stat().st_size if path.exists() else 0
            except Exception as e:
                errors.append(f"Failed to delete {path}: {e}")

    result = CleanupResult(
        runs_deleted=len(runs_to_delete) if not policy.dry_run else 0,
        bytes_freed=bytes_freed,
        runs_remaining=len(runs_to_keep),
        errors=errors,
    )

    if not quiet:
        if policy.dry_run:
            console.print(f"[yellow]Dry run:[/yellow] Would delete {len(runs_to_delete)} runs, free {bytes_freed / 1024:.1f}KB")
        elif runs_to_delete:
            console.print(f"[green]Cleaned up {result.runs_deleted} runs, freed {bytes_freed / 1024:.1f}KB[/green]")
        else:
            console.print("[dim]No runs to clean up[/dim]")

        if errors:
            for err in errors[:5]:
                console.print(f"[red]{err}[/red]")
            if len(errors) > 5:
                console.print(f"[red]... and {len(errors) - 5} more errors[/red]")

    return result


def auto_cleanup_if_needed(
    policy: RetentionPolicy | None = None,
    quiet: bool = True,
) -> CleanupResult | None:
    """Run cleanup automatically if thresholds are exceeded.

    Called automatically before new runs to prevent unbounded growth.
    Only triggers if:
    - Disk usage exceeds warning threshold, OR
    - Run count exceeds max_runs

    Args:
        policy: Retention policy
        quiet: If True, suppress output (default True for auto mode)

    Returns:
        CleanupResult if cleanup was performed, None otherwise
    """
    policy = policy or get_retention_policy()

    # Check if cleanup is needed
    runs = list_run_artifacts()
    usage_mb = get_disk_usage() / (1024 * 1024)

    needs_cleanup = (
        len(runs) > policy.max_runs or
        usage_mb > policy.warn_disk_mb
    )

    if needs_cleanup:
        return cleanup_old_runs(policy, quiet=quiet)

    return None


__all__ = [
    "RetentionPolicy",
    "CleanupResult",
    "get_retention_policy",
    "list_run_artifacts",
    "get_disk_usage",
    "check_disk_usage_warning",
    "cleanup_old_runs",
    "auto_cleanup_if_needed",
]
