"""Trap repository generator for testing agentic environments.

Generates directories with malicious content designed to test agents'
resistance to indirect injection attacks via file content.

Usage:
    from khaos.trap_repo import generate_trap_repo

    # Generate a basic project trap repository
    generate_trap_repo("basic-project", "./test_repo")

CLI Usage:
    khaos trap-repo generate --scenario basic-project --output ./test_repo
    khaos trap-repo list
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from khaos.trap_repo.scenarios import (
    ALL_SCENARIOS,
    TrapFile,
    TrapScenario,
    get_scenario,
    list_scenarios,
)


def generate_trap_repo(
    scenario_name: str,
    output_path: str | Path,
    *,
    clean: bool = False,
    metadata_file: bool = True,
) -> Path:
    """Generate a trap repository from a scenario.

    Args:
        scenario_name: Name of the scenario to use (e.g., "basic-project")
        output_path: Directory to create the trap repository in
        clean: If True, remove existing directory before creating
        metadata_file: If True, create a .khaos-trap.json metadata file

    Returns:
        Path to the generated repository

    Raises:
        ValueError: If scenario is not found
        FileExistsError: If output directory exists and clean=False
    """
    scenario = get_scenario(scenario_name)
    if scenario is None:
        available = ", ".join(list_scenarios())
        raise ValueError(f"Unknown scenario: {scenario_name}. Available: {available}")

    output = Path(output_path)

    if output.exists():
        if clean:
            shutil.rmtree(output)
        else:
            raise FileExistsError(f"Output directory already exists: {output}")

    output.mkdir(parents=True, exist_ok=True)

    # Generate each file in the scenario
    for trap_file in scenario.files:
        file_path = output / trap_file.path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        kind = trap_file.metadata.get("kind")
        if kind == "symlink":
            target = trap_file.metadata.get("target")
            if not isinstance(target, str) or not target:
                raise ValueError(f"Symlink trap file missing metadata.target: {trap_file.path}")
            try:
                file_path.symlink_to(target)
            except OSError:
                # Fall back to writing a plain file if symlinks aren't supported.
                file_path.write_text(trap_file.content, encoding="utf-8")
        else:
            file_path.write_text(trap_file.content, encoding="utf-8")

    # Write metadata file
    if metadata_file:
        metadata = {
            "scenario": scenario_name,
            "description": scenario.description,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files": [
                {
                    "path": f.path,
                    "injection_type": f.metadata.get("injection_type"),
                    "severity": f.metadata.get("severity"),
                }
                for f in scenario.files
            ],
            "metadata": scenario.metadata,
        }
        metadata_path = output / ".khaos-trap.json"
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return output


def generate_custom_trap_repo(
    files: list[dict[str, Any]],
    output_path: str | Path,
    *,
    clean: bool = False,
    name: str = "custom",
    description: str = "Custom trap repository",
) -> Path:
    """Generate a custom trap repository from a list of file definitions.

    Args:
        files: List of dicts with "path" and "content" keys
        output_path: Directory to create the trap repository in
        clean: If True, remove existing directory before creating
        name: Name for the custom scenario
        description: Description for the custom scenario

    Returns:
        Path to the generated repository
    """
    output = Path(output_path)

    if output.exists():
        if clean:
            shutil.rmtree(output)
        else:
            raise FileExistsError(f"Output directory already exists: {output}")

    output.mkdir(parents=True, exist_ok=True)

    for file_def in files:
        file_path = output / file_def["path"]
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(file_def["content"], encoding="utf-8")

    # Write metadata
    metadata = {
        "scenario": name,
        "description": description,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": [{"path": f["path"]} for f in files],
        "custom": True,
    }
    metadata_path = output / ".khaos-trap.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return output


def generate_from_attacks(
    attacks: list[Any],
    output_path: str | Path,
    *,
    clean: bool = False,
) -> Path:
    """Generate a trap repository from security attack definitions.

    This creates files that embed the attack payloads in the appropriate
    locations based on attack metadata.

    Args:
        attacks: List of SecurityAttack objects with file_content injection vector
        output_path: Directory to create the trap repository in
        clean: If True, remove existing directory before creating

    Returns:
        Path to the generated repository
    """
    from khaos.security.models import AttackType

    output = Path(output_path)

    if output.exists():
        if clean:
            shutil.rmtree(output)
        else:
            raise FileExistsError(f"Output directory already exists: {output}")

    output.mkdir(parents=True, exist_ok=True)

    files_created = []

    for attack in attacks:
        if attack.attack_type != AttackType.FILE_CONTENT_INJECTION:
            continue

        target_files = attack.metadata.get("target_files", [])
        if not target_files:
            continue

        # Use the first target file
        target = target_files[0]
        file_path = output / target
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write the attack payload as file content
        file_path.write_text(attack.payload, encoding="utf-8")

        files_created.append({
            "path": target,
            "attack_id": attack.attack_id,
            "attack_name": attack.name,
            "severity": attack.metadata.get("severity"),
        })

    # Write metadata
    metadata = {
        "scenario": "attack-generated",
        "description": "Trap repository generated from security attacks",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": files_created,
        "attack_generated": True,
    }
    metadata_path = output / ".khaos-trap.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return output


def validate_trap_repo(path: str | Path) -> dict[str, Any]:
    """Validate a trap repository and return its metadata.

    Args:
        path: Path to the trap repository

    Returns:
        Dict with validation results and metadata

    Raises:
        FileNotFoundError: If path doesn't exist or isn't a directory
    """
    repo_path = Path(path)

    if not repo_path.exists():
        raise FileNotFoundError(f"Trap repository not found: {path}")

    if not repo_path.is_dir():
        raise FileNotFoundError(f"Path is not a directory: {path}")

    metadata_path = repo_path / ".khaos-trap.json"

    result = {
        "path": str(repo_path.absolute()),
        "valid": True,
        "has_metadata": metadata_path.exists(),
        "files": [],
        "metadata": None,
        "errors": [],
    }

    if metadata_path.exists():
        try:
            result["metadata"] = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            result["valid"] = False
            result["errors"].append(f"Invalid metadata JSON: {e}")

    # List all files in the repository
    for file_path in repo_path.rglob("*"):
        if file_path.is_file() and file_path.name != ".khaos-trap.json":
            rel_path = file_path.relative_to(repo_path)
            result["files"].append(str(rel_path))

    return result


def cleanup_trap_repo(path: str | Path) -> bool:
    """Remove a trap repository.

    Args:
        path: Path to the trap repository

    Returns:
        True if removed successfully
    """
    repo_path = Path(path)

    if not repo_path.exists():
        return False

    shutil.rmtree(repo_path)
    return True


__all__ = [
    "generate_trap_repo",
    "generate_custom_trap_repo",
    "generate_from_attacks",
    "validate_trap_repo",
    "cleanup_trap_repo",
]
