"""Scenario versioning and standardization.

Provides:
- Schema versioning for future-proof scenario evolution
- Scenario metadata API for browsing scenario libraries
- Diff/comparison tools for scenario versions
- Certification and validation for release packs
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


# Current schema version
CURRENT_SCHEMA_VERSION = "1.0.0"

# Supported schema versions (for migration)
SUPPORTED_SCHEMA_VERSIONS = ["1.0.0"]


class CertificationLevel(Enum):
    """Certification level for scenarios."""

    DRAFT = "draft"  # Work in progress
    COMMUNITY = "community"  # Community contributed
    REVIEWED = "reviewed"  # Reviewed but not certified
    CERTIFIED = "certified"  # Officially certified for release
    DEPRECATED = "deprecated"  # No longer recommended


@dataclass
class ScenarioVersion:
    """Version information for a scenario."""

    schema_version: str = CURRENT_SCHEMA_VERSION
    scenario_version: str = "1.0.0"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    author: str = ""
    changelog: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_version": self.scenario_version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "author": self.author,
            "changelog": self.changelog,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScenarioVersion":
        created_at = data.get("created_at")
        updated_at = data.get("updated_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)

        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        elif updated_at is None:
            updated_at = datetime.now(timezone.utc)

        return cls(
            schema_version=data.get("schema_version", CURRENT_SCHEMA_VERSION),
            scenario_version=data.get("scenario_version", "1.0.0"),
            created_at=created_at,
            updated_at=updated_at,
            author=data.get("author", ""),
            changelog=data.get("changelog", []),
        )


@dataclass
class ScenarioCertification:
    """Certification status for a scenario."""

    level: CertificationLevel = CertificationLevel.DRAFT
    certified_by: str = ""
    certified_at: datetime | None = None
    release_pack: str = ""  # e.g., "v1", "v2"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "certified_by": self.certified_by,
            "certified_at": self.certified_at.isoformat() if self.certified_at else None,
            "release_pack": self.release_pack,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScenarioCertification":
        level_str = data.get("level", "draft")
        try:
            level = CertificationLevel(level_str)
        except ValueError:
            level = CertificationLevel.DRAFT

        certified_at = data.get("certified_at")
        if isinstance(certified_at, str):
            certified_at = datetime.fromisoformat(certified_at.replace("Z", "+00:00"))

        return cls(
            level=level,
            certified_by=data.get("certified_by", ""),
            certified_at=certified_at,
            release_pack=data.get("release_pack", ""),
            notes=data.get("notes", ""),
        )

    @property
    def is_certified(self) -> bool:
        return self.level == CertificationLevel.CERTIFIED


@dataclass
class VersionedScenarioMetadata:
    """Extended scenario metadata with versioning."""

    identifier: str
    summary: str
    version: ScenarioVersion
    certification: ScenarioCertification
    tags: list[str] = field(default_factory=list)
    fault_count: int = 0
    fault_types: list[str] = field(default_factory=list)
    difficulty: float = 0.0
    difficulty_label: str = "Easy"
    source_path: str | None = None
    content_hash: str = ""  # SHA256 of scenario content

    def to_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "summary": self.summary,
            "version": self.version.to_dict(),
            "certification": self.certification.to_dict(),
            "tags": self.tags,
            "fault_count": self.fault_count,
            "fault_types": self.fault_types,
            "difficulty": self.difficulty,
            "difficulty_label": self.difficulty_label,
            "source_path": self.source_path,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VersionedScenarioMetadata":
        return cls(
            identifier=data.get("identifier", ""),
            summary=data.get("summary", ""),
            version=ScenarioVersion.from_dict(data.get("version", {})),
            certification=ScenarioCertification.from_dict(data.get("certification", {})),
            tags=data.get("tags", []),
            fault_count=data.get("fault_count", 0),
            fault_types=data.get("fault_types", []),
            difficulty=data.get("difficulty", 0.0),
            difficulty_label=data.get("difficulty_label", "Easy"),
            source_path=data.get("source_path"),
            content_hash=data.get("content_hash", ""),
        )


def compute_scenario_hash(content: str | dict[str, Any]) -> str:
    """Compute SHA256 hash of scenario content."""
    if isinstance(content, dict):
        # Normalize dict to JSON string for consistent hashing
        content = json.dumps(content, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def validate_schema_version(version: str) -> bool:
    """Check if schema version is supported."""
    return version in SUPPORTED_SCHEMA_VERSIONS


def migrate_scenario(data: dict[str, Any], from_version: str, to_version: str) -> dict[str, Any]:
    """Migrate scenario data between schema versions.

    Currently only 1.0.0 is supported, so this is a no-op.
    Future versions will add migration logic here.
    """
    if from_version == to_version:
        return data

    # Add migration logic as new versions are introduced
    # For now, just return the data unchanged
    return data


def add_version_fields(data: dict[str, Any], author: str = "") -> dict[str, Any]:
    """Add version fields to a scenario that doesn't have them."""
    if "version" not in data:
        data["version"] = ScenarioVersion(author=author).to_dict()

    if "certification" not in data:
        data["certification"] = ScenarioCertification().to_dict()

    return data


# ---------------------------------------------------------------------------
# Scenario Diff/Comparison
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    """Result of comparing two scenarios."""

    identifier: str
    changed: bool
    additions: list[str] = field(default_factory=list)
    deletions: list[str] = field(default_factory=list)
    modifications: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        if not self.changed:
            return f"{self.identifier}: No changes"

        parts = []
        if self.additions:
            parts.append(f"+{len(self.additions)} additions")
        if self.deletions:
            parts.append(f"-{len(self.deletions)} deletions")
        if self.modifications:
            parts.append(f"~{len(self.modifications)} modifications")

        return f"{self.identifier}: {', '.join(parts)}"


def _compare_lists(key: str, old: list, new: list) -> tuple[list[str], list[str], list[str]]:
    """Compare two lists and return additions, deletions, modifications."""
    old_set = set(str(x) for x in old)
    new_set = set(str(x) for x in new)

    additions = [f"{key}[{x}]" for x in (new_set - old_set)]
    deletions = [f"{key}[{x}]" for x in (old_set - new_set)]

    return additions, deletions, []


def _compare_dicts(prefix: str, old: dict, new: dict) -> tuple[list[str], list[str], list[str]]:
    """Compare two dicts and return additions, deletions, modifications."""
    additions = []
    deletions = []
    modifications = []

    old_keys = set(old.keys())
    new_keys = set(new.keys())

    # Added keys
    for key in (new_keys - old_keys):
        additions.append(f"{prefix}.{key}")

    # Deleted keys
    for key in (old_keys - new_keys):
        deletions.append(f"{prefix}.{key}")

    # Changed keys
    for key in (old_keys & new_keys):
        old_val = old[key]
        new_val = new[key]

        if old_val != new_val:
            if isinstance(old_val, dict) and isinstance(new_val, dict):
                sub_add, sub_del, sub_mod = _compare_dicts(f"{prefix}.{key}", old_val, new_val)
                additions.extend(sub_add)
                deletions.extend(sub_del)
                modifications.extend(sub_mod)
            elif isinstance(old_val, list) and isinstance(new_val, list):
                sub_add, sub_del, sub_mod = _compare_lists(f"{prefix}.{key}", old_val, new_val)
                additions.extend(sub_add)
                deletions.extend(sub_del)
                modifications.extend(sub_mod)
            else:
                modifications.append(f"{prefix}.{key}: {old_val} -> {new_val}")

    return additions, deletions, modifications


def diff_scenarios(old: dict[str, Any], new: dict[str, Any]) -> DiffResult:
    """Compare two scenario definitions and return differences.

    Args:
        old: The old scenario definition
        new: The new scenario definition

    Returns:
        DiffResult with detailed differences
    """
    identifier = new.get("identifier", old.get("identifier", "unknown"))

    # Skip version and certification fields for comparison
    skip_keys = {"version", "certification", "created_at", "updated_at"}

    old_filtered = {k: v for k, v in old.items() if k not in skip_keys}
    new_filtered = {k: v for k, v in new.items() if k not in skip_keys}

    if old_filtered == new_filtered:
        return DiffResult(identifier=identifier, changed=False)

    additions, deletions, modifications = _compare_dicts("", old_filtered, new_filtered)

    return DiffResult(
        identifier=identifier,
        changed=True,
        additions=additions,
        deletions=deletions,
        modifications=modifications,
        details={
            "old_hash": compute_scenario_hash(old_filtered),
            "new_hash": compute_scenario_hash(new_filtered),
        },
    )


def diff_scenario_files(old_path: Path, new_path: Path) -> DiffResult:
    """Compare two scenario files."""
    with old_path.open() as f:
        old_data = yaml.safe_load(f)

    with new_path.open() as f:
        new_data = yaml.safe_load(f)

    return diff_scenarios(old_data, new_data)


# ---------------------------------------------------------------------------
# Scenario Library API
# ---------------------------------------------------------------------------

@dataclass
class ScenarioLibrary:
    """Collection of scenarios with metadata."""

    scenarios: list[VersionedScenarioMetadata] = field(default_factory=list)
    name: str = "default"
    description: str = ""
    version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "scenario_count": len(self.scenarios),
            "scenarios": [s.to_dict() for s in self.scenarios],
        }

    def filter_by_tags(self, tags: list[str]) -> list[VersionedScenarioMetadata]:
        """Filter scenarios by tags."""
        return [s for s in self.scenarios if any(t in s.tags for t in tags)]

    def filter_by_certification(self, level: CertificationLevel) -> list[VersionedScenarioMetadata]:
        """Filter scenarios by certification level."""
        return [s for s in self.scenarios if s.certification.level == level]

    def filter_certified(self) -> list[VersionedScenarioMetadata]:
        """Get only certified scenarios."""
        return self.filter_by_certification(CertificationLevel.CERTIFIED)

    def filter_by_release_pack(self, pack: str) -> list[VersionedScenarioMetadata]:
        """Filter scenarios by release pack."""
        return [s for s in self.scenarios if s.certification.release_pack == pack]

    def get_by_identifier(self, identifier: str) -> VersionedScenarioMetadata | None:
        """Get a scenario by identifier."""
        for s in self.scenarios:
            if s.identifier == identifier:
                return s
        return None


def load_scenario_library(directory: Path) -> ScenarioLibrary:
    """Load a scenario library from a directory.

    Args:
        directory: Directory containing scenario YAML files

    Returns:
        ScenarioLibrary with all scenarios
    """
    scenarios = []

    for yaml_file in directory.rglob("*.yaml"):
        try:
            with yaml_file.open() as f:
                data = yaml.safe_load(f)

            if not data or not isinstance(data, dict):
                continue

            # Extract metadata
            version = ScenarioVersion.from_dict(data.get("version", {}))
            certification = ScenarioCertification.from_dict(data.get("certification", {}))

            # Get fault info
            faults = data.get("faults", [])
            fault_types = list(set(f.get("type", "") for f in faults if isinstance(f, dict)))

            metadata = VersionedScenarioMetadata(
                identifier=data.get("identifier", yaml_file.stem),
                summary=data.get("summary", ""),
                version=version,
                certification=certification,
                tags=list(data.get("tags", [])),
                fault_count=len(faults),
                fault_types=fault_types,
                difficulty=data.get("difficulty", 0.0),
                difficulty_label=data.get("difficulty_label", "Easy"),
                source_path=str(yaml_file),
                content_hash=compute_scenario_hash(data),
            )

            scenarios.append(metadata)

        except Exception:
            # Skip invalid files
            continue

    return ScenarioLibrary(
        scenarios=scenarios,
        name=directory.name,
        description=f"Scenarios from {directory}",
    )


def get_scenario_api_response(library: ScenarioLibrary) -> dict[str, Any]:
    """Format library for API response.

    This is what the dashboard would receive when browsing scenarios.
    """
    return {
        "library": library.to_dict(),
        "certified_count": len(library.filter_certified()),
        "release_packs": list(set(
            s.certification.release_pack
            for s in library.scenarios
            if s.certification.release_pack
        )),
        "all_tags": list(set(
            tag
            for s in library.scenarios
            for tag in s.tags
        )),
    }
