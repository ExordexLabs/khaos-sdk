"""Scenario registry responsible for discovery and caching."""

from __future__ import annotations
from collections.abc import Iterable, Mapping, Sequence

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from ..state import get_state_dir
from .scenario import (
    ChaosScenario,
    ScenarioMetadata,
    ScenarioValidationError,
    load_scenario_from_yaml,
)

def _default_cache_dir() -> Path:
    """Return the default cache directory under the user's home."""

    return get_state_dir() / "cache"

def _iter_scenario_files(paths: Sequence[Path]) -> Iterable[Path]:
    """Yield candidate scenario YAML files in the configured directories."""

    for base in paths:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.yaml")):
            if path.is_file():
                yield path
        for path in sorted(base.rglob("*.yml")):
            if path.is_file():
                yield path

@dataclass(slots=True)
class DiscoveredScenario:
    """Data carrier linking metadata with its source."""

    metadata: ScenarioMetadata
    path: Path

@dataclass(slots=True)
class InvalidScenario:
    """Captures validation issues discovered during registry scans."""

    path: Path
    error: str

class ScenarioRegistry:
    """Filesystem-backed registry for chaos scenarios."""

    def __init__(
        self,
        search_paths: Sequence[Path],
        cache_dir: Path | None = None,
    ) -> None:
        self._search_paths = tuple(search_paths)
        self._cache_dir = cache_dir or _default_cache_dir()
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._scenarios, self._invalid_entries = self._discover()

    def _discover(self) -> tuple[dict[str, DiscoveredScenario], list[InvalidScenario]]:
        discovered: dict[str, DiscoveredScenario] = {}
        invalid: list[InvalidScenario] = []
        for path in _iter_scenario_files(self._search_paths):
            try:
                scenario = load_scenario_from_yaml(path)
            except ScenarioValidationError as exc:
                invalid.append(InvalidScenario(path=path, error=str(exc)))
                continue
            metadata = scenario.metadata
            metadata.source_path = path
            # Prefer the first occurrence of an identifier to avoid accidental overrides.
            discovered.setdefault(metadata.identifier, DiscoveredScenario(metadata, path))
        self._write_index(discovered, invalid)
        return discovered, invalid

    @property
    def search_paths(self) -> Sequence[Path]:
        return self._search_paths

    def list_metadata(self) -> list[ScenarioMetadata]:
        """Return metadata for all discovered scenarios."""

        return [entry.metadata for entry in self._scenarios.values()]

    def get(self, identifier: str) -> ChaosScenario:
        """Load a scenario by identifier, refreshing cache on success."""

        entry = self._scenarios.get(identifier)
        if entry is None:
            raise ScenarioValidationError(f"Scenario '{identifier}' was not found in registry")
        scenario = load_scenario_from_yaml(entry.path)
        self._write_cache(scenario)
        return scenario

    def validate(self, path: Path) -> ChaosScenario:
        """Validate an arbitrary path and write it to cache if valid."""

        scenario = load_scenario_from_yaml(path)
        self._write_cache(scenario)
        return scenario

    def refresh(self) -> None:
        """Re-run discovery to pick up newly added scenarios."""

        self._scenarios, self._invalid_entries = self._discover()

    @property
    def invalid_entries(self) -> list[InvalidScenario]:
        """Return scenarios that failed validation during discovery."""

        return list(self._invalid_entries)

    def _write_cache(self, scenario: ChaosScenario) -> None:
        payload = scenario.to_payload()
        rendered = json.dumps(payload, sort_keys=True)
        digest = sha256(rendered.encode("utf-8")).hexdigest()
        cache_name = f"{scenario.metadata.identifier}-{digest}.json"
        cache_path = self._cache_dir / cache_name
        cache_path.write_text(rendered)

    def _write_index(
        self,
        discovered: dict[str, DiscoveredScenario],
        invalid: list[InvalidScenario],
    ) -> None:
        """Persist an index describing registry state for tooling."""

        index_path = self._cache_dir / "index.json"
        index_payload = {
            "scenarios": [
                {
                    "identifier": entry.metadata.identifier,
                    "summary": entry.metadata.summary,
                    "fault_count": entry.metadata.fault_count,
                    "tags": list(entry.metadata.tags),
                    "fault_types": list(entry.metadata.fault_types),
                    "difficulty": entry.metadata.difficulty,
                    "difficulty_label": entry.metadata.difficulty_label,
                    "source_path": str(entry.path),
                }
                for entry in discovered.values()
            ],
            "invalid": [
                {
                    "path": str(item.path),
                    "error": item.error,
                }
                for item in invalid
            ],
        }
        index_path.write_text(json.dumps(index_payload, indent=2, sort_keys=True))

def build_default_registry(
    project_root: Path | None = None, cache_dir: Path | None = None
) -> ScenarioRegistry:
    """Construct a registry using project defaults."""

    base = project_root or Path(__file__).resolve().parents[3]
    default_path = base / "sdk" / "scenarios"
    return ScenarioRegistry(search_paths=[default_path], cache_dir=cache_dir)
