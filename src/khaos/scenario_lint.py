"""Lightweight scenario linting for assertion/path compatibility."""

from __future__ import annotations
from collections.abc import Iterable

import json
from pathlib import Path

from khaos.chaos.scenario import AssertionDefinition, ChaosScenario
from khaos.state import get_state_dir

def lint_scenario(scenario: ChaosScenario) -> list[str]:
    """Return warnings for common scenario/agent compatibility issues."""

    warnings: list[str] = []

    if scenario.security_tests_enabled and not scenario.security_attacks:
        warnings.append("Security is enabled but no security_attacks are defined.")

    # Basic assertion path sanity (non-empty, unique names)
    seen_names: set[str] = set()
    for assertion in scenario.assertions:
        if not assertion.path:
            warnings.append(f"Assertion '{assertion.name}' has an empty path.")
        if assertion.name in seen_names:
            warnings.append(f"Assertion name '{assertion.name}' is duplicated.")
        seen_names.add(assertion.name)

    # Empty goals/assertions
    if scenario.assertions and not scenario.goals:
        warnings.append("Assertions are defined but no goals reference them.")
    if scenario.goals and not scenario.assertions:
        warnings.append("Goals are defined but no assertions exist to satisfy them.")
    for goal in scenario.goals:
        missing = [name for name in goal.assertions if name not in {a.name for a in scenario.assertions}]
        if missing:
            warnings.append(f"Goal '{goal.name}' references unknown assertions: {', '.join(missing)}.")

    return warnings

def lint_against_sample(scenario: ChaosScenario, sample_payload: dict) -> list[str]:
    """Validate assertion paths against a sample agent payload."""

    warnings: list[str] = []
    for assertion in scenario.assertions:
        if not _path_exists(sample_payload, assertion.path):
            warnings.append(f"Assertion '{assertion.name}' path '{assertion.path}' not found in sample payload.")
    return warnings

def load_sample(path: Path | None = None, inline: str | None = None) -> dict | None:
    """Load a sample payload from a file or inline JSON."""

    if inline:
        try:
            return json.loads(inline)
        except Exception:
            return None
    if path is None:
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None

def load_auto_sample_from_traces() -> dict | None:
    """Best-effort sample payload from the latest transport.receive event in the state dir."""

    runs_dir = get_state_dir() / "runs"
    if not runs_dir.exists():
        return None
    trace_files = sorted(runs_dir.glob("trace-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in trace_files:
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for event in reversed(data):
            if not isinstance(event, dict):
                continue
            if event.get("event") != "transport.receive":
                continue
            payload = event.get("payload")
            if isinstance(payload, dict) and payload:
                return payload
    return None

def _path_exists(payload: dict, path: str) -> bool:
    """Simple dotted-path walker."""

    if not path:
        return False
    parts = path.split(".")
    current: any = payload
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        return False
    return True
