"""Static agent discovery helpers leveraging taxonomy signals."""

from __future__ import annotations
from collections.abc import Iterable, Sequence

import json
from dataclasses import dataclass
from pathlib import Path

from .agent import (
    AgentCapability,
    AgentCategory,
    AgentMetadata,
    DetectionSignal,
    discover_agent_metadata,
    iter_detection_signals,
    STATE_DIR,
    load_registry_discovery_rules,
    update_registry_discovery_rules,
)
from .state import get_state_dir

DEFAULT_INCLUDE_PATTERNS: tuple[str, ...] = ("*.py",)
DEFAULT_EXCLUDE_DIRS: set[str] = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
}

def _discovery_rules_path() -> Path:
    path = get_state_dir() / "agent-discovery.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

# Backward-compatible constant (evaluated at import).
DISCOVERY_RULES_PATH = _discovery_rules_path()

SIGNAL_CAPABILITY_MAP: dict[str, AgentCapability] = {
    "function-calling": AgentCapability.TOOL_CALLING,
    "mcp-schema": AgentCapability.MCP,
    "langgraph": AgentCapability.ORCHESTRATION,
    "crewai": AgentCapability.ORCHESTRATION,
    "autogen": AgentCapability.ORCHESTRATION,
    "airflow-dag": AgentCapability.WORKFLOW,
    "prefect-flow": AgentCapability.WORKFLOW,
    "dagster-job": AgentCapability.WORKFLOW,
    "vision-model": AgentCapability.MULTIMODAL_IO,
    "media-preprocess": AgentCapability.MULTIMODAL_IO,
    "custom-runner": AgentCapability.CUSTOM_RUNTIME,
    "khaos-decorator": AgentCapability.CUSTOM_RUNTIME,
}

FRAMEWORK_SIGNAL_MAP: dict[str, str] = {
    "langgraph": "langgraph",
    "crewai": "crewai",
    "autogen": "autogen",
    "prefect-flow": "prefect",
    "airflow-dag": "airflow",
    "dagster-job": "dagster",
}

CATEGORY_BASE_CAPABILITIES: dict[AgentCategory, tuple[AgentCapability, ...]] = {
    AgentCategory.TOOL_AGENT: (AgentCapability.TOOL_CALLING,),
    AgentCategory.ORCHESTRATED: (AgentCapability.ORCHESTRATION,),
    AgentCategory.WORKFLOW: (AgentCapability.WORKFLOW,),
    AgentCategory.MULTIMODAL: (AgentCapability.MULTIMODAL_IO,),
    AgentCategory.CUSTOM: (AgentCapability.CUSTOM_RUNTIME,),
}

def load_discovery_rules() -> dict[str, list[str]]:
    rules = {
        "include": list(DEFAULT_INCLUDE_PATTERNS),
        "exclude_dirs": sorted(DEFAULT_EXCLUDE_DIRS),
    }
    registry_rules = load_registry_discovery_rules()
    include_reg = registry_rules.get("include")
    if include_reg:
        rules["include"] = [str(item) for item in include_reg if str(item).strip()]
    exclude_reg = registry_rules.get("exclude_dirs")
    if exclude_reg:
        rules["exclude_dirs"] = [str(item) for item in exclude_reg if str(item).strip()]
    path = _discovery_rules_path()
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            include = data.get("include")
            if isinstance(include, list) and include:
                rules["include"] = [str(item) for item in include]
            exclude = data.get("exclude_dirs")
            if isinstance(exclude, list) and exclude:
                rules["exclude_dirs"] = [str(item) for item in exclude]
    if not rules["include"]:
        rules["include"] = list(DEFAULT_INCLUDE_PATTERNS)
    if not rules["exclude_dirs"]:
        rules["exclude_dirs"] = sorted(DEFAULT_EXCLUDE_DIRS)
    return rules

def save_discovery_rules(rules: dict[str, list[str]]) -> None:
    path = _discovery_rules_path()
    normalized = {
        "include": [str(item) for item in rules.get("include", []) if str(item).strip()],
        "exclude_dirs": [
            str(item) for item in rules.get("exclude_dirs", []) if str(item).strip()
        ],
    }
    path.write_text(json.dumps(normalized, indent=2))
    update_registry_discovery_rules(normalized)

@dataclass
class DiscoveredAgent:
    metadata: AgentMetadata
    entrypoint: Path
    signals: list[DetectionSignal]
    decorator_defined: bool
    confidence: float

def scan_agents(
    root: Path,
    *,
    include_patterns: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
) -> list[DiscoveredAgent]:
    root = root.expanduser().resolve()
    rules = load_discovery_rules()
    includes = tuple(include_patterns or rules.get("include", DEFAULT_INCLUDE_PATTERNS))
    excluded = set(exclude_dirs or rules.get("exclude_dirs", DEFAULT_EXCLUDE_DIRS))

    results: list[DiscoveredAgent] = []
    for path in _iter_candidate_paths(root, includes, excluded):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        decorator_defined = "@khaosagent" in text
        signals = _detect_signals(text)
        if not decorator_defined and not signals:
            continue
        try:
            metadata = discover_agent_metadata(path)
        except (OSError, ValueError):
            continue
        _apply_inference(metadata, signals, decorator_defined)
        confidence = _confidence_for(
            discovered_via_decorator=decorator_defined, signal_count=len(signals)
        )
        results.append(
            DiscoveredAgent(
                metadata=metadata,
                entrypoint=path,
                signals=signals,
                decorator_defined=decorator_defined,
                confidence=confidence,
            )
        )
    return results

def _iter_candidate_paths(
    root: Path,
    include_patterns: Sequence[str],
    exclude_dirs: set[str],
) -> Iterable[Path]:
    seen: set[Path] = set()
    for pattern in include_patterns:
        for path in root.rglob(pattern):
            if path in seen or not path.is_file():
                continue
            if any(part in exclude_dirs for part in path.parts):
                continue
            seen.add(path)
            yield path

def _detect_signals(contents: str) -> list[DetectionSignal]:
    triggered: list[DetectionSignal] = []
    for signal in iter_detection_signals():
        if signal.imports and not any(_contains_import(contents, module) for module in signal.imports):
            continue
        if signal.keywords and not any(keyword in contents for keyword in signal.keywords):
            continue
        triggered.append(signal)
    return triggered

def _contains_import(contents: str, module: str) -> bool:
    pattern = f"import {module}"
    pattern_from = f"from {module}"
    return pattern in contents or pattern_from in contents

def _apply_inference(
    metadata: AgentMetadata,
    signals: list[DetectionSignal],
    decorator_defined: bool,
) -> None:
    if metadata.category is None:
        metadata.category = _infer_category(signals)
    if metadata.category is None:
        metadata.category = AgentCategory.LLM_INFERENCE

    if metadata.framework is None:
        for signal in signals:
            framework = FRAMEWORK_SIGNAL_MAP.get(signal.id)
            if framework:
                metadata.framework = framework
                break

    capability_values = set(metadata.capabilities or [])
    for capability in CATEGORY_BASE_CAPABILITIES.get(metadata.category, ()):  # type: ignore[arg-type]
        capability_values.add(capability.value)
    for signal in signals:
        mapped = SIGNAL_CAPABILITY_MAP.get(signal.id)
        if mapped:
            capability_values.add(mapped.value)
    metadata.capabilities = sorted(capability_values)
    if decorator_defined:
        metadata.detection_source = "decorator"
    elif signals:
        metadata.detection_source = f"signal:{signals[0].id}"
    else:
        metadata.detection_source = "heuristic"
    metadata.confidence = _confidence_for(
        discovered_via_decorator=decorator_defined, signal_count=len(signals)
    )
    metadata.signals = [signal.id for signal in signals]

def _infer_category(signals: list[DetectionSignal]) -> AgentCategory | None:
    if not signals:
        return None
    priority_order = [
        AgentCategory.ORCHESTRATED,
        AgentCategory.WORKFLOW,
        AgentCategory.TOOL_AGENT,
        AgentCategory.MULTIMODAL,
        AgentCategory.CUSTOM,
        AgentCategory.LLM_INFERENCE,
    ]
    for category in priority_order:
        if any(signal.category == category for signal in signals):
            return category
    return signals[0].category

def _confidence_for(*, discovered_via_decorator: bool, signal_count: int) -> float:
    if discovered_via_decorator:
        return 0.95
    if signal_count == 0:
        return 0.4
    return min(0.5 + 0.1 * signal_count, 0.9)

__all__ = ["DiscoveredAgent", "scan_agents"]
