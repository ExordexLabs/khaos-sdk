from __future__ import annotations

from pathlib import Path
from typing import Any

from .comparison.models import ComparisonReport  # re-export for typing hints if needed

BASE_PATH = Path(__file__).resolve().parents[2] / "scenarios"


def _scenario(name: str) -> Path:
    return BASE_PATH / f"{name}.yaml"


def _scenario_rel(*parts: str) -> Path:
    return BASE_PATH.joinpath(*parts)


BUILTIN_SUITES: dict[str, dict[str, Any]] = {
    "baseline": {
        "identifier": "baseline",
        "description": "Light faults for fast local checks.",
        "scenario": _scenario("quickstart"),
    },
    "stress": {
        "identifier": "stress",
        "description": "Heavy latency/tool faults for robustness.",
        "scenario": _scenario("latency_storm"),
    },
    "reliability": {
        "identifier": "reliability",
        "description": "Multi-run consistency (uses quickstart, multiple runs).",
        "scenario": _scenario("quickstart"),
        "runs": 3,
    },
    "security": {
        "identifier": "security",
        "description": "Security-focused run (uses quickstart_all_lenses).",
        "scenario": _scenario("quickstart_all_lenses"),
    },
    "all": {
        "identifier": "all",
        "description": "Comprehensive run across lenses.",
        "scenario": _scenario("quickstart_all_lenses"),
    },
    "release": {
        "identifier": "release",
        "description": "Release pack v1 (3–5 min): baseline + resilience + tooling + LLM turbulence + security.",
        "scenarios": [
            _scenario_rel("release", "v1", "baseline.yaml"),
            _scenario_rel("release", "v1", "resilience.yaml"),
            _scenario_rel("release", "v1", "tooling_http.yaml"),
            _scenario_rel("release", "v1", "llm_resilience.yaml"),
            _scenario_rel("release", "v1", "security_smoke.yaml"),
        ],
        "security_attack_limit": 20,
    },
    "quick": {
        "identifier": "quick",
        "description": "Quick check (<=2 min): baseline + security quickscan.",
        "scenarios": [
            _scenario_rel("release", "v1", "baseline.yaml"),
            _scenario_rel("release", "v1", "security_smoke.yaml"),
        ],
        "security_attack_limit": 10,
    },
}
