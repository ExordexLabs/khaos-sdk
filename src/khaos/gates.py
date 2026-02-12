"""Deploy gate evaluation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Iterable

import yaml

from khaos.evaluator.base import EvaluationArtifact

@dataclass(slots=True)
class GateRule:
    """Single gate threshold definition."""

    name: str
    metric: str
    minimum: float | None = None
    maximum: float | None = None
    recommendation: str | None = None

@dataclass(slots=True)
class GateOutcome:
    """Result for an evaluated gate."""

    rule: GateRule
    value: float | None
    passed: bool

    @property
    def name(self) -> str:  # pragma: no cover - convenience
        return self.rule.name

@dataclass(slots=True)
class GateConfig:
    """Scenario + gate configuration loaded from YAML."""

    scenario: str | None
    scenario_file: Path | None
    scenario_id: str | None
    seed: int
    gates: list[GateRule]

def load_gate_config(path: Path) -> GateConfig:
    """Load gate configuration from YAML."""

    if not path.exists():
        raise FileNotFoundError(f"Gate config not found at {path}")
    raw = yaml.safe_load(path.read_text()) or {}
    version = raw.get("version", 1)
    if version != 1:
        raise ValueError("Unsupported gate config version. Expected '1'.")

    scenario_value = raw.get("scenario")
    scenario_file = Path(scenario_value).expanduser() if scenario_value and Path(scenario_value).exists() else None
    scenario_id = raw.get("scenario_id")
    seed = int(raw.get("seed", 42))
    gates_payload = raw.get("gates") or []
    if not isinstance(gates_payload, Iterable):
        raise ValueError("Config 'gates' must be a list of gate definitions.")

    gates: list[GateRule] = []
    for entry in gates_payload:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("metric") or "gate"
        metric = entry.get("metric")
        if not metric:
            raise ValueError("Each gate must supply a 'metric' field.")
        gates.append(
            GateRule(
                name=name,
                metric=metric,
                minimum=entry.get("min") if entry.get("min") is not None else entry.get("minimum"),
                maximum=entry.get("max") if entry.get("max") is not None else entry.get("maximum"),
                recommendation=entry.get("recommendation") or entry.get("message"),
            )
        )

    return GateConfig(
        scenario=scenario_value if scenario_file is None else None,
        scenario_file=scenario_file,
        scenario_id=scenario_id,
        seed=seed,
        gates=gates,
    )

def _metric_lookup(
    artifacts: list[EvaluationArtifact],
    report: dict[str, Any] | None,
    reliability_report: dict[str, Any] | None = None,
    comparison_report: dict[str, Any] | None = None,
) -> dict[str, float]:
    """Flatten artifact and report metrics into a single lookup table.

    Supported metric namespaces:
    - Standard metrics from artifacts (e.g., security.score, llm.observability)
    - resilience.* from resilience report
    - consistency.* from reliability report
    - comparison.* from comparison report (delta values for regression gating)
    """

    lookup: dict[str, float] = {}
    for artifact in artifacts:
        lookup[artifact.name] = float(artifact.value)
        if artifact.name == "security.score":
            details = artifact.details or {}
            tested = float(details.get("attacks_tested") or 0)
            blocked = float(details.get("attacks_blocked") or 0)
            if tested > 0:
                lookup["security.attacks_blocked_rate"] = blocked / tested
        if artifact.name == "llm.observability" and isinstance(artifact.details, dict):
            lookup["llm.total_cost_usd"] = float(artifact.details.get("cost_usd") or 0.0)
            lookup["llm.avg_latency_ms"] = float(artifact.details.get("avg_latency_ms") or 0.0)

    report = report or {}
    if isinstance(report, dict):
        if "summary_score" in report:
            lookup.setdefault("resilience.score", float(report["summary_score"]))
        for metric in report.get("metrics", []) or []:
            name = metric.get("name")
            value = metric.get("value")
            if name and value is not None:
                lookup.setdefault(name, float(value))

    if reliability_report:
        consistency = reliability_report.get("consistency_score")
        if consistency is not None:
            lookup["consistency.score"] = float(consistency)
        pass_rate = reliability_report.get("pass_rate")
        if pass_rate is not None:
            lookup["consistency.pass_rate"] = float(pass_rate)
        avg_similarity = reliability_report.get("average_similarity")
        if avg_similarity is not None:
            lookup["consistency.avg_similarity"] = float(avg_similarity)

    # Extract comparison delta metrics for regression gating
    if comparison_report:
        _extract_comparison_metrics(comparison_report, lookup)

    return lookup

def _extract_comparison_metrics(comparison_report: dict[str, Any], lookup: dict[str, float]) -> None:
    """Extract comparison delta metrics into the lookup table.

    Available comparison metrics:
    - comparison.resilience_delta: Change in resilience score (positive = improved)
    - comparison.security_delta: Change in security score (positive = improved)
    - comparison.cost_delta: Change in cost (negative = improved/cheaper)
    - comparison.latency_delta: Change in latency (negative = improved/faster)
    - comparison.functional_similarity: Output similarity score (0-1)
    - comparison.has_regression: 1.0 if any regression detected, 0.0 otherwise
    - comparison.has_security_regression: 1.0 if security regressed, 0.0 otherwise
    - comparison.new_vulnerabilities: Count of new vulnerabilities
    """
    # Resilience delta
    resilience = comparison_report.get("resilience", {})
    if resilience:
        resilience_score = resilience.get("resilience_score", {})
        delta = resilience_score.get("absolute_delta")
        if delta is not None:
            lookup["comparison.resilience_delta"] = float(delta)
        # Track if resilience regressed
        if resilience_score.get("trend") == "regressed":
            lookup["comparison.has_resilience_regression"] = 1.0
        else:
            lookup.setdefault("comparison.has_resilience_regression", 0.0)

    # Security delta
    security = comparison_report.get("security")
    if security:
        security_score = security.get("security_score", {})
        delta = security_score.get("absolute_delta")
        if delta is not None:
            lookup["comparison.security_delta"] = float(delta)
        # Track if security regressed
        if security_score.get("trend") == "regressed":
            lookup["comparison.has_security_regression"] = 1.0
        else:
            lookup.setdefault("comparison.has_security_regression", 0.0)
        # Count new vulnerabilities
        new_vulns = security.get("new_vulnerabilities", [])
        lookup["comparison.new_vulnerabilities"] = float(len(new_vulns))

    # Structural deltas (cost, latency)
    structural = comparison_report.get("structural", {})
    if structural:
        cost = structural.get("cost", {})
        cost_delta = cost.get("absolute_delta")
        if cost_delta is not None:
            lookup["comparison.cost_delta"] = float(cost_delta)

        latency = structural.get("latency", {})
        latency_delta = latency.get("absolute_delta")
        if latency_delta is not None:
            lookup["comparison.latency_delta"] = float(latency_delta)

    # Functional similarity
    functional = comparison_report.get("functional", {})
    if functional:
        similarity = functional.get("output_similarity")
        if similarity is not None:
            lookup["comparison.functional_similarity"] = float(similarity)
        divergent_count = len(functional.get("divergent_outputs", []))
        lookup["comparison.divergent_outputs"] = float(divergent_count)

    # Overall regression flag (any regression = 1.0)
    has_regression = (
        lookup.get("comparison.has_resilience_regression", 0.0) == 1.0
        or lookup.get("comparison.has_security_regression", 0.0) == 1.0
        or lookup.get("comparison.new_vulnerabilities", 0.0) > 0
        or lookup.get("comparison.functional_similarity", 1.0) < 0.8
    )
    lookup["comparison.has_regression"] = 1.0 if has_regression else 0.0

def evaluate_gates(
    rules: list[GateRule],
    artifacts: list[EvaluationArtifact],
    report: dict[str, Any] | None,
    reliability_report: dict[str, Any] | None = None,
    comparison_report: dict[str, Any] | None = None,
) -> list[GateOutcome]:
    """Evaluate configured gates against collected metrics.

    Args:
        rules: List of gate rules to evaluate
        artifacts: Evaluation artifacts from the run
        report: Resilience report from the run
        reliability_report: Optional reliability sweep report
        comparison_report: Optional comparison report for regression gates

    Comparison metrics available when comparison_report is provided:
        - comparison.resilience_delta: min 0 to prevent regression
        - comparison.security_delta: min 0 to prevent regression
        - comparison.cost_delta: max 0 to prevent cost increase
        - comparison.has_regression: max 0 to fail on any regression
        - comparison.new_vulnerabilities: max 0 to fail on new vulns
        - comparison.functional_similarity: min 0.8 for output stability
    """

    lookup = _metric_lookup(
        artifacts, report,
        reliability_report=reliability_report,
        comparison_report=comparison_report,
    )
    outcomes: list[GateOutcome] = []
    for rule in rules:
        value = lookup.get(rule.metric)
        passed = True
        if value is None:
            passed = False
        if rule.minimum is not None and (value is None or value < rule.minimum):
            passed = False
        if rule.maximum is not None and (value is None or value > rule.maximum):
            passed = False
        outcomes.append(GateOutcome(rule=rule, value=value, passed=passed))
    return outcomes
