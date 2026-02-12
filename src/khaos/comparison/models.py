"""Schema objects shared by the comparison workflow."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TrendLabel = Literal["improved", "regressed", "neutral", "unknown"]


class ComparisonRunDescriptor(BaseModel):
    """Minimal metadata about a baseline or candidate run."""

    model_config = ConfigDict(frozen=True)

    run_id: str = Field(..., description="Unique identifier for the captured run.")
    agent_name: str | None = Field(
        default=None,
        description="Human readable agent label for the UI.",
    )
    scenario_identifier: str | None = Field(
        default=None,
        description="Scenario exercised during the run.",
    )
    scenario_label: str | None = Field(
        default=None,
        description="Friendly name for the scenario (optional, for presentation).",
    )
    seed: int | None = Field(
        default=None,
        description="Seed that configured stochastic parts of the scenario, if provided.",
    )
    executed_at: datetime | None = Field(
        default=None,
        description="Timestamp when the run completed (UTC).",
    )
    resilience_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Overall resilience score captured for the run (0-100).",
    )
    goal_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Goal component score, included for quick reference in reports.",
    )
    recovery_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Recovery component score for the run (0-100).",
    )
    stability_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Stability component score for the run (0-100).",
    )
    security_score: float | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Overall security score for the run (0-100).",
    )
    attacks_blocked: int | None = Field(
        default=None,
        ge=0,
        description="Number of security attacks successfully blocked.",
    )
    vulnerabilities_found: int | None = Field(
        default=None,
        ge=0,
        description="Number of vulnerabilities detected in the run.",
    )


class MetricDelta(BaseModel):
    """Describes how a scalar metric changed between baseline and candidate runs."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Metric identifier used for lookups (e.g. cost.total_usd).")
    label: str = Field(..., description="Human readable label rendered in reports.")
    unit: str | None = Field(
        default=None,
        description="Unit string appended to formatted values.",
    )
    baseline_value: float | None = Field(
        default=None,
        description="Metric value recorded for the baseline run.",
    )
    candidate_value: float | None = Field(
        default=None,
        description="Metric value recorded for the candidate run.",
    )
    absolute_delta: float | None = Field(
        default=None,
        description="candidate_value - baseline_value.",
    )
    percent_delta: float | None = Field(
        default=None,
        description="Percentage change relative to baseline (0.12 == +12%).",
    )
    trend: TrendLabel = Field(
        default="unknown",
        description="Classification used for UI cues (improved/regressed/neutral).",
    )


class StructuralComparison(BaseModel):
    """Cost/latency/tooling deltas."""

    model_config = ConfigDict(frozen=True)

    cost: MetricDelta
    latency: MetricDelta
    tool_calls: MetricDelta
    cost_source: str | None = Field(
        default=None,
        description="Confidence label for cost metrics (reported|estimated|mixed|unknown).",
    )
    additional_metrics: tuple[MetricDelta, ...] = Field(
        default_factory=tuple,
        description="Optional structural metrics gathered for the comparison.",
    )


class ResilienceComparison(BaseModel):
    """Resilience triad deltas and supporting rollup."""

    model_config = ConfigDict(frozen=True)

    resilience_score: MetricDelta
    goal_score: MetricDelta
    recovery_score: MetricDelta
    stability_score: MetricDelta
    additional_metrics: tuple[MetricDelta, ...] = Field(
        default_factory=tuple,
        description="Optional resilience-related metrics for richer dashboards.",
    )


class DivergentOutput(BaseModel):
    """Describes a single divergent output when aligning traces."""

    model_config = ConfigDict(frozen=True)

    step_index: int = Field(
        ..., ge=0, description="Index within the aligned trace window that diverged."
    )
    label: str | None = Field(
        default=None,
        description="Optional label summarizing the agent step (tool call, goal, etc).",
    )
    baseline_output: str | None = Field(
        default=None,
        description="Captured text/value for the baseline run at this step.",
    )
    candidate_output: str | None = Field(
        default=None,
        description="Captured text/value for the candidate run at this step.",
    )
    similarity_score: float = Field(
        ..., ge=0.0, le=1.0, description="Semantic/textual similarity between outputs."
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata (tool args, latency, traces) aiding triage.",
    )


class FunctionalComparison(BaseModel):
    """Functional lens summary and divergent output list."""

    model_config = ConfigDict(frozen=True)

    output_similarity: float = Field(
        ..., ge=0.0, le=1.0, description="Overall fraction of aligned outputs that match."
    )
    divergent_outputs: tuple[DivergentOutput, ...] = Field(
        default_factory=tuple,
        description="Ordered divergent outputs surfaced to the user.",
    )
    notes: str | None = Field(
        default=None, description="Optional textual summary for CLI/dashboard copy."
    )


class SecurityComparison(BaseModel):
    """Security lens deltas including attack results and vulnerability tracking."""

    model_config = ConfigDict(frozen=True)

    security_score: MetricDelta = Field(
        ..., description="Overall security score delta (0-100)."
    )
    prompt_injection_defense: MetricDelta = Field(
        ..., description="Prompt injection defense score delta (0-100)."
    )
    tool_validation_score: MetricDelta = Field(
        ..., description="Tool output validation score delta (0-100)."
    )
    leakage_prevention_score: MetricDelta = Field(
        ..., description="System prompt leakage prevention score delta (0-100)."
    )
    attacks_tested: int = Field(
        ..., ge=0, description="Total number of security attacks tested."
    )
    attacks_blocked_baseline: int = Field(
        ..., ge=0, description="Number of attacks blocked by baseline run."
    )
    attacks_blocked_candidate: int = Field(
        ..., ge=0, description="Number of attacks blocked by candidate run."
    )
    new_vulnerabilities: tuple[str, ...] = Field(
        default_factory=tuple,
        description="List of new vulnerabilities found in candidate (vs baseline).",
    )
    fixed_vulnerabilities: tuple[str, ...] = Field(
        default_factory=tuple,
        description="List of vulnerabilities fixed in candidate (vs baseline).",
    )
    additional_metrics: tuple[MetricDelta, ...] = Field(
        default_factory=tuple,
        description="Optional security-related metrics for richer dashboards.",
    )


class ComparisonReport(BaseModel):
    """Full comparison artifact shared by CLI, API, and dashboard."""

    model_config = ConfigDict(frozen=True)

    version: str = Field(
        default="1.0",
        description="Schema version enabling backward compatible decoder logic.",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the report was assembled (UTC).",
    )
    baseline: ComparisonRunDescriptor
    candidate: ComparisonRunDescriptor
    structural: StructuralComparison
    resilience: ResilienceComparison
    security: SecurityComparison | None = Field(
        default=None,
        description="Security lens comparison (optional, only present if security tests enabled).",
    )
    functional: FunctionalComparison
    summary: str | None = Field(
        default=None,
        description="High level summary callout displayed in the CLI/dashboard.",
    )
    annotations: dict[str, Any] = Field(
        default_factory=dict,
        description="Open-ended metadata for future lenses or UI hints.",
    )
