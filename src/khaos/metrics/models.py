"""Structured data representations for resilience metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

@dataclass(slots=True)
class MetricDatum:
    """Represents a single metric emitted by the evaluator."""

    name: str
    value: float
    unit: str
    captured_at: datetime
    metadata: dict[str, object] = field(default_factory=dict)

@dataclass(slots=True)
class ResilienceReport:
    """Aggregated metrics for a single chaos run."""

    run_identifier: str
    scenario_identifier: str
    metrics: list[MetricDatum]
    summary_score: float
    scenario_difficulty: float | None = None
    scenario_difficulty_label: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize the report for storage or transport."""
        return {
            "run_identifier": self.run_identifier,
            "scenario_identifier": self.scenario_identifier,
            "summary_score": self.summary_score,
            "scenario_difficulty": self.scenario_difficulty,
            "scenario_difficulty_label": self.scenario_difficulty_label,
            "metrics": [
                {
                    "name": metric.name,
                    "value": metric.value,
                    "unit": metric.unit,
                    "captured_at": metric.captured_at.isoformat(),
                    "metadata": metric.metadata,
                }
                for metric in self.metrics
            ],
        }
