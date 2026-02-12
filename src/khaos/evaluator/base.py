"""Evaluator protocol definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from collections.abc import Iterable

@dataclass(slots=True)
class EvaluationContext:
    """Contextual information gathered during a chaos run."""

    run_identifier: str
    scenario_identifier: str
    metadata: dict[str, object]

@dataclass(slots=True)
class EvaluationArtifact:
    """Structured evaluator output."""

    name: str
    value: float | int
    unit: str
    details: dict[str, object]

class Evaluator(Protocol):
    """Interface for resilience metric calculators."""

    name: str

    async def evaluate(
        self,
        context: EvaluationContext,
    ) -> Iterable[EvaluationArtifact]: ...
