"""Tri-state security classification with full provenance.

Wraps the existing ``khaos.security.scoring`` engine to provide a
testing-friendly API: an ``Outcome`` enum, a frozen ``ClassificationResult``
with matched rules and confidence, and a single ``classify()`` entry-point.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from khaos.security.scoring import (
    SecurityClassification,
    classify_security_response,
    detect_behavioral_compromise,
)


class Outcome(str, Enum):
    """Tri-state test outcome for security classification."""

    BLOCKED = "blocked"
    COMPROMISED = "compromised"
    INCONCLUSIVE = "inconclusive"


_CLASSIFICATION_TO_OUTCOME: dict[SecurityClassification, Outcome] = {
    SecurityClassification.BLOCKED: Outcome.BLOCKED,
    SecurityClassification.COMPROMISED: Outcome.COMPROMISED,
    SecurityClassification.INCONCLUSIVE: Outcome.INCONCLUSIVE,
}


@dataclass(frozen=True)
class ClassificationResult:
    """Full provenance for a single classification decision."""

    outcome: Outcome
    classifier: str
    matched_rules: tuple[str, ...]
    confidence: float
    raw_signals: dict[str, Any]


def classify(
    text: str,
    *,
    attack_type: str = "unknown",
    tool_calls: list[dict[str, Any]] | None = None,
    forbidden_keywords: list[str] | None = None,
    forbidden_tool_names: list[str] | None = None,
    forbidden_tool_arg_markers: list[str] | None = None,
) -> ClassificationResult:
    """Classify *text* using the security scoring engine.

    Returns a :class:`ClassificationResult` with the outcome, which rules
    matched, a confidence estimate, and the raw behavioural signals.
    """
    # Run pattern + behavioural classification
    classification = classify_security_response(
        text,
        attack_type=attack_type,
        forbidden_keywords=forbidden_keywords,
        tool_calls=tool_calls,
        forbidden_tool_names=forbidden_tool_names,
        forbidden_tool_arg_markers=forbidden_tool_arg_markers,
    )

    # Collect behavioural signals for provenance
    behavioral = detect_behavioral_compromise(text, tool_calls)

    # Build matched-rules list from behavioural findings
    matched: list[str] = []
    for category, findings in behavioral.items():
        for finding in findings:
            matched.append(f"{category}:{finding}")

    # Estimate confidence from signal density
    if classification == SecurityClassification.COMPROMISED:
        confidence = min(1.0, 0.7 + 0.1 * len(matched))
    elif classification == SecurityClassification.BLOCKED:
        confidence = 0.9
    else:
        confidence = 0.5

    outcome = _CLASSIFICATION_TO_OUTCOME[classification]
    return ClassificationResult(
        outcome=outcome,
        classifier="khaos.security.scoring",
        matched_rules=tuple(matched),
        confidence=round(confidence, 2),
        raw_signals=behavioral,
    )


__all__ = ["Outcome", "ClassificationResult", "classify"]
