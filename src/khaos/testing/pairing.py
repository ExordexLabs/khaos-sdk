"""Attack / control paired-trial runner and evidence export.

Runs an attack prompt and its benign control through the same agent,
then computes the causal lift (difference in block rate) to confirm
that any failure is actually caused by the attack, not random flakiness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.testing.client import AgentResponse, AgentTestClient
from khaos.testing.classification import ClassificationResult, Outcome, classify


@dataclass(frozen=True)
class TrialResult:
    """Single trial (either attack or control)."""

    response: AgentResponse
    classification: ClassificationResult
    is_control: bool
    prompt: str


@dataclass(frozen=True)
class PairedTrialResult:
    """Attack + control pair with causal attribution."""

    attack_trial: TrialResult
    control_trial: TrialResult

    @property
    def causal_lift(self) -> float:
        """Fraction-point difference: attack compromise rate minus control.

        For a single pair this is 1.0, 0.0, or -1.0.
        """
        attack_score = 1.0 if self.attack_trial.classification.outcome == Outcome.COMPROMISED else 0.0
        control_score = 1.0 if self.control_trial.classification.outcome == Outcome.COMPROMISED else 0.0
        return attack_score - control_score


def run_paired_trial(
    client: AgentTestClient,
    attack_prompt: str,
    control_prompt: str,
    *,
    attack_type: str = "unknown",
    forbidden_keywords: list[str] | None = None,
) -> PairedTrialResult:
    """Run *attack_prompt* and *control_prompt* through *client*.

    Returns a :class:`PairedTrialResult` with classifications and causal lift.
    """
    attack_response = client(attack_prompt)
    control_response = client(control_prompt)

    attack_cls = classify(
        attack_response.text,
        attack_type=attack_type,
        forbidden_keywords=forbidden_keywords,
    )
    control_cls = classify(
        control_response.text,
        attack_type=attack_type,
        forbidden_keywords=forbidden_keywords,
    )

    return PairedTrialResult(
        attack_trial=TrialResult(
            response=attack_response,
            classification=attack_cls,
            is_control=False,
            prompt=attack_prompt,
        ),
        control_trial=TrialResult(
            response=control_response,
            classification=control_cls,
            is_control=True,
            prompt=control_prompt,
        ),
    )


def _serialise_trial(trial: TrialResult, *, redact: bool) -> dict[str, Any]:
    text = trial.response.text
    if redact:
        from khaos.testing.redaction import redact_text
        text = redact_text(text)

    return {
        "prompt": trial.prompt,
        "is_control": trial.is_control,
        "outcome": trial.classification.outcome.value,
        "confidence": trial.classification.confidence,
        "matched_rules": list(trial.classification.matched_rules),
        "response_text": text,
        "latency_ms": trial.response.latency_ms,
        "success": trial.response.success,
    }


def export_evidence(
    results: list[PairedTrialResult],
    path: str | Path,
    *,
    format: str = "json",
    redact: bool = True,
) -> Path:
    """Write paired-trial evidence to *path* for audit.

    Args:
        results: List of paired trial results to export.
        path: Output file path.
        format: Output format (currently only ``"json"``).
        redact: Whether to redact PII from response text.

    Returns:
        The resolved output path.
    """
    out = Path(path)
    records = []
    for pair in results:
        records.append({
            "attack": _serialise_trial(pair.attack_trial, redact=redact),
            "control": _serialise_trial(pair.control_trial, redact=redact),
            "causal_lift": pair.causal_lift,
        })

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(records, indent=2, default=str))
    return out


__all__ = [
    "TrialResult",
    "PairedTrialResult",
    "run_paired_trial",
    "export_evidence",
]
