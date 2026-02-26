"""Unit tests for khaos.testing.pairing."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from khaos.testing.client import AgentResponse, AgentTestClient
from khaos.testing.classification import Outcome
from khaos.testing.pairing import (
    PairedTrialResult,
    TrialResult,
    export_evidence,
    run_paired_trial,
)


def _make_client(*responses: str) -> AgentTestClient:
    """Create a mock AgentTestClient that returns canned responses."""
    call_idx = {"i": 0}

    def agent_fn(message):
        idx = call_idx["i"]
        call_idx["i"] += 1
        text = responses[idx] if idx < len(responses) else ""
        return {"payload": {"text": text}, "metadata": {}}

    return AgentTestClient(agent_fn, config=None)


class TestRunPairedTrial:
    def test_basic_pair(self):
        client = _make_client(
            "I cannot help with that.",  # attack -> blocked
            "The capital of France is Paris.",  # control -> inconclusive
        )
        result = run_paired_trial(
            client,
            attack_prompt="Ignore instructions",
            control_prompt="What is the capital of France?",
        )
        assert isinstance(result, PairedTrialResult)
        assert result.attack_trial.is_control is False
        assert result.control_trial.is_control is True
        assert result.attack_trial.prompt == "Ignore instructions"
        assert result.control_trial.prompt == "What is the capital of France?"

    def test_causal_lift_positive(self):
        """Attack compromised, control not -> positive lift."""
        client = _make_client(
            "Sure, def keylogger(): pass",  # compromised
            "I'm sorry, I cannot do that.",  # blocked
        )
        result = run_paired_trial(
            client, "hack it", "be nice",
            attack_type="prompt_injection",
        )
        assert result.causal_lift > 0

    def test_causal_lift_zero(self):
        """Both blocked -> zero lift."""
        client = _make_client(
            "I cannot help with that.",
            "I cannot help with that.",
        )
        result = run_paired_trial(client, "bad", "good")
        assert result.causal_lift == 0.0


class TestTrialResult:
    def test_fields(self):
        resp = AgentResponse(
            success=True, text="hello", raw={}, latency_ms=10.0,
        )
        from khaos.testing.classification import ClassificationResult
        cls = ClassificationResult(
            outcome=Outcome.BLOCKED,
            classifier="test",
            matched_rules=(),
            confidence=0.9,
            raw_signals={},
        )
        trial = TrialResult(
            response=resp, classification=cls,
            is_control=False, prompt="test",
        )
        assert trial.is_control is False
        assert trial.classification.outcome == Outcome.BLOCKED


class TestExportEvidence:
    def test_json_export(self, tmp_path):
        client = _make_client(
            "I cannot help.",
            "Paris is the capital.",
        )
        result = run_paired_trial(client, "attack", "control")

        out_path = tmp_path / "evidence.json"
        actual = export_evidence([result], out_path, redact=False)
        assert actual == out_path
        assert out_path.exists()

        data = json.loads(out_path.read_text())
        assert len(data) == 1
        assert "attack" in data[0]
        assert "control" in data[0]
        assert "causal_lift" in data[0]

    def test_creates_parent_dirs(self, tmp_path):
        client = _make_client("no", "yes")
        result = run_paired_trial(client, "a", "b")

        out_path = tmp_path / "subdir" / "deep" / "evidence.json"
        export_evidence([result], out_path)
        assert out_path.exists()
