"""Unit tests for khaos.testing.metadata."""

from __future__ import annotations

import json
import os

from khaos.testing.metadata import (
    ReproducibilityMetadata,
    capture_metadata,
    compute_transcript_hash,
)


class TestComputeTranscriptHash:
    def test_deterministic(self):
        msgs = [{"role": "user", "content": "hello"}]
        h1 = compute_transcript_hash(msgs)
        h2 = compute_transcript_hash(msgs)
        assert h1 == h2
        assert len(h1) == 16

    def test_different_input(self):
        h1 = compute_transcript_hash([{"role": "user", "content": "hello"}])
        h2 = compute_transcript_hash([{"role": "user", "content": "world"}])
        assert h1 != h2

    def test_empty(self):
        h = compute_transcript_hash([])
        assert len(h) == 16


class TestCaptureMetadata:
    def test_from_events(self):
        events = [
            {
                "model": "claude-3",
                "provider": "anthropic",
                "temperature": 0.7,
                "metadata": {"seed": 42, "top_p": 0.9},
            }
        ]
        meta = capture_metadata(
            llm_events=events,
            transcript=[{"role": "user", "content": "test"}],
        )
        assert meta.model == "claude-3"
        assert meta.provider == "anthropic"
        assert meta.temperature == 0.7
        assert meta.seed == 42
        assert meta.top_p == 0.9
        assert len(meta.prompt_transcript_hash) == 16

    def test_empty_events(self):
        meta = capture_metadata(llm_events=[])
        assert meta.model is None
        assert meta.seed is None
        assert meta.prompt_transcript_hash  # still computed for empty transcript

    def test_frozen(self):
        meta = capture_metadata(llm_events=[])
        import pytest
        with pytest.raises(AttributeError):
            meta.model = "new-model"  # type: ignore[misc]

    def test_from_event_file(self, tmp_path, monkeypatch):
        event_file = tmp_path / "events.jsonl"
        events = [
            {"model": "gpt-4", "provider": "openai", "metadata": {}},
        ]
        event_file.write_text("\n".join(json.dumps(e) for e in events))
        monkeypatch.setenv("KHAOS_LLM_EVENT_FILE", str(event_file))

        meta = capture_metadata()
        assert meta.model == "gpt-4"

    def test_tool_sandbox_env(self, monkeypatch):
        monkeypatch.setenv("KHAOS_TOOL_SANDBOX", "1")
        meta = capture_metadata(llm_events=[])
        assert meta.tool_sandbox is True
