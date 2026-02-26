"""Unit tests for khaos.testing.redaction."""

from __future__ import annotations

from khaos.testing.client import AgentResponse
from khaos.testing.redaction import (
    redact_response,
    redact_text,
    redact_transcript,
)


class TestRedactText:
    def test_clean_text_unchanged(self):
        assert redact_text("Hello world") == "Hello world"

    def test_redacts_email(self):
        result = redact_text("Contact john@example.com for details")
        assert "john@example.com" not in result
        assert "[REDACTED]" in result

    def test_extra_patterns(self):
        result = redact_text(
            "Token: SECRET-12345",
            extra_patterns=[r"SECRET-\d+"],
        )
        assert "SECRET-12345" not in result
        assert "[REDACTED]" in result


class TestRedactResponse:
    def test_returns_new_response(self):
        resp = AgentResponse(
            success=True,
            text="Email: john.doe@company.com",
            raw={},
            latency_ms=10.0,
        )
        redacted = redact_response(resp)
        assert isinstance(redacted, AgentResponse)
        assert redacted is not resp
        assert "john.doe@company.com" not in redacted.text
        # Other fields preserved
        assert redacted.success is True
        assert redacted.latency_ms == 10.0

    def test_clean_response_preserved(self):
        resp = AgentResponse(
            success=True,
            text="Hello world",
            raw={},
            latency_ms=10.0,
        )
        redacted = redact_response(resp)
        assert redacted.text == "Hello world"


class TestRedactTranscript:
    def test_redacts_messages(self):
        messages = [
            {"role": "user", "content": "My email is john@example.com"},
            {"role": "assistant", "content": "Got it, john@example.com"},
        ]
        result = redact_transcript(messages)
        assert len(result) == 2
        for msg in result:
            assert "john@example.com" not in msg["content"]

    def test_preserves_structure(self):
        messages = [
            {"role": "user", "content": "Hello", "extra": "data"},
        ]
        result = redact_transcript(messages)
        assert result[0]["role"] == "user"
        assert result[0]["extra"] == "data"

    def test_does_not_modify_original(self):
        messages = [{"role": "user", "content": "john@example.com"}]
        redact_transcript(messages)
        assert messages[0]["content"] == "john@example.com"
