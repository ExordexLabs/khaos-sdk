"""PII and secret redaction for test evidence.

Thin wrapper around :class:`khaos.pii.detector.PIIDetector` that
operates on response objects and message transcripts.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from khaos.pii.detector import PIIDetector


_DEFAULT_DETECTOR = PIIDetector()

# Fallback regex for secrets (API keys, tokens) when PIIDetector
# doesn't cover them.
_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9]{20,}|kht_[A-Za-z0-9]+|"
    r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}|"
    r"[A-Za-z0-9]{32,})",
)


def redact_text(
    text: str,
    *,
    mode: str = "mask",
    extra_patterns: list[str] | None = None,
    detector: PIIDetector | None = None,
) -> str:
    """Redact PII and secrets from *text*.

    Args:
        text: Input text to redact.
        mode: ``"mask"`` replaces with ``[REDACTED]``.
        extra_patterns: Additional regex patterns to redact.
        detector: Optional PIIDetector instance (uses default if None).

    Returns:
        A copy of *text* with PII replaced.
    """
    det = detector or _DEFAULT_DETECTOR
    result = det.scan(text)

    # Build replacement spans (sorted by position, reversed for safe replacement)
    spans: list[tuple[int, int]] = []
    for match in result.matches:
        spans.append((match.start, match.end))

    # Apply extra patterns
    if extra_patterns:
        for pat in extra_patterns:
            for m in re.finditer(pat, text):
                spans.append((m.start(), m.end()))

    # Sort descending by start position to replace safely
    spans.sort(key=lambda s: s[0], reverse=True)

    redacted = text
    for start, end in spans:
        redacted = redacted[:start] + "[REDACTED]" + redacted[end:]

    return redacted


def redact_response(
    response: Any,
    *,
    mode: str = "mask",
) -> Any:
    """Return a copy of *response* with PII redacted from the text field.

    Works with :class:`~khaos.testing.client.AgentResponse` or any object
    that has a ``text`` attribute.
    """
    from khaos.testing.client import AgentResponse

    if isinstance(response, AgentResponse):
        redacted_text = redact_text(response.text, mode=mode)
        return AgentResponse(
            success=response.success,
            text=redacted_text,
            raw=response.raw,
            latency_ms=response.latency_ms,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            error=response.error,
            classification=response.classification,
            tool_calls=response.tool_calls,
            llm_events=response.llm_events,
            metadata=response.metadata,
        )

    # Generic fallback: copy and redact .text
    result = copy.copy(response)
    if hasattr(result, "text"):
        result.text = redact_text(result.text, mode=mode)
    return result


def redact_transcript(
    messages: list[dict[str, Any]],
    *,
    extra_patterns: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Redact PII from a list of message dicts.

    Each message is expected to have a ``"content"`` key with string text.
    Returns a deep copy with PII replaced.
    """
    out: list[dict[str, Any]] = []
    for msg in messages:
        msg_copy = dict(msg)
        content = msg_copy.get("content", "")
        if isinstance(content, str):
            msg_copy["content"] = redact_text(content, extra_patterns=extra_patterns)
        out.append(msg_copy)
    return out


__all__ = ["redact_text", "redact_response", "redact_transcript"]
