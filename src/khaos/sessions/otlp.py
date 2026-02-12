"""OpenTelemetry-compatible trace export.

Exports Khaos sessions as OpenTelemetry Protocol (OTLP) traces,
enabling integration with observability platforms like:
- Jaeger
- Zipkin
- Honeycomb
- Datadog
- New Relic
- Grafana Tempo

The export format follows the OTLP JSON specification.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from khaos.sessions.models import LLMCall, Session, Turn


# OpenTelemetry semantic conventions for LLM
# Based on emerging LLM observability standards
LLM_SYSTEM = "llm"
LLM_REQUEST_MODEL = "llm.request.model"
LLM_RESPONSE_MODEL = "llm.response.model"
LLM_REQUEST_MAX_TOKENS = "llm.request.max_tokens"
LLM_USAGE_PROMPT_TOKENS = "llm.usage.prompt_tokens"
LLM_USAGE_COMPLETION_TOKENS = "llm.usage.completion_tokens"
LLM_USAGE_TOTAL_TOKENS = "llm.usage.total_tokens"
LLM_RESPONSE_FINISH_REASON = "llm.response.finish_reasons"
GEN_AI_SYSTEM = "gen_ai.system"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_RESPONSE_MODEL = "gen_ai.response.model"


def _datetime_to_nanos(dt: datetime) -> int:
    """Convert datetime to nanoseconds since epoch."""
    return int(dt.timestamp() * 1_000_000_000)


def _generate_trace_id() -> str:
    """Generate a 32-character hex trace ID."""
    import secrets
    return secrets.token_hex(16)


def _generate_span_id() -> str:
    """Generate a 16-character hex span ID."""
    import secrets
    return secrets.token_hex(8)


@dataclass
class OTLPSpan:
    """OpenTelemetry span representation."""

    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    kind: int  # 1=INTERNAL, 2=SERVER, 3=CLIENT
    start_time_unix_nano: int
    end_time_unix_nano: int
    attributes: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    status: dict[str, Any] = field(default_factory=lambda: {"code": 1})  # OK

    def to_dict(self) -> dict[str, Any]:
        """Convert to OTLP JSON format."""
        span = {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": self.kind,
            "startTimeUnixNano": str(self.start_time_unix_nano),
            "endTimeUnixNano": str(self.end_time_unix_nano),
            "attributes": self.attributes,
            "status": self.status,
        }
        if self.parent_span_id:
            span["parentSpanId"] = self.parent_span_id
        if self.events:
            span["events"] = self.events
        return span


@dataclass
class OTLPTrace:
    """Collection of spans forming a trace."""

    trace_id: str
    spans: list[OTLPSpan] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to OTLP JSON format."""
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "khaos-agent"}},
                            {"key": "service.version", "value": {"stringValue": "1.0.0"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {
                                "name": "khaos.sessions",
                                "version": "1.0.0",
                            },
                            "spans": [s.to_dict() for s in self.spans],
                        }
                    ],
                }
            ]
        }


def _make_attribute(key: str, value: Any) -> dict[str, Any]:
    """Create an OTLP attribute."""
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    elif isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    elif isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    elif isinstance(value, list):
        return {"key": key, "value": {"arrayValue": {"values": [{"stringValue": str(v)} for v in value]}}}
    else:
        return {"key": key, "value": {"stringValue": str(value)}}


def _llm_call_to_span(
    call: LLMCall,
    trace_id: str,
    parent_span_id: str | None,
) -> OTLPSpan:
    """Convert an LLM call to an OTLP span."""
    span_id = _generate_span_id()

    # Calculate timing
    start_nanos = _datetime_to_nanos(call.timestamp)
    duration_nanos = int(call.latency_ms * 1_000_000)
    end_nanos = start_nanos + duration_nanos

    # Build attributes following LLM semantic conventions
    attributes = [
        _make_attribute(GEN_AI_SYSTEM, call.provider),
        _make_attribute(GEN_AI_REQUEST_MODEL, call.model),
        _make_attribute(LLM_USAGE_PROMPT_TOKENS, call.prompt_tokens),
        _make_attribute(LLM_USAGE_COMPLETION_TOKENS, call.completion_tokens),
        _make_attribute(LLM_USAGE_TOTAL_TOKENS, call.total_tokens),
        _make_attribute("llm.cost_usd", call.cost_usd),
        _make_attribute("llm.latency_ms", call.latency_ms),
    ]

    if call.finish_reason:
        attributes.append(_make_attribute(LLM_RESPONSE_FINISH_REASON, [call.finish_reason]))

    # Add tool call info
    if call.tool_calls:
        tool_names = [tc.name for tc in call.tool_calls]
        attributes.append(_make_attribute("llm.tool_calls", tool_names))
        attributes.append(_make_attribute("llm.tool_call_count", len(call.tool_calls)))

    # Build events for tool calls
    events = []
    for tc in call.tool_calls:
        events.append({
            "name": f"tool_call.{tc.name}",
            "timeUnixNano": str(start_nanos),
            "attributes": [
                _make_attribute("tool.id", tc.id),
                _make_attribute("tool.name", tc.name),
            ],
        })

    return OTLPSpan(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        name=f"llm.{call.provider}.{call.model}",
        kind=3,  # CLIENT
        start_time_unix_nano=start_nanos,
        end_time_unix_nano=end_nanos,
        attributes=attributes,
        events=events,
    )


def _turn_to_span(
    turn: Turn,
    trace_id: str,
    parent_span_id: str | None,
) -> tuple[OTLPSpan, list[OTLPSpan]]:
    """Convert a turn to OTLP spans.

    Returns the turn span and child LLM call spans.
    """
    span_id = _generate_span_id()

    # Calculate timing
    if turn.start_time and turn.end_time:
        start_nanos = _datetime_to_nanos(turn.start_time)
        end_nanos = _datetime_to_nanos(turn.end_time)
    elif turn.llm_calls:
        start_nanos = _datetime_to_nanos(turn.llm_calls[0].timestamp)
        duration_nanos = int(turn.latency_ms * 1_000_000)
        end_nanos = start_nanos + duration_nanos
    else:
        now = datetime.now(timezone.utc)
        start_nanos = _datetime_to_nanos(now)
        end_nanos = start_nanos

    # Build attributes
    attributes = [
        _make_attribute("turn.index", turn.turn_index),
        _make_attribute("turn.llm_call_count", turn.llm_call_count),
        _make_attribute("turn.total_tokens", turn.total_tokens),
        _make_attribute("turn.cost_usd", turn.cost_usd),
        _make_attribute("turn.latency_ms", turn.latency_ms),
    ]

    if turn.user_message and turn.user_message.content:
        # Truncate long messages
        content = turn.user_message.content
        if len(content) > 200:
            content = content[:200] + "..."
        attributes.append(_make_attribute("turn.user_message", content))

    turn_span = OTLPSpan(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        name=f"turn.{turn.turn_index}",
        kind=1,  # INTERNAL
        start_time_unix_nano=start_nanos,
        end_time_unix_nano=end_nanos,
        attributes=attributes,
    )

    # Create child spans for LLM calls
    child_spans = [
        _llm_call_to_span(call, trace_id, span_id)
        for call in turn.llm_calls
    ]

    return turn_span, child_spans


def session_to_otlp(session: Session) -> OTLPTrace:
    """Convert a session to OTLP trace format.

    Args:
        session: The session to convert

    Returns:
        OTLPTrace object
    """
    trace_id = _generate_trace_id()
    spans: list[OTLPSpan] = []

    # Create root session span
    if session.start_time and session.end_time:
        start_nanos = _datetime_to_nanos(session.start_time)
        end_nanos = _datetime_to_nanos(session.end_time)
    else:
        start_nanos = _datetime_to_nanos(session.start_time)
        end_nanos = start_nanos + int(session.duration_ms * 1_000_000)

    root_span_id = _generate_span_id()
    metrics = session.get_metrics()

    root_span = OTLPSpan(
        trace_id=trace_id,
        span_id=root_span_id,
        parent_span_id=None,
        name=f"session.{session.agent_name or 'agent'}",
        kind=2,  # SERVER
        start_time_unix_nano=start_nanos,
        end_time_unix_nano=end_nanos,
        attributes=[
            _make_attribute("session.id", session.session_id),
            _make_attribute("agent.name", session.agent_name),
            _make_attribute("agent.version", session.agent_version),
            _make_attribute("session.turn_count", session.turn_count),
            _make_attribute("session.llm_call_count", session.llm_call_count),
            _make_attribute("session.total_tokens", session.total_tokens),
            _make_attribute("session.total_cost_usd", session.total_cost_usd),
            _make_attribute("session.duration_ms", session.duration_ms),
            _make_attribute("session.models_used", session.models_used),
            _make_attribute("session.providers_used", session.providers_used),
        ],
    )
    spans.append(root_span)

    # Create turn spans with LLM call children
    for turn in session.turns:
        turn_span, llm_spans = _turn_to_span(turn, trace_id, root_span_id)
        spans.append(turn_span)
        spans.extend(llm_spans)

    return OTLPTrace(trace_id=trace_id, spans=spans)


def to_otlp_json(session: Session) -> str:
    """Convert session to OTLP JSON string.

    Args:
        session: The session to convert

    Returns:
        JSON string in OTLP format
    """
    trace = session_to_otlp(session)
    return json.dumps(trace.to_dict(), indent=2)


def export_otlp_file(session: Session, path: str | Path) -> Path:
    """Export session to OTLP JSON file.

    Args:
        session: The session to export
        path: Output file path

    Returns:
        Path to the exported file
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w") as f:
        f.write(to_otlp_json(session))

    return path


def export_sessions_otlp(sessions: list[Session], path: str | Path) -> Path:
    """Export multiple sessions to a single OTLP JSON file.

    Args:
        sessions: List of sessions to export
        path: Output file path

    Returns:
        Path to the exported file
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Combine all traces
    all_resource_spans = []
    for session in sessions:
        trace = session_to_otlp(session)
        trace_dict = trace.to_dict()
        all_resource_spans.extend(trace_dict.get("resourceSpans", []))

    combined = {"resourceSpans": all_resource_spans}

    with path.open("w") as f:
        json.dump(combined, f, indent=2)

    return path
