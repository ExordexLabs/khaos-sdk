"""Trace collection and artifact persistence.

Handles:
- Building trace objects from events
- Persisting trace and metrics artifacts
- Message extraction and deduplication
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from khaos.state import get_state_dir


def normalize_for_hash(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a stable subset of message data for hashing/deduping."""
    normalized: list[dict[str, Any]] = []
    for msg in messages:
        normalized.append({
            "role": msg.get("role"),
            "content": msg.get("content") or "",
            "tool_calls": msg.get("tool_calls") or None,
        })
    return normalized


def hash_messages(messages: list[dict[str, Any]]) -> str:
    """Hash messages for content deduplication."""
    payload = json.dumps(normalize_for_hash(messages), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def extract_messages_from_events(trace_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract LLM messages from trace events (portable subset for dashboard).

    Args:
        trace_events: List of telemetry events

    Returns:
        List of message dicts with role, content, and metadata
    """
    messages: list[dict[str, Any]] = []

    # Sort within a case to keep message ordering stable even when callers append
    # synthesized boundaries (transport.send/receive) out of order.
    for _, event in sorted(
        enumerate(trace_events),
        key=lambda pair: (str((pair[1] or {}).get("ts") or ""), pair[0]),
    ):
        event_type = event.get("event", "")
        payload = event.get("payload", {}) or {}
        ts = event.get("ts")

        if event_type in ("llm.response", "llm.call", "framework.call"):
            content_data = payload.get("content", {}) or {}
            tokens = payload.get("tokens", {}) or {}
            metadata = payload.get("metadata", {}) or {}

            prompt = content_data.get("prompt")
            if prompt:
                messages.append({
                    "role": "user",
                    "content": prompt if isinstance(prompt, str) else json.dumps(prompt, ensure_ascii=False),
                    "token_count": tokens.get("prompt"),
                    "timestamp": ts,
                    "model": payload.get("model"),
                })

            completion = content_data.get("completion")
            if completion:
                tool_calls = None
                raw_tool_calls = metadata.get("tool_calls", []) or []
                if raw_tool_calls:
                    tool_calls = [
                        {
                            "id": tc.get("id", ""),
                            "name": tc.get("name", ""),
                            "arguments": tc.get("arguments", ""),
                            "result": tc.get("result"),
                        }
                        for tc in raw_tool_calls
                    ]

                messages.append({
                    "role": "assistant",
                    "content": completion if isinstance(completion, str) else json.dumps(completion, ensure_ascii=False),
                    "token_count": tokens.get("completion"),
                    "timestamp": ts,
                    "tool_calls": tool_calls,
                    "model": payload.get("model"),
                    "latency_ms": payload.get("latency_ms"),
                })

        elif event_type == "transport.send":
            content = payload.get("content")
            if content:
                messages.append({
                    "role": "user",
                    "content": content if isinstance(content, str) else str(content),
                    "timestamp": ts,
                })

        elif event_type == "transport.receive":
            content = payload.get("content")
            if content:
                messages.append({
                    "role": "assistant",
                    "content": content if isinstance(content, str) else str(content),
                    "timestamp": ts,
                })

        elif event_type == "security.attack":
            # Multi-turn security attacks store conversation history in payload
            conversation = payload.get("conversation", [])
            attack_response = payload.get("response")

            # Add each turn from the multi-turn attack conversation
            for turn in conversation:
                if isinstance(turn, dict) and turn.get("content"):
                    role = turn.get("role", "user")
                    messages.append({
                        "role": role,
                        "content": turn["content"],
                        "timestamp": ts,
                    })

            # Add the final response if not already captured
            if attack_response and isinstance(attack_response, str):
                # Check if the last message already has this response
                if not messages or messages[-1].get("content") != attack_response:
                    messages.append({
                        "role": "assistant",
                        "content": attack_response,
                        "timestamp": ts,
                    })

    return messages


def build_pack_trace_from_events(
    trace_events: list[dict[str, Any]],
    *,
    pack_name: str | None,
    pack_version: str | None,
    run_id: str,
    input_results: list[Any] | None = None,
    security_attack_results: list[Any] | None = None,
) -> dict[str, Any]:
    """Build a pack-aware trace object with per-case indexing and content de-dupe.

    Args:
        trace_events: List of telemetry events from agent runs
        pack_name: Name of the evaluation pack
        pack_version: Version of the pack
        run_id: Unique run identifier
        input_results: Optional list of InputResult from evaluation for verdict data
        security_attack_results: Optional list of security attack results for verdicts
    """
    try:
        from khaos.evaluator.trace import TraceStatsEvaluator
    except Exception:
        TraceStatsEvaluator = None  # type: ignore[misc,assignment]

    # Build a lookup for verdicts from input_results
    # Key: (phase, input_id, run_index) -> InputResult
    verdict_lookup: dict[tuple[str, str, int], Any] = {}
    if input_results:
        for result in input_results:
            key = (result.phase.lower(), result.input_id, result.run_index)
            verdict_lookup[key] = result

    security_lookup: dict[str, str] = {}
    if security_attack_results:
        for attack in security_attack_results:
            try:
                attack_id = getattr(attack, "attack_id", None) or (attack.get("attack_id") if isinstance(attack, dict) else None)
                classification = getattr(attack, "classification", None) or (
                    attack.get("classification") if isinstance(attack, dict) else None
                )
            except Exception:
                continue
            if isinstance(attack_id, str) and attack_id and isinstance(classification, str) and classification:
                security_lookup[attack_id] = classification.lower()

    cases: list[dict[str, Any]] = []
    traces: dict[str, dict[str, Any]] = {}
    run_index_by_key: dict[tuple[str, str], int] = {}

    current_case_events: list[dict[str, Any]] = []
    current_context: dict[str, Any] | None = None

    def flush_case() -> None:
        nonlocal current_case_events, current_context
        if not current_case_events or not current_context:
            current_case_events = []
            current_context = None
            return

        phase = str(current_context.get("phase") or "unknown")
        input_id = str(current_context.get("input_id") or "unknown")
        run_index = run_index_by_key.get((phase, input_id), 0)
        run_index_by_key[(phase, input_id)] = run_index + 1
        case_id = f"{phase}:{input_id}:{run_index}"

        messages = extract_messages_from_events(current_case_events)
        content_hash = hash_messages(messages)

        llm_summary: dict[str, Any] = {}
        if TraceStatsEvaluator is not None:
            try:
                llm_summary = TraceStatsEvaluator()._llm_stats(current_case_events).get("summary", {})
            except Exception:
                llm_summary = {}

        if content_hash not in traces:
            traces[content_hash] = {
                "messages": messages,
                "llm": llm_summary,
            }

        preview = ""
        for msg in messages:
            if msg.get("role") == "user" and msg.get("content"):
                preview = str(msg.get("content"))[:140]
                break

        # Look up verdict from input_results
        verdict: dict[str, Any] | None = None
        verdict_key = (phase.lower(), input_id, run_index)
        if verdict_key in verdict_lookup:
            result = verdict_lookup[verdict_key]
            # Determine status based on success and goal_met
            if result.success:
                if result.goal_met is None or result.goal_met:
                    status = "passed"
                else:
                    status = "partial"  # succeeded but goal not met
            else:
                status = "failed"

            # Build assertion results from check_errors
            assertion_results: list[dict[str, Any]] | None = None
            if result.check_errors:
                assertion_results = [
                    {"name": f"check_{i}", "passed": False, "message": err}
                    for i, err in enumerate(result.check_errors)
                ]

            verdict = {
                "status": status,
                "goal_met": result.goal_met,
                "success": result.success,
                "error": result.error,
                "expected": None,  # Not tracked in InputResult currently
                "actual": result.response_preview if hasattr(result, 'response_preview') else None,
                "assertion_results": assertion_results,
            }
        elif phase.lower() == "security":
            classification = security_lookup.get(input_id)
            if classification == "blocked":
                verdict = {"status": "passed", "goal_met": None, "success": True, "error": None}
            elif classification == "compromised":
                verdict = {"status": "failed", "goal_met": None, "success": True, "error": None}
            elif classification == "inconclusive":
                verdict = {"status": "partial", "goal_met": None, "success": True, "error": None}

        # Include multi-turn metadata if present
        is_multi_turn = current_context.get("is_multi_turn", False)
        turn_count = current_context.get("turn_count", 1)

        cases.append({
            "case_id": case_id,
            "phase": phase,
            "input_id": input_id,
            "run_index": run_index,
            "content_hash": content_hash,
            "preview": preview,
            "faults": current_context.get("faults") or [],
            "security_mode": current_context.get("security_mode"),
            "llm": llm_summary,
            "verdict": verdict,
            "is_multi_turn": is_multi_turn,
            "turn_count": turn_count if is_multi_turn else None,
        })

        current_case_events = []
        current_context = None

    for event in trace_events:
        if not isinstance(event, dict):
            continue
        context = event.get("context")
        event_type = event.get("event")

        # New invocation boundary.
        # For multi-turn conversations, only flush on the first turn (turn_index=0).
        # Subsequent turns in the same conversation should be appended to current case.
        if event_type == "transport.send":
            is_multi_turn = isinstance(context, dict) and context.get("is_multi_turn", False)
            turn_index = context.get("turn_index", 0) if isinstance(context, dict) else 0

            # Only start a new case if:
            # 1. This is a single-turn conversation, OR
            # 2. This is the first turn of a multi-turn conversation
            if not is_multi_turn or turn_index == 0:
                flush_case()
                if isinstance(context, dict):
                    current_context = context
                else:
                    current_context = None
                current_case_events = [event]
            else:
                # Continuation of multi-turn - append to current case
                current_case_events.append(event)
            continue

        # Security attack events are also case boundaries (each attack is its own case)
        if event_type == "security.attack":
            flush_case()
            if isinstance(context, dict):
                # Add multi-turn info if this is a multi-turn attack
                payload = event.get("payload", {}) or {}
                conversation = payload.get("conversation", [])
                if conversation and len(conversation) > 1:
                    context = dict(context)  # Don't mutate original
                    context["is_multi_turn"] = True
                    context["turn_count"] = len(conversation)
                current_context = context
            else:
                current_context = None
            current_case_events = [event]
            continue

        if current_case_events:
            current_case_events.append(event)

    flush_case()

    return {
        "schema": "khaos.pack_trace.v1",
        "run_id": run_id,
        "pack_name": pack_name,
        "pack_version": pack_version,
        "cases": cases,
        "traces": traces,
    }


def persist_pack_artifacts(
    report: Any,
    *,
    trace_events: list[dict[str, Any]],
    security_trace_events: list[dict[str, Any]] | None = None,
) -> tuple[Path, Path]:
    """Persist pack trace and metrics locally.

    Args:
        report: Evaluation report
        trace_events: LLM telemetry events
        security_trace_events: Optional security test events to merge

    Returns:
        Tuple of (trace_path, metrics_path)
    """
    run_id = report.run_id
    runs_dir = get_state_dir() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    all_trace_events = list(trace_events)
    if security_trace_events:
        all_trace_events.extend(security_trace_events)

    pack_trace = build_pack_trace_from_events(
        all_trace_events,
        pack_name=report.pack_name,
        pack_version=report.pack_version,
        run_id=run_id,
        input_results=report.input_results,
    )
    trace_path = runs_dir / f"trace-{run_id}.json"
    trace_path.write_text(json.dumps(pack_trace, indent=2), encoding="utf-8")

    # Build artifacts from trace stats
    artifacts: list[dict[str, Any]] = []
    try:
        from khaos.evaluator.trace import TraceStatsEvaluator
        llm_stats = TraceStatsEvaluator()._llm_stats(trace_events)
        artifacts.extend([
            {
                "name": artifact.name,
                "value": artifact.value,
                "unit": artifact.unit,
                "details": artifact.details,
            }
            for artifact in llm_stats.get("artifacts", [])
        ])
    except Exception:
        pass

    metrics_path = runs_dir / f"metrics-{run_id}.json"
    metrics_payload = {
        "run_id": run_id,
        "scenario": report.pack_name or "pack",
        "seed": report.seed,
        "scenario_difficulty": None,
        "scenario_difficulty_label": None,
        "resilience_report": None,
        "artifacts": artifacts,
    }
    metrics_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

    return trace_path, metrics_path


__all__ = [
    "extract_messages_from_events",
    "build_pack_trace_from_events",
    "persist_pack_artifacts",
    "hash_messages",
    "normalize_for_hash",
]
