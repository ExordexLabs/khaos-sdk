"""Utilities for building a normalized LLM trace payload for the dashboard."""

from __future__ import annotations

from typing import Any


def build_llm_trace(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Build a compact LLM trace payload from raw llm.call events.

    `records` must be the parsed JSONL entries written by `khaos.llm.telemetry`.
    """

    if not records:
        return None

    interactions: list[dict[str, Any]] = []
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_cost = 0.0
    total_latency = 0.0
    models: set[str] = set()
    pii_hits = 0

    for idx, record in enumerate(records, start=1):
        payload = record.get("payload", {}) or {}
        content = payload.get("content", {}) or {}
        tokens = payload.get("tokens", {}) or {}
        meta = record.get("meta", {}) or {}

        prompt_tokens = int(tokens.get("prompt", 0) or 0)
        completion_tokens = int(tokens.get("completion", 0) or 0)
        total_tokens = prompt_tokens + completion_tokens
        cost_total = float(payload.get("cost_usd", 0.0) or 0.0)
        latency_ms = float(payload.get("latency_ms", 0.0) or 0.0)
        provider = payload.get("provider", "unknown") or "unknown"
        model = payload.get("model", "unknown") or "unknown"

        models.add(model)
        total_prompt_tokens += prompt_tokens
        total_completion_tokens += completion_tokens
        total_cost += cost_total
        total_latency += latency_ms
        if meta.get("pii_detected"):
            pii_hits += 1

        prompt_cost_field = payload.get("cost_prompt_usd")
        completion_cost_field = payload.get("cost_completion_usd")
        if prompt_cost_field is None or completion_cost_field is None:
            ratio = (prompt_tokens / total_tokens) if total_tokens else 0.5
            prompt_cost = cost_total * ratio
            completion_cost = cost_total - prompt_cost
        else:
            prompt_cost = float(prompt_cost_field or 0.0)
            completion_cost = float(completion_cost_field or 0.0)

        interactions.append(
            {
                "interaction_id": f"llm-{idx:04d}",
                "timestamp": record.get("ts"),
                "provider": provider,
                "model": model,
                "request": {
                    "messages": [
                        {
                            "role": "user",
                            "content": content.get("prompt")
                            or ("(redacted)" if content.get("mode") == "redact" else ""),
                        }
                    ],
                    "metadata": payload.get("metadata", {}),
                },
                "response": {
                    "message": {
                        "role": "assistant",
                        "content": content.get("completion"),
                        "tool_calls": payload.get("tool_calls"),
                    },
                    "finish_reason": payload.get("finish_reason", "stop"),
                },
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                },
                "cost": {
                    "prompt_cost_usd": round(prompt_cost, 10),
                    "completion_cost_usd": round(completion_cost, 10),
                    "total_cost_usd": round(cost_total, 10),
                },
                "latency_ms": round(latency_ms, 3),
                "pii_detected": bool(meta.get("pii_detected")),
                "content_mode": content.get("mode"),
            }
        )

    return {
        "total_llm_calls": len(records),
        "total_tokens": total_prompt_tokens + total_completion_tokens,
        "total_cost_usd": round(total_cost, 6),
        "models_used": sorted(models),
        "prompt_tokens": total_prompt_tokens,
        "completion_tokens": total_completion_tokens,
        "avg_latency_ms": round(total_latency / len(records), 3) if records else 0.0,
        "pii_hits": pii_hits,
        "interactions": interactions,
    }

