"""Trace-driven evaluator implementations."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any
from collections.abc import Iterable

import statistics
import os

from khaos.costs import estimate_cost_usd, load_cost_table
from .base import EvaluationArtifact, EvaluationContext, Evaluator
from khaos.metrics import MetricDatum, ResilienceReport

TRANSPORT_INSTABILITY_WEIGHT = 0.5
TOOL_INSTABILITY_WEIGHT = 0.3
LLM_INSTABILITY_WEIGHT = 0.2
LLM_LOOP_SAFE_CALLS = 8

class TraceStatsEvaluator(Evaluator):
    """Summarize transport/injector events and emit a resilience report."""

    name = "trace-stats"

    async def evaluate(
        self,
        context: EvaluationContext,
    ) -> Iterable[EvaluationArtifact]:
        trace = context.metadata.get("trace", [])
        if not trace:
            return []

        counter = Counter(event["event"] for event in trace)
        artifacts: list[EvaluationArtifact] = []

        for metric_name, value in sorted(counter.items()):
            artifacts.append(
                EvaluationArtifact(
                    name=f"{metric_name}.count",
                    value=int(value),
                    unit="events",
                    details={"event": metric_name},
                )
            )

        success_count = counter.get("transport.receive", 0)
        send_count = counter.get("transport.send", 0)
        error_count = counter.get("transport.error", 0)

        total_latency = sum(
            event["payload"].get("latency_ms", 0.0)
            for event in trace
            if event["event"] == "injector.action"
        )
        artifacts.append(
            EvaluationArtifact(
                name="injector.total_latency_ms",
                value=float(total_latency),
                unit="ms",
                details={},
            )
        )

        mcp_stats = self._mcp_stats(trace)
        artifacts.extend(mcp_stats["artifacts"])
        llm_stats = self._llm_stats(trace)
        artifacts.extend(llm_stats["artifacts"])

        goal_component = self._goal_component(artifacts)
        recovery_component = self._recovery_component(success_count, send_count)
        stability_component, stability_breakdown = self._stability_component(
            success_count,
            error_count,
            mcp_stats["summary"],
            llm_stats["summary"],
        )
        score = self._resilience_score(
            goal_component,
            recovery_component,
            stability_component,
        )

        artifacts.extend(
            [
                EvaluationArtifact(
                    name="resilience.goal_component",
                    value=goal_component,
                    unit="ratio",
                    details={},
                ),
                EvaluationArtifact(
                    name="resilience.recovery_component",
                    value=recovery_component,
                    unit="ratio",
                    details={"success": success_count, "attempts": send_count},
                ),
                EvaluationArtifact(
                    name="resilience.stability_component",
                    value=stability_component,
                    unit="ratio",
                    details=stability_breakdown,
                ),
            ]
        )
        artifacts.append(
            EvaluationArtifact(
                name="resilience.score",
                value=score,
                unit="points",
                details={
                    "formula": "100 * (0.4*goal + 0.3*recovery + 0.3*stability)",
                    "goal_component": goal_component,
                    "recovery_component": recovery_component,
                    "stability_component": stability_component,
                },
            )
        )

        recovery_rate = recovery_component
        artifacts.append(
            EvaluationArtifact(
                name="transport.recovery_rate",
                value=recovery_rate,
                unit="ratio",
                details={"success": success_count, "attempts": send_count},
            )
        )

        artifacts.append(
            self._build_report(
                context,
                artifacts,
                trace,
                mcp_stats["summary"],
                llm_stats["summary"],
                goal_component,
                recovery_component,
                stability_component,
                stability_breakdown,
            )
        )
        return artifacts

    def _goal_component(self, artifacts: list[EvaluationArtifact]) -> float:
        goal_artifact = next(
            (artifact for artifact in artifacts if artifact.name == "goal.score"),
            None,
        )
        if goal_artifact is not None:
            return max(0.0, min(1.0, float(goal_artifact.value) / 100.0))

        assertion_artifact = next(
            (
                artifact
                for artifact in artifacts
                if artifact.name == "assertion.pass_rate"
            ),
            None,
        )
        if assertion_artifact is not None:
            return max(0.0, min(1.0, float(assertion_artifact.value) / 100.0))
        return 1.0

    def _recovery_component(self, success_count: int, send_count: int) -> float:
        if send_count <= 0:
            return 0.0
        return max(0.0, min(1.0, success_count / send_count))

    def _stability_component(
        self,
        success_count: int,
        error_count: int,
        mcp_summary: dict[str, Any],
        llm_summary: dict[str, Any],
    ) -> tuple[float, dict[str, float]]:
        total_attempts = success_count + error_count
        transport_error_rate = (error_count / total_attempts) if total_attempts else 0.0

        tool_calls = int(mcp_summary.get("call_count") or 0)
        tool_faults = int(mcp_summary.get("failure_count") or 0) + int(
            mcp_summary.get("corruption_count") or 0
        )
        tool_fault_rate = (tool_faults / tool_calls) if tool_calls else 0.0

        llm_calls = int(llm_summary.get("call_count") or 0)
        pii_hits = int(llm_summary.get("pii_hits") or 0)
        llm_pii_rate = (pii_hits / llm_calls) if llm_calls else 0.0
        if llm_calls > LLM_LOOP_SAFE_CALLS:
            llm_loop_rate = min(1.0, (llm_calls - LLM_LOOP_SAFE_CALLS) / LLM_LOOP_SAFE_CALLS)
        else:
            llm_loop_rate = 0.0
        llm_anomaly_penalty = min(1.0, 0.7 * llm_pii_rate + 0.3 * llm_loop_rate)

        weighted_penalty = (
            transport_error_rate * TRANSPORT_INSTABILITY_WEIGHT
            + tool_fault_rate * TOOL_INSTABILITY_WEIGHT
            + llm_anomaly_penalty * LLM_INSTABILITY_WEIGHT
        )
        instability = min(1.0, max(transport_error_rate, weighted_penalty))
        stability = max(0.0, 1.0 - instability)

        breakdown = {
            "transport_error_rate": round(transport_error_rate, 4),
            "transport_errors": float(error_count),
            "transport_attempts": float(total_attempts),
            "tool_fault_rate": round(tool_fault_rate, 4),
            "tool_faults": float(tool_faults),
            "tool_calls": float(tool_calls),
            "llm_pii_rate": round(llm_pii_rate, 4),
            "llm_loop_rate": round(llm_loop_rate, 4),
            "llm_anomaly_penalty": round(llm_anomaly_penalty, 4),
            "llm_calls": float(llm_calls),
            "pii_hits": float(pii_hits),
            "instability": round(instability, 4),
        }
        return stability, breakdown

    def _resilience_score(
        self,
        goal_component: float,
        recovery_component: float,
        stability_component: float,
    ) -> float:
        weighted = (
            0.4 * goal_component
            + 0.3 * recovery_component
            + 0.3 * stability_component
        )
        return round(weighted * 100.0, 3)

    def _build_report(
        self,
        context: EvaluationContext,
        artifacts: list[EvaluationArtifact],
        trace: list[dict],
        mcp_summary: dict[str, float],
        llm_summary: dict[str, float],
        goal_component: float,
        recovery_component: float,
        stability_component: float,
        stability_breakdown: dict[str, float],
    ) -> EvaluationArtifact:
        latency_values = self._latency_values(trace)
        success_count = int(
            next((a.value for a in artifacts if a.name == "transport.receive.count"), 0)
        )
        send_count = int(
            next((a.value for a in artifacts if a.name == "transport.send.count"), 0)
        )
        error_count = int(
            next((a.value for a in artifacts if a.name == "transport.error.count"), 0)
        )
        score = next(
            (a.value for a in artifacts if a.name == "resilience.score"),
            0.0,
        )

        captured_at = context.metadata.get("captured_at")
        if captured_at is None:
            captured_at = datetime.now(timezone.utc)

        metrics: list[MetricDatum] = [
            MetricDatum(
                name="resilience.score",
                value=score,
                unit="points",
                captured_at=captured_at,
                metadata={},
            ),
            MetricDatum(
                name="resilience.goal_component",
                value=goal_component,
                unit="ratio",
                captured_at=captured_at,
                metadata={},
            ),
            MetricDatum(
                name="resilience.recovery_component",
                value=recovery_component,
                unit="ratio",
                captured_at=captured_at,
                metadata={"success": success_count, "attempts": send_count},
            ),
            MetricDatum(
                name="resilience.stability_component",
                value=stability_component,
                unit="ratio",
                captured_at=captured_at,
                metadata=stability_breakdown,
            ),
            MetricDatum(
                name="transport.recovery_rate",
                value=(success_count / send_count) if send_count else 0.0,
                unit="ratio",
                captured_at=captured_at,
                metadata={"success": success_count, "attempts": send_count},
            ),
            MetricDatum(
                name="transport.success_count",
                value=float(success_count),
                unit="events",
                captured_at=captured_at,
                metadata={},
            ),
            MetricDatum(
                name="transport.error_count",
                value=float(error_count),
                unit="events",
                captured_at=captured_at,
                metadata={},
            ),
        ]

        goal_score_artifact = next(
            (artifact for artifact in artifacts if artifact.name == "goal.score"),
            None,
        )
        if goal_score_artifact is not None:
            metrics.append(
                MetricDatum(
                    name="goal.score",
                    value=float(goal_score_artifact.value),
                    unit="points",
                    captured_at=captured_at,
                    metadata=goal_score_artifact.details,
                )
            )

        assertion_rate_artifact = next(
            (artifact for artifact in artifacts if artifact.name == "assertion.pass_rate"),
            None,
        )
        if assertion_rate_artifact is not None:
            metrics.append(
                MetricDatum(
                    name="assertion.pass_rate",
                    value=float(assertion_rate_artifact.value),
                    unit="percent",
                    captured_at=captured_at,
                    metadata=assertion_rate_artifact.details,
                )
            )

        if latency_values:
            mean_latency = sum(latency_values) / len(latency_values)
            if len(latency_values) >= 2:
                percentiles = statistics.quantiles(latency_values, n=100, method="inclusive")
                p95 = percentiles[94]
                p99 = percentiles[98]
            else:
                p95 = p99 = latency_values[0]

            metrics.extend(
                [
                    MetricDatum(
                        name="injector.latency_mean_ms",
                        value=mean_latency,
                        unit="ms",
                        captured_at=captured_at,
                        metadata={},
                    ),
                    MetricDatum(
                        name="injector.latency_p95_ms",
                        value=p95,
                        unit="ms",
                        captured_at=captured_at,
                        metadata={},
                    ),
                    MetricDatum(
                        name="injector.latency_p99_ms",
                        value=p99,
                        unit="ms",
                        captured_at=captured_at,
                        metadata={},
                    ),
                ]
            )

        if mcp_summary["call_count"]:
            metrics.append(
                MetricDatum(
                    name="mcp.tool_call.count",
                    value=float(mcp_summary["call_count"]),
                    unit="events",
                    captured_at=captured_at,
                    metadata={},
                )
            )
        if mcp_summary["failure_count"]:
            metrics.append(
                MetricDatum(
                    name="mcp.tool_failure.count",
                    value=float(mcp_summary["failure_count"]),
                    unit="events",
                    captured_at=captured_at,
                    metadata={},
                )
            )
        if mcp_summary["corruption_count"]:
            metrics.append(
                MetricDatum(
                    name="mcp.tool_corruption.count",
                    value=float(mcp_summary["corruption_count"]),
                    unit="events",
                    captured_at=captured_at,
                    metadata={},
                )
            )
        if mcp_summary["delay_ms"]:
            metrics.append(
                MetricDatum(
                    name="mcp.tool_delay.total_ms",
                    value=float(mcp_summary["delay_ms"]),
                    unit="ms",
                    captured_at=captured_at,
                    metadata={},
                )
            )

        report = ResilienceReport(
            run_identifier=context.run_identifier,
            scenario_identifier=context.scenario_identifier,
            metrics=metrics,
            summary_score=score,
            scenario_difficulty=context.metadata.get("scenario_difficulty"),
            scenario_difficulty_label=context.metadata.get("scenario_difficulty_label"),
        )

        if llm_summary["call_count"]:
            metrics.append(
                MetricDatum(
                    name="llm.call.count",
                    value=float(llm_summary["call_count"]),
                    unit="events",
                    captured_at=captured_at,
                    metadata={},
                )
            )
        if llm_summary["total_tokens_in"]:
            metrics.append(
                MetricDatum(
                    name="llm.tokens.prompt.total",
                    value=float(llm_summary["total_tokens_in"]),
                    unit="tokens",
                    captured_at=captured_at,
                    metadata={},
                )
            )
        if llm_summary["total_tokens_out"]:
            metrics.append(
                MetricDatum(
                    name="llm.tokens.completion.total",
                    value=float(llm_summary["total_tokens_out"]),
                    unit="tokens",
                    captured_at=captured_at,
                    metadata={},
                )
            )
        if llm_summary["cost_usd"]:
            metrics.append(
                MetricDatum(
                    name="llm.cost.total_usd",
                    value=float(llm_summary["cost_usd"]),
                    unit="usd",
                    captured_at=captured_at,
                    metadata={},
                )
            )

        report_dict = report.to_dict()

        goal_artifact = next(
            (artifact for artifact in artifacts if artifact.name == "goal.score"),
            None,
        )
        assertion_artifact = next(
            (artifact for artifact in artifacts if artifact.name == "assertion.pass_rate"),
            None,
        )
        goal_steps = [
            artifact
            for artifact in artifacts
            if artifact.name.startswith("goal.") and artifact.name != "goal.score"
        ]

        report_dict["scores"] = {
            "resilience_score": score,
            "goal_score": float(goal_artifact.value) if goal_artifact else round(goal_component * 100.0, 3),
            "recovery_score": round(recovery_component * 100.0, 3),
            "stability_score": round(stability_component * 100.0, 3),
            "overall_score": score,
        }

        report_dict["resilience"] = {
            "score": score,
            "goal_component": goal_component,
            "recovery_component": recovery_component,
            "stability_component": stability_component,
            "metrics": {
                "transport_error_count": error_count,
                "success_count": success_count,
                "recovery_rate": recovery_component,
            },
        }

        report_dict["goal"] = {
            "score": float(goal_artifact.value) if goal_artifact else round(goal_component * 100.0, 3),
            "steps": [
                {
                    "name": artifact.name.replace("goal.", ""),
                    "details": artifact.details or {},
                }
                for artifact in goal_steps
            ],
            "assertions": assertion_artifact.details.get("assertions")
            if assertion_artifact and isinstance(assertion_artifact.details, dict)
            else [],
            "pass_rate": assertion_artifact.value if assertion_artifact else None,
        }

        report_dict["recovery"] = {
            "score": round(recovery_component * 100.0, 3),
            "success_count": success_count,
            "attempts": send_count,
        }

        report_dict["stability"] = {
            "score": round(stability_component * 100.0, 3),
            "breakdown": stability_breakdown,
        }

        return EvaluationArtifact(
            name="resilience.report",
            value=score,
            unit="points",
            details={"report": report_dict},
        )

    def _latency_values(self, trace: list[dict]) -> list[float]:
        return [
            float(event["payload"].get("latency_ms", 0.0))
            for event in trace
            if event["event"] == "injector.action" and "latency_ms" in event["payload"]
        ]

    def _mcp_stats(self, trace: list[dict]) -> dict[str, Any]:
        call_count = sum(1 for event in trace if event["event"] == "mcp.tool_call_plan")
        failure_count = sum(
            1 for event in trace if event["event"] == "mcp.tool_call_injected_failure"
        )
        corruption_count = sum(
            1 for event in trace if event["event"] == "mcp.tool_call_corrupted"
        )
        delay_ms = sum(
            float(event["payload"].get("delay_ms", 0.0))
            for event in trace
            if event["event"] == "mcp.tool_call_delay"
        )

        tool_state: dict[str, dict[str, Any]] = {}
        server_counts: dict[str, dict[str, int]] = {}
        latency_samples: list[float] = []

        def _tool_record(name: str) -> dict[str, Any]:
            record = tool_state.get(name)
            if record is None:
                record = {
                    "calls": 0,
                    "failures": 0,
                    "latencies": [],
                }
                tool_state[name] = record
            return record

        for event in trace:
            payload = event.get("payload") or {}
            meta = event.get("meta") or {}
            if event["event"] == "mcp.tool_call_plan":
                tool = payload.get("tool", "unknown")
                _tool_record(tool)  # ensure record exists
            elif event["event"] == "mcp.tool_call_result":
                tool = payload.get("tool", "unknown")
                status = payload.get("status", "success")
                record = _tool_record(tool)
                record["calls"] += 1
                if status != "success":
                    record["failures"] += 1
                latency = meta.get("latency_ms")
                if latency is not None:
                    latency_value = float(latency)
                    record.setdefault("latencies", []).append(latency_value)
                    latency_samples.append(latency_value)
            elif event["event"] in {"mcp.server_registered", "mcp.server_unavailable"}:
                server_name = (
                    payload.get("name")
                    or payload.get("server")
                    or "unknown"
                )
                counts = server_counts.setdefault(server_name, {"registered": 0, "unavailable": 0})
                if event["event"] == "mcp.server_registered":
                    counts["registered"] += 1
                else:
                    counts["unavailable"] += 1

        per_tool_summary: dict[str, dict[str, float]] = {}
        for tool, record in tool_state.items():
            calls = int(record.get("calls", 0))
            failures = int(record.get("failures", 0))
            latencies = record.get("latencies", []) or []
            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
            per_tool_summary[tool] = {
                "calls": float(calls),
                "failures": float(failures),
                "success_rate": ((calls - failures) / calls) if calls else 0.0,
                "avg_latency_ms": avg_latency,
            }

        avg_latency_overall = sum(latency_samples) / len(latency_samples) if latency_samples else 0.0

        per_server_summary: dict[str, float] = {}
        for server, counts in server_counts.items():
            registered = counts.get("registered", 0)
            unavailable = counts.get("unavailable", 0)
            if registered <= 0:
                availability = 0.0
            else:
                availability = max(0.0, (registered - unavailable) / registered)
            per_server_summary[server] = availability

        artifacts: list[EvaluationArtifact] = []
        if call_count:
            artifacts.append(
                EvaluationArtifact(
                    name="mcp.tool_call.count",
                    value=float(call_count),
                    unit="events",
                    details={},
                )
            )
        if failure_count:
            artifacts.append(
                EvaluationArtifact(
                    name="mcp.tool_failure.count",
                    value=float(failure_count),
                    unit="events",
                    details={},
                )
            )
        if corruption_count:
            artifacts.append(
                EvaluationArtifact(
                    name="mcp.tool_corruption.count",
                    value=float(corruption_count),
                    unit="events",
                    details={},
                )
            )
        if delay_ms:
            artifacts.append(
                EvaluationArtifact(
                    name="mcp.tool_delay.total_ms",
                    value=float(delay_ms),
                    unit="ms",
                    details={},
                )
            )
        if per_tool_summary:
            artifacts.append(
                EvaluationArtifact(
                    name="mcp.tool.metrics",
                    value=float(call_count),
                    unit="events",
                    details={
                        "total_calls": float(call_count),
                        "failure_count": float(failure_count),
                        "avg_latency_ms": avg_latency_overall,
                        "per_tool": per_tool_summary,
                        "per_server": per_server_summary,
                    },
                )
            )

        summary = {
            "call_count": float(call_count),
            "failure_count": float(failure_count),
            "corruption_count": float(corruption_count),
            "delay_ms": float(delay_ms),
            "avg_latency_ms": float(avg_latency_overall),
            "per_tool": per_tool_summary,
            "per_server": per_server_summary,
        }
        return {"artifacts": artifacts, "summary": summary}

    def _llm_stats(self, trace: list[dict]) -> dict[str, Any]:
        events = [event for event in trace if event.get("event") == "llm.call"]
        call_count = len(events)
        total_tokens_in = 0.0
        total_tokens_out = 0.0
        total_cost = 0.0
        total_prompt_cost = 0.0
        total_completion_cost = 0.0
        total_latency = 0.0
        pii_hits = 0
        per_model: dict[str, dict[str, float]] = {}
        cost_sources: set[str] = set()
        cost_table = load_cost_table(os.environ.get("KHAOS_COST_TABLE"))

        for event in events:
            payload = event.get("payload", {})
            tokens = payload.get("tokens", {})
            tokens_in = float(tokens.get("prompt", 0.0))
            tokens_out = float(tokens.get("completion", 0.0))
            total_tokens_in += tokens_in
            total_tokens_out += tokens_out
            cost_raw = payload.get("cost_usd")
            cost = float(cost_raw) if cost_raw not in (None, "") else 0.0
            prompt_cost_raw = payload.get("cost_prompt_usd")
            completion_cost_raw = payload.get("cost_completion_usd")
            provider = payload.get("provider") or "unknown"
            model = payload.get("model", "unknown")
            cost_source = "unknown"
            if cost > 0:
                cost_source = "reported"
            elif tokens_in or tokens_out:
                estimated_cost, estimated_source = estimate_cost_usd(
                    provider=provider,
                    model=model,
                    prompt_tokens=tokens_in,
                    completion_tokens=tokens_out,
                    table=cost_table,
                )
                if estimated_cost is not None:
                    cost = estimated_cost
                    cost_source = estimated_source
            if prompt_cost_raw is None or completion_cost_raw is None:
                ratio = tokens_in / (tokens_in + tokens_out) if (tokens_in + tokens_out) else 0.5
                prompt_cost = cost * ratio
                completion_cost = cost - prompt_cost
            else:
                prompt_cost = float(prompt_cost_raw)
                completion_cost = float(completion_cost_raw)
            total_cost += cost
            total_prompt_cost += prompt_cost
            total_completion_cost += completion_cost
            latency = float(payload.get("latency_ms", 0.0))
            total_latency += latency
            if isinstance(event.get("meta"), dict) and event["meta"].get("pii_detected"):
                pii_hits += 1
            cost_sources.add(cost_source)
            entry = per_model.setdefault(
                model,
                {
                    "calls": 0.0,
                    "tokens_in": 0.0,
                    "tokens_out": 0.0,
                    "cost_usd": 0.0,
                    "prompt_cost": 0.0,
                    "completion_cost": 0.0,
                    "latency_total": 0.0,
                    "cost_source": cost_source,
                },
            )
            entry["calls"] += 1
            entry["tokens_in"] += tokens_in
            entry["tokens_out"] += tokens_out
            entry["cost_usd"] += cost
            entry["prompt_cost"] += prompt_cost
            entry["completion_cost"] += completion_cost
            entry["latency_total"] += latency

        def _cost_source_label() -> str:
            if not cost_sources:
                return "unknown"
            if len(cost_sources) == 1:
                return next(iter(cost_sources))
            if "reported" in cost_sources:
                return "mixed"
            return "estimated"

        artifacts: list[EvaluationArtifact] = []
        if call_count:
            details = {
                "call_count": float(call_count),
                "total_tokens_in": total_tokens_in,
                "total_tokens_out": total_tokens_out,
                "cost_usd": total_cost,
                "cost_prompt_usd": total_prompt_cost,
                "cost_completion_usd": total_completion_cost,
                "avg_latency_ms": total_latency / call_count if call_count else 0.0,
                "pii_hits": pii_hits,
                "cost_source": _cost_source_label(),
                "per_model": {
                    model: {
                        "calls": stats["calls"],
                        "tokens_in": stats["tokens_in"],
                        "tokens_out": stats["tokens_out"],
                        "cost_usd": stats["cost_usd"],
                        "prompt_cost_usd": stats.get("prompt_cost", 0.0),
                        "completion_cost_usd": stats.get("completion_cost", 0.0),
                        "avg_latency_ms": stats["latency_total"] / stats["calls"] if stats["calls"] else 0.0,
                        "cost_source": stats.get("cost_source", "unknown"),
                    }
                    for model, stats in per_model.items()
                },
            }
            artifacts.append(
                EvaluationArtifact(
                    name="llm.observability",
                    value=float(call_count),
                    unit="events",
                    details=details,
                )
            )

        summary = {
            "call_count": float(call_count),
            "total_tokens_in": total_tokens_in,
            "total_tokens_out": total_tokens_out,
            "cost_usd": total_cost,
            "cost_prompt_usd": total_prompt_cost,
            "cost_completion_usd": total_completion_cost,
            "avg_latency_ms": total_latency / call_count if call_count else 0.0,
            "pii_hits": float(pii_hits),
            "cost_source": _cost_source_label(),
            "per_model": {
                model: {
                    "calls": stats["calls"],
                    "tokens_in": stats["tokens_in"],
                    "tokens_out": stats["tokens_out"],
                    "cost_usd": stats["cost_usd"],
                    "prompt_cost_usd": stats.get("prompt_cost", 0.0),
                    "completion_cost_usd": stats.get("completion_cost", 0.0),
                    "avg_latency_ms": stats["latency_total"] / stats["calls"] if stats["calls"] else 0.0,
                    "cost_source": stats.get("cost_source", "unknown"),
                }
                for model, stats in per_model.items()
            },
        }
        return {"artifacts": artifacts, "summary": summary}
