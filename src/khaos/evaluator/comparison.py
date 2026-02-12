"""Comparison evaluator that generates ComparisonReport artifacts."""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from khaos.output import extract_output_text
from khaos.comparison import (
    ComparisonReport,
    ComparisonRunDescriptor,
    DivergentOutput,
    FunctionalComparison,
    MetricDelta,
    ResilienceComparison,
    SecurityComparison,
    StructuralComparison,
)

@dataclass(slots=True)
class RunData:
    """In-memory representation of a captured chaos run."""

    run_id: str
    trace: list[dict[str, Any]]
    framework_metrics: dict[str, float]
    metrics_payload: dict[str, Any]
    metrics_by_name: dict[str, dict[str, Any]]
    artifacts_by_name: dict[str, dict[str, Any]]
    scenario_id: str | None
    seed: int | None
    agent_label: str | None
    executed_at: datetime | None
    resilience_scores: dict[str, float]

class ComparisonDataError(RuntimeError):
    """Raised when persisted run artifacts are missing or malformed."""

class ComparisonEvaluator:
    """Compare two runs persisted locally and emit a ComparisonReport."""

    OUTPUT_EVENT = "transport.receive"
    SIMILARITY_THRESHOLD = 0.85
    _TREND_TOLERANCE = 1e-9

    def __init__(self, runs_dir: Path | None = None) -> None:
        self.runs_dir = Path(runs_dir) if runs_dir else Path.home() / ".khaos" / "runs"

    async def compare(self, baseline_run_id: str, candidate_run_id: str) -> ComparisonReport:
        """Compare two runs stored in ~/.khaos/runs and build a ComparisonReport."""

        baseline = await self._load_run(baseline_run_id)
        candidate = await self._load_run(candidate_run_id)

        structural = self._structural_comparison(baseline, candidate)
        resilience = self._resilience_comparison(baseline, candidate)
        security = self._security_comparison(baseline, candidate)
        functional = self._functional_comparison(baseline, candidate)
        summary = self._generate_summary(structural, resilience, functional, security)

        return ComparisonReport(
            baseline=self._descriptor(baseline),
            candidate=self._descriptor(candidate),
            structural=structural,
            resilience=resilience,
            security=security,
            functional=functional,
            summary=summary,
            annotations={
                "divergent_output_count": len(functional.divergent_outputs),
                "output_similarity": functional.output_similarity,
            },
        )

    async def _load_run(self, run_id: str) -> RunData:
        metrics_path = self.runs_dir / f"metrics-{run_id}.json"
        trace_path = self.runs_dir / f"trace-{run_id}.json"
        if not metrics_path.exists():
            raise FileNotFoundError(f"Metrics artifact not found for run {run_id} at {metrics_path}")
        if not trace_path.exists():
            raise FileNotFoundError(f"Trace artifact not found for run {run_id} at {trace_path}")

        try:
            metrics_payload = json.loads(metrics_path.read_text())
        except json.JSONDecodeError as exc:
            raise ComparisonDataError(f"Metrics artifact for run {run_id} is not valid JSON") from exc

        try:
            trace_raw = json.loads(trace_path.read_text())
        except json.JSONDecodeError as exc:
            raise ComparisonDataError(f"Trace artifact for run {run_id} is not valid JSON") from exc

        # Handle pack trace format (dict with schema) vs standard trace format (list)
        trace = self._normalize_trace(trace_raw, run_id)

        resilience_report = metrics_payload.get("resilience_report") or {}
        metrics_by_name = self._build_metric_map(resilience_report.get("metrics") or [])
        artifacts_by_name = self._build_artifact_map(metrics_payload.get("artifacts") or [])
        scenario_id = metrics_payload.get("scenario")
        seed = self._extract_seed(trace)
        agent_label = self._extract_agent_label(trace)
        executed_at = self._extract_executed_at(trace)
        resilience_scores = self._normalize_scores(resilience_report.get("scores"))
        framework_metrics = self._extract_framework_metrics(trace)

        return RunData(
            run_id=run_id,
            trace=trace,
            framework_metrics=framework_metrics,
            metrics_payload=metrics_payload,
            metrics_by_name=metrics_by_name,
            artifacts_by_name=artifacts_by_name,
            scenario_id=scenario_id,
            seed=seed,
            agent_label=agent_label,
            executed_at=executed_at,
            resilience_scores=resilience_scores,
        )

    def _structural_comparison(self, baseline: RunData, candidate: RunData) -> StructuralComparison:
        cost = self._build_metric_delta(
            name="cost.total_usd",
            label="Cost",
            unit="usd",
            baseline_value=self._metric_value(baseline, "llm.cost.total_usd"),
            candidate_value=self._metric_value(candidate, "llm.cost.total_usd"),
            invert=True,
        )
        latency = self._build_metric_delta(
            name="latency.mean_seconds",
            label="Latency",
            unit="s",
            baseline_value=self._scaled_metric(baseline, "injector.latency_mean_ms", scale=0.001),
            candidate_value=self._scaled_metric(candidate, "injector.latency_mean_ms", scale=0.001),
            invert=True,
        )
        tool_calls = self._build_metric_delta(
            name="tools.total_calls",
            label="Tool Calls",
            unit="calls",
            baseline_value=self._metric_value(baseline, "mcp.tool_call.count"),
            candidate_value=self._metric_value(candidate, "mcp.tool_call.count"),
            invert=True,
        )
        framework_metrics = self._framework_additional_metrics(baseline, candidate)
        cost_source = self._cost_source_label(baseline, candidate)
        return StructuralComparison(
            cost=cost,
            latency=latency,
            tool_calls=tool_calls,
            cost_source=cost_source,
            additional_metrics=tuple(framework_metrics),
        )

    def _resilience_comparison(self, baseline: RunData, candidate: RunData) -> ResilienceComparison:
        resilience_delta = self._build_metric_delta(
            name="resilience.score",
            label="Resilience",
            unit="points",
            baseline_value=baseline.resilience_scores.get("resilience_score"),
            candidate_value=candidate.resilience_scores.get("resilience_score"),
        )
        goal_delta = self._build_metric_delta(
            name="resilience.goal",
            label="Goal",
            unit="points",
            baseline_value=baseline.resilience_scores.get("goal_score"),
            candidate_value=candidate.resilience_scores.get("goal_score"),
        )
        recovery_delta = self._build_metric_delta(
            name="resilience.recovery",
            label="Recovery",
            unit="points",
            baseline_value=baseline.resilience_scores.get("recovery_score"),
            candidate_value=candidate.resilience_scores.get("recovery_score"),
        )
        stability_delta = self._build_metric_delta(
            name="resilience.stability",
            label="Stability",
            unit="points",
            baseline_value=baseline.resilience_scores.get("stability_score"),
            candidate_value=candidate.resilience_scores.get("stability_score"),
        )
        return ResilienceComparison(
            resilience_score=resilience_delta,
            goal_score=goal_delta,
            recovery_score=recovery_delta,
            stability_score=stability_delta,
            additional_metrics=tuple(),
        )

    def _security_comparison(self, baseline: RunData, candidate: RunData) -> SecurityComparison | None:
        baseline_score = self._artifact_value(baseline, "security.score")
        candidate_score = self._artifact_value(candidate, "security.score")
        if baseline_score is None and candidate_score is None:
            return None

        score_delta = self._build_metric_delta(
            name="security.score",
            label="Security",
            unit="points",
            baseline_value=baseline_score,
            candidate_value=candidate_score,
        )
        prompt_delta = self._build_metric_delta(
            name="security.prompt_injection_defense",
            label="Prompt Injection Defense",
            unit="points",
            baseline_value=self._artifact_value(baseline, "security.prompt_injection_defense"),
            candidate_value=self._artifact_value(candidate, "security.prompt_injection_defense"),
        )
        tool_delta = self._build_metric_delta(
            name="security.tool_validation_score",
            label="Tool Validation",
            unit="points",
            baseline_value=self._artifact_value(baseline, "security.tool_validation_score"),
            candidate_value=self._artifact_value(candidate, "security.tool_validation_score"),
        )
        leakage_delta = self._build_metric_delta(
            name="security.leakage_prevention_score",
            label="Leakage Prevention",
            unit="points",
            baseline_value=self._artifact_value(baseline, "security.leakage_prevention_score"),
            candidate_value=self._artifact_value(candidate, "security.leakage_prevention_score"),
        )
        baseline_details = self._security_details(baseline.artifacts_by_name.get("security.score"))
        candidate_details = self._security_details(candidate.artifacts_by_name.get("security.score"))
        attacks_tested = int(candidate_details.get("attacks_tested") or baseline_details.get("attacks_tested") or 0)
        attacks_blocked_baseline = int(baseline_details.get("attacks_blocked") or 0)
        attacks_blocked_candidate = int(candidate_details.get("attacks_blocked") or 0)
        baseline_vulns = set(self._string_iterable(baseline_details.get("vulnerabilities_found")))
        candidate_vulns = set(self._string_iterable(candidate_details.get("vulnerabilities_found")))
        new_vulnerabilities = tuple(sorted(candidate_vulns - baseline_vulns))
        fixed_vulnerabilities = tuple(sorted(baseline_vulns - candidate_vulns))

        return SecurityComparison(
            security_score=score_delta,
            prompt_injection_defense=prompt_delta,
            tool_validation_score=tool_delta,
            leakage_prevention_score=leakage_delta,
            attacks_tested=attacks_tested,
            attacks_blocked_baseline=attacks_blocked_baseline,
            attacks_blocked_candidate=attacks_blocked_candidate,
            new_vulnerabilities=new_vulnerabilities,
            fixed_vulnerabilities=fixed_vulnerabilities,
            additional_metrics=tuple(),
        )

    def _functional_comparison(self, baseline: RunData, candidate: RunData) -> FunctionalComparison:
        baseline_outputs = [event for event in baseline.trace if event.get("event") == self.OUTPUT_EVENT]
        candidate_outputs = [event for event in candidate.trace if event.get("event") == self.OUTPUT_EVENT]

        aligned = self._align_outputs(baseline_outputs, candidate_outputs)
        total_aligned = len(aligned)
        divergent: list[DivergentOutput] = []
        matched = 0

        for idx, (baseline_event, candidate_event) in enumerate(aligned):
            similarity = self._similarity_score(baseline_event, candidate_event)
            if similarity >= self.SIMILARITY_THRESHOLD:
                matched += 1
                continue
            divergent.append(self._build_divergent_output(idx, baseline_event, candidate_event, similarity))

        output_similarity = matched / total_aligned if total_aligned else 1.0
        notes = None
        if divergent:
            notes = f"{len(divergent)} divergent output(s) detected."

        return FunctionalComparison(
            output_similarity=output_similarity,
            divergent_outputs=tuple(divergent),
            notes=notes,
        )

    def _align_outputs(
        self,
        baseline: list[dict[str, Any]],
        candidate: list[dict[str, Any]],
    ) -> list[tuple[dict[str, Any] | None, dict[str, Any] | None]]:
        labels_a = [self._event_label(event) for event in baseline]
        labels_b = [self._event_label(event) for event in candidate]
        matcher = difflib.SequenceMatcher(a=labels_a, b=labels_b, autojunk=False)
        alignment: list[tuple[dict[str, Any] | None, dict[str, Any] | None]] = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for offset in range(i2 - i1):
                    alignment.append((baseline[i1 + offset], candidate[j1 + offset]))
            elif tag == "replace":
                span = max(i2 - i1, j2 - j1)
                for offset in range(span):
                    left = baseline[i1 + offset] if i1 + offset < i2 else None
                    right = candidate[j1 + offset] if j1 + offset < j2 else None
                    alignment.append((left, right))
            elif tag == "delete":
                for offset in range(i1, i2):
                    alignment.append((baseline[offset], None))
            elif tag == "insert":
                for offset in range(j1, j2):
                    alignment.append((None, candidate[offset]))
        return alignment

    def _similarity_score(
        self,
        baseline_event: dict[str, Any] | None,
        candidate_event: dict[str, Any] | None,
    ) -> float:
        if baseline_event is None or candidate_event is None:
            return 0.0
        baseline_text = self._event_output_text(baseline_event)
        candidate_text = self._event_output_text(candidate_event)
        if not baseline_text and not candidate_text:
            return 1.0
        matcher = difflib.SequenceMatcher(a=baseline_text, b=candidate_text, autojunk=False)
        return matcher.ratio()

    def _extract_framework_metrics(self, trace: list[dict[str, Any]]) -> dict[str, float]:
        """Aggregate framework telemetry events captured during runtime."""

        counts: dict[str, int] = {}
        for event in trace:
            name = event.get("event")
            if not isinstance(name, str) or not name.startswith("framework."):
                continue
            counts[name] = counts.get(name, 0) + 1

        return {k: float(v) for k, v in counts.items()}

    def _framework_additional_metrics(self, baseline: RunData, candidate: RunData) -> list[MetricDelta]:
        """Build MetricDelta entries for framework telemetry counts."""

        metrics: list[MetricDelta] = []
        definitions = [
            ("framework.langgraph.invoke", "LangGraph Invocations", "calls"),
            ("framework.langgraph.tool", "LangGraph Tool Calls", "calls"),
            ("framework.langgraph.llm", "LangGraph LLM Calls", "calls"),
            ("framework.crewai.run", "CrewAI Runs", "calls"),
            ("framework.crewai.task", "CrewAI Tasks", "calls"),
            ("framework.crewai.llm", "CrewAI LLM Calls", "calls"),
            ("framework.prefect.run", "Prefect Flow Runs", "calls"),
            ("framework.airflow.run", "Airflow DAG Runs", "calls"),
            ("framework.dagster.run", "Dagster Job Runs", "calls"),
        ]
        for key, label, unit in definitions:
            metrics.append(
                self._build_metric_delta(
                    name=key,
                    label=label,
                    unit=unit,
                    baseline_value=baseline.framework_metrics.get(key),
                    candidate_value=candidate.framework_metrics.get(key),
                    invert=True,
                )
            )
        return metrics

    def _build_divergent_output(
        self,
        idx: int,
        baseline_event: dict[str, Any] | None,
        candidate_event: dict[str, Any] | None,
        similarity: float,
    ) -> DivergentOutput:
        label = self._extract_label(candidate_event) or self._extract_label(baseline_event)
        return DivergentOutput(
            step_index=idx,
            label=label,
            baseline_output=self._event_output_text(baseline_event) if baseline_event else None,
            candidate_output=self._event_output_text(candidate_event) if candidate_event else None,
            similarity_score=similarity,
            context=self._build_divergent_context(baseline_event, candidate_event),
        )

    def _descriptor(self, run: RunData) -> ComparisonRunDescriptor:
        security_artifact = run.artifacts_by_name.get("security.score", {})
        security_details = self._security_details(security_artifact)

        return ComparisonRunDescriptor(
            run_id=run.run_id,
            agent_name=run.agent_label,
            scenario_identifier=run.scenario_id,
            scenario_label=None,
            seed=run.seed,
            executed_at=run.executed_at,
            resilience_score=run.resilience_scores.get("resilience_score"),
            goal_score=run.resilience_scores.get("goal_score"),
            recovery_score=run.resilience_scores.get("recovery_score"),
            stability_score=run.resilience_scores.get("stability_score"),
            security_score=self._artifact_value(run, "security.overall_score"),
            attacks_blocked=int(security_details.get("attacks_blocked") or 0) if security_details else None,
            vulnerabilities_found=len(self._string_iterable(security_details.get("vulnerabilities_found"))) if security_details else None,
        )

    def _generate_summary(
        self,
        structural: StructuralComparison,
        resilience: ResilienceComparison,
        functional: FunctionalComparison,
        security: SecurityComparison | None = None,
    ) -> str | None:
        pieces = []
        for metric in (
            structural.cost,
            structural.latency,
            structural.tool_calls,
            resilience.resilience_score,
            resilience.goal_score,
            resilience.recovery_score,
            resilience.stability_score,
        ):
            snippet = self._summary_fragment(metric)
            if snippet:
                pieces.append(snippet)
        if security is not None:
            snippet = self._summary_fragment(security.security_score)
            if snippet:
                pieces.append(snippet)
        if functional.output_similarity < 0.99:
            pieces.append(f"{len(functional.divergent_outputs)} divergent output(s).")
        if not pieces:
            return "No meaningful deltas detected across structural or resilience lenses."
        return " ".join(pieces[:3])

    def _summary_fragment(self, metric: MetricDelta) -> str | None:
        if metric.absolute_delta is None:
            return None
        if metric.trend == "neutral":
            return None
        direction = "improved" if metric.trend == "improved" else "regressed"
        value = metric.absolute_delta
        unit = metric.unit or ""
        formatted = f"{value:+.2f}{unit if unit else ''}"
        return f"{metric.label} {direction} ({formatted})"

    def _scaled_metric(self, run: RunData, name: str, *, scale: float) -> float | None:
        value = self._metric_value(run, name)
        if value is None:
            return None
        return value * scale

    def _metric_value(self, run: RunData, name: str) -> float | None:
        entry = run.metrics_by_name.get(name)
        if not entry:
            return None
        value = entry.get("value")
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _artifact_value(self, run: RunData, name: str) -> float | None:
        entry = run.artifacts_by_name.get(name)
        if not entry:
            return None
        value = entry.get("value")
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _cost_source_label(self, baseline: RunData, candidate: RunData) -> str | None:
        sources: set[str] = set()
        for run in (baseline, candidate):
            artifact = run.artifacts_by_name.get("llm.observability")
            if artifact and isinstance(artifact.get("details"), dict):
                source = artifact["details"].get("cost_source")
                if isinstance(source, str) and source:
                    sources.add(source)
        if not sources:
            return None
        if len(sources) == 1:
            return next(iter(sources))
        if "reported" in sources:
            return "mixed"
        return "mixed"

    def _build_metric_delta(
        self,
        *,
        name: str,
        label: str,
        unit: str | None,
        baseline_value: float | None,
        candidate_value: float | None,
        invert: bool = False,
    ) -> MetricDelta:
        absolute_delta: float | None = None
        percent_delta: float | None = None
        trend = "unknown"
        if baseline_value is not None and candidate_value is not None:
            absolute_delta = candidate_value - baseline_value
            if abs(baseline_value) > self._TREND_TOLERANCE:
                percent_delta = absolute_delta / baseline_value
            if abs(absolute_delta) <= self._TREND_TOLERANCE:
                trend = "neutral"
            else:
                improved = absolute_delta > 0.0
                if invert:
                    improved = not improved
                trend = "improved" if improved else "regressed"
        return MetricDelta(
            name=name,
            label=label,
            unit=unit,
            baseline_value=baseline_value,
            candidate_value=candidate_value,
            absolute_delta=absolute_delta,
            percent_delta=percent_delta,
            trend=trend,
        )

    def _build_metric_map(self, metrics: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        mapping: dict[str, dict[str, Any]] = {}
        for entry in metrics:
            name = entry.get("name")
            if name:
                mapping[name] = entry
        return mapping

    def _build_artifact_map(self, artifacts: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        mapping: dict[str, dict[str, Any]] = {}
        for entry in artifacts:
            name = entry.get("name")
            if name:
                mapping[name] = entry
        return mapping

    def _security_details(self, artifact: dict[str, Any] | None) -> dict[str, Any]:
        if artifact is None:
            return {}
        details = artifact.get("details")
        if isinstance(details, dict):
            return details
        return {}

    def _string_iterable(self, values: Any) -> list[str]:
        if isinstance(values, (list, tuple, set)):
            return [str(value) for value in values if isinstance(value, str)]
        return []

    def _normalize_trace(self, trace_raw: Any, run_id: str) -> list[dict[str, Any]]:
        """Normalize trace data to a list of events, handling pack trace format.

        Pack traces have schema "khaos.pack_trace.v1" with a dict structure containing
        cases and traces. Standard traces are already a list of events.
        """
        # Standard trace format - already a list of events
        if isinstance(trace_raw, list):
            return trace_raw

        # Pack trace format - dict with schema, cases, and traces
        if isinstance(trace_raw, dict):
            schema = trace_raw.get("schema", "")
            if schema.startswith("khaos.pack_trace"):
                # Extract events from pack trace format
                return self._extract_events_from_pack_trace(trace_raw)
            # Unknown dict format - try to extract any list of events
            if "events" in trace_raw and isinstance(trace_raw["events"], list):
                return trace_raw["events"]

        raise ComparisonDataError(f"Trace artifact for run {run_id} must be a list of events or pack trace format")

    def _extract_events_from_pack_trace(self, pack_trace: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract a flat list of events from pack trace format for comparison.

        Pack traces store messages per-case in a deduplicated format. We reconstruct
        a list of events suitable for functional comparison.
        """
        events: list[dict[str, Any]] = []
        cases = pack_trace.get("cases") or []
        traces = pack_trace.get("traces") or {}

        for case in cases:
            content_hash = case.get("content_hash")
            if not content_hash:
                continue

            trace_data = traces.get(content_hash)
            if not trace_data:
                continue

            messages = trace_data.get("messages") or []
            for msg in messages:
                # Convert message format to event format for comparison
                role = msg.get("role", "")
                content = msg.get("content", "")

                # Create synthetic events that match the expected format
                if role == "user":
                    events.append({
                        "event": "transport.send",
                        "payload": {"content": content, "role": role},
                        "meta": {"case_id": case.get("case_id"), "phase": case.get("phase")},
                    })
                elif role == "assistant":
                    events.append({
                        "event": "transport.receive",
                        "payload": {"content": content, "role": role},
                        "meta": {"case_id": case.get("case_id"), "phase": case.get("phase")},
                    })
                elif role == "tool":
                    # Tool calls and results
                    events.append({
                        "event": "transport.receive",
                        "payload": {"content": content, "role": role, "tool": msg.get("name")},
                        "meta": {"case_id": case.get("case_id"), "phase": case.get("phase")},
                    })

        return events

    def _extract_seed(self, trace: list[dict[str, Any]]) -> int | None:
        for event in trace:
            meta = event.get("meta") or {}
            seed = meta.get("seed")
            if isinstance(seed, int):
                return seed
        return None

    def _extract_agent_label(self, trace: list[dict[str, Any]]) -> str | None:
        for event in trace:
            agent_id = event.get("agent_id")
            if isinstance(agent_id, str) and agent_id:
                return agent_id
        return None

    def _extract_executed_at(self, trace: list[dict[str, Any]]) -> datetime | None:
        if not trace:
            return None
        ts = trace[-1].get("ts")
        if not isinstance(ts, str):
            return None
        return self._parse_timestamp(ts)

    def _normalize_scores(self, scores: dict[str, Any] | None) -> dict[str, float]:
        if not scores:
            return {}
        normalized: dict[str, float] = {}
        for key, value in scores.items():
            try:
                normalized[key] = float(value)
            except (TypeError, ValueError):
                continue
        return normalized

    def _event_label(self, event: dict[str, Any] | None) -> str:
        if not event:
            return ""
        name = str(event.get("event") or "")
        payload = event.get("payload") or {}
        if isinstance(payload, dict):
            for key in ("message", "tool", "name", "label"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return f"{name}:{value}"
        return name

    def _event_output_text(self, event: dict[str, Any] | None) -> str:
        """Extract output text from an event using the unified helper."""
        if not event:
            return ""
        payload = event.get("payload")
        return extract_output_text(payload)

    def _extract_label(self, event: dict[str, Any] | None) -> str | None:
        if not event:
            return None
        payload = event.get("payload") or {}
        if isinstance(payload, dict):
            for key in ("label", "message", "tool", "name"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    def _build_divergent_context(
        self,
        baseline_event: dict[str, Any] | None,
        candidate_event: dict[str, Any] | None,
    ) -> dict[str, Any]:
        context: dict[str, Any] = {}
        if baseline_event:
            context["baseline"] = {
                "payload": baseline_event.get("payload"),
                "meta": baseline_event.get("meta"),
            }
        if candidate_event:
            context["candidate"] = {
                "payload": candidate_event.get("payload"),
                "meta": candidate_event.get("meta"),
            }
        return context

    def _parse_timestamp(self, value: str) -> datetime | None:
        normalized = value.replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)
        return timestamp
