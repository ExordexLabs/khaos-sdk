"""Pack runner - executes evaluation packs and produces reports.

The runner orchestrates the three-phase evaluation:
1. Baseline - Pure agent observation
2. Resilience - Agent under fault injection
3. Security - Agent under attack testing
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import statistics
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from collections.abc import Callable

from .schema import (
    Pack,
    PackInput,
    PackPhase,
    PhaseType,
    load_pack,
    get_builtin_pack,
)
from .contract import (
    EvaluationReport,
    AgentInfo,
    BaselineMetrics,
    ResilienceMetrics,
    SecurityMetrics,
    LatencyMetrics,
    TokenMetrics,
    FaultImpact,
    FaultCoverage,
    FaultInjectedRecord,
    FaultInjectedImpact,
    VulnerabilityDetail,
    InputResult,
    TurnResultDetail,
    OutputConsistencyMetrics,
)
from .schema import FaultConfig
from khaos.artifacts import RunManifest, write_manifest, generate_run_id

def generate_evaluation_id() -> str:
    """Generate a unique evaluation ID for grouping pack scenario runs."""
    date_str = datetime.utcnow().strftime("%Y%m%d")
    uuid_suffix = uuid.uuid4().hex[:8]
    return f"khaos-eval-{date_str}-{uuid_suffix}"

@dataclass
class TurnResult:
    """Result of a single turn in a multi-turn conversation."""

    turn_index: int
    user_input: str
    response: str
    latency_ms: float
    tokens_in: int = 0
    tokens_out: int = 0
    goal_met: bool | None = None  # Per-turn goal result
    faults_applied: list[str] = field(default_factory=list)  # Fault types applied this turn
    error: str | None = None

@dataclass
class RunResult:
    """Result of a single agent invocation."""

    input_id: str
    success: bool
    latency_ms: float
    response: str
    tokens_in: int = 0
    tokens_out: int = 0
    error: str | None = None
    goal_met: bool | None = None  # Did the agent achieve the goal?
    checks_met: bool | None = None  # Additional Khaos checks (dependency usage, etc.)
    check_errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Multi-turn fields (NEW)
    is_multi_turn: bool = False
    turn_count: int = 1
    turns: list[TurnResult] = field(default_factory=list)

    # Backwards compatibility alias
    @property
    def expectation_met(self) -> bool | None:
        return self.goal_met

@dataclass
class PhaseResult:
    """Result of running a complete phase."""

    phase_type: PhaseType
    runs: list[RunResult]
    total_time_ms: float
    error_count: int = 0

    @property
    def latencies(self) -> list[float]:
        return [
            r.latency_ms
            for r in self.runs
            if r.success and not _is_khaos_skipped_run(r.metadata)
        ]

    @property
    def success_rate(self) -> float:
        eligible = [r for r in self.runs if not _is_khaos_skipped_run(r.metadata)]
        if not eligible:
            return 0.0
        return sum(1 for r in eligible if r.success) / len(eligible)

@dataclass
class EvaluationResult:
    """Complete evaluation result."""

    pack: Pack
    phases: dict[PhaseType, PhaseResult]
    report: EvaluationReport
    total_time_ms: float

# Type for agent invocation function
AgentInvoker = Callable[[str], str | tuple[str, dict[str, Any]]]

# Type for multi-turn agent invocation (sessionful)
# Takes (input, phase, run_index) and returns RunResult with turns populated
MultiTurnInvoker = Callable[["PackInput", str, int], "RunResult"]

def _is_khaos_skipped_run(metadata: dict[str, Any] | None) -> bool:
    if not isinstance(metadata, dict):
        return False
    return bool(metadata.get("khaos_skip"))

def _check_goal(response: str, goal: Any) -> bool:
    """Check if response meets goal criteria."""
    if goal is None:
        return True

    response_lower = response.lower()

    if goal.contains and goal.contains.lower() not in response_lower:
        return False

    if goal.contains_any:
        if not any(c.lower() in response_lower for c in goal.contains_any):
            return False

    if goal.contains_all:
        if not all(c.lower() in response_lower for c in goal.contains_all):
            return False

    if goal.not_contains and goal.not_contains.lower() in response_lower:
        return False

    if goal.min_length and len(response) < goal.min_length:
        return False

    if goal.max_length and len(response) > goal.max_length:
        return False

    if goal.matches_regex:
        if not re.search(goal.matches_regex, response):
            return False

    return True

# Alias for backwards compatibility
_check_expectation = _check_goal

def _compute_latency_metrics(latencies: list[float]) -> LatencyMetrics:
    """Compute latency statistics."""
    if not latencies:
        return LatencyMetrics(p50=0, p95=0, p99=0, min=0, max=0, mean=0)

    sorted_lat = sorted(latencies)
    n = len(sorted_lat)

    return LatencyMetrics(
        p50=sorted_lat[int(n * 0.50)] if n > 0 else 0,
        p95=sorted_lat[int(n * 0.95)] if n > 1 else sorted_lat[-1],
        p99=sorted_lat[int(n * 0.99)] if n > 2 else sorted_lat[-1],
        min=min(sorted_lat),
        max=max(sorted_lat),
        mean=statistics.mean(sorted_lat),
    )

def _compute_token_metrics(results: list[RunResult]) -> TokenMetrics:
    """Compute token usage statistics."""
    input_totals = [r.tokens_in for r in results]
    output_totals = [r.tokens_out for r in results]

    return TokenMetrics(
        input_total=sum(input_totals),
        output_total=sum(output_totals),
        input_avg=statistics.mean(input_totals) if input_totals else 0,
        output_avg=statistics.mean(output_totals) if output_totals else 0,
    )

def _estimate_cost(
    results: list[RunResult],
    provider: str | None = None,
    model: str | None = None,
) -> float:
    """Estimate USD cost from token counts using pricing tables.

    Uses khaos.llm.costs for model-specific pricing lookup. Falls back to
    gpt-4o-mini pricing when provider/model is not specified.
    """
    from khaos.llm.costs import estimate_cost, PricingNotFound

    total_input_tokens = sum(r.tokens_in for r in results)
    total_output_tokens = sum(r.tokens_out for r in results)

    if total_input_tokens == 0 and total_output_tokens == 0:
        return 0.0

    # Use provided provider/model or default to openai/gpt-4o-mini
    effective_provider = provider or "openai"
    effective_model = model or "gpt-4o-mini"

    try:
        cost_estimate = estimate_cost(
            provider=effective_provider,
            model=effective_model,
            prompt_tokens=total_input_tokens,
            completion_tokens=total_output_tokens,
        )
        return cost_estimate.total_cost_usd
    except PricingNotFound:
        # Fall back to gpt-4o-mini pricing as reasonable default
        cost_estimate = estimate_cost(
            provider="openai",
            model="gpt-4o-mini",
            prompt_tokens=total_input_tokens,
            completion_tokens=total_output_tokens,
        )
        return cost_estimate.total_cost_usd

class PackRunner:
    """Runs evaluation packs against agents."""

    def __init__(
        self,
        agent_invoker: AgentInvoker,
        agent_name: str = "agent",
        agent_version: str = "1.0.0",
        agent_source: str | None = None,
        framework: str | None = None,
        on_progress: Callable[[str, int, int], None] | None = None,
        on_input_start: Callable[[str], None] | None = None,
        on_result: Callable[[str, str, bool, float, str | None], None] | None = None,
        evaluation_id: str | None = None,
        multi_turn_invoker: MultiTurnInvoker | None = None,
    ):
        """Initialize pack runner.

        Args:
            agent_invoker: Function that takes input text and returns response text
            agent_name: Name of the agent being tested
            agent_version: Version of the agent
            agent_source: Source code of agent (for hashing)
            framework: Framework used (crewai, langgraph, etc.)
            on_progress: Callback for progress updates (phase, current, total)
            on_input_start: Callback called before each input (input_id) for fault scheduling
            on_result: Callback for individual test results (phase, input_id, passed, latency_ms, error)
            evaluation_id: Optional evaluation ID for grouping pack scenario runs
            multi_turn_invoker: Optional invoker for multi-turn conversations (sessionful)
        """
        self.agent_invoker = agent_invoker
        self.multi_turn_invoker = multi_turn_invoker
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.agent_source = agent_source or ""
        self.framework = framework
        self.on_progress = on_progress
        self.on_input_start = on_input_start
        self.on_result = on_result

        # Evaluation primitive (Phase 0)
        self.evaluation_id = evaluation_id or generate_evaluation_id()
        self._scenario_order = 0  # Tracks current scenario number within evaluation

        # Compute code hash
        self.code_hash = hashlib.sha256(self.agent_source.encode()).hexdigest()[:16]

        # Metadata side-channel: populated after each invocation instead of
        # monkey-patching __khaos_last_metadata__ onto the callable.
        self._last_metadata: dict[str, Any] = {}

    def _invoke_agent(self, input_text: str) -> tuple[str, float, str | None]:
        """Invoke agent and return (response, latency_ms, error)."""
        start = time.perf_counter()
        try:
            response = self.agent_invoker(input_text)
            latency_ms = (time.perf_counter() - start) * 1000
            if isinstance(response, tuple) and len(response) == 2 and isinstance(response[0], str) and isinstance(response[1], dict):
                self._last_metadata = response[1]
                return response[0], latency_ms, None
            # Check if the invoker set metadata on itself (backward compat with invokers.py).
            invoker_meta = getattr(self.agent_invoker, "__khaos_last_metadata__", None)
            if isinstance(invoker_meta, dict):
                self._last_metadata = invoker_meta
            else:
                self._last_metadata = {}
            return str(response), latency_ms, None
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            self._last_metadata = {}
            return "", latency_ms, str(e)

    def _run_input(
        self,
        inp: PackInput,
        phase_type: PhaseType,
        run_index: int,
    ) -> RunResult:
        """Run a single input and return result.

        Dispatches to multi-turn invoker for multi-turn inputs if available.
        """
        # Notify callback before invocation (enables fault_schedule lookup)
        if self.on_input_start:
            self.on_input_start(inp.id)

        # Dispatch to multi-turn invoker if this is a multi-turn input
        if inp.is_multi_turn:
            if self.multi_turn_invoker:
                return self.multi_turn_invoker(inp, phase_type.value, run_index)
            else:
                # No multi-turn invoker available - error
                return RunResult(
                    input_id=inp.id,
                    success=False,
                    latency_ms=0.0,
                    response="",
                    error="Multi-turn inputs require a multi_turn_invoker",
                    metadata={
                        "phase": phase_type.value,
                        "run_index": run_index,
                    },
                )

        input_text = inp.render()
        response, latency_ms, error = self._invoke_agent(input_text)

        success = error is None and len(response) > 0
        goal_met = None
        if success and inp.goal:
            goal_met = _check_goal(response, inp.goal)

        extra_metadata: dict[str, Any] = self._last_metadata

        # Capability gating can mark runs as N/A (skipped). Skipped runs should not
        # be treated as failures even if no response was produced.
        if _is_khaos_skipped_run(extra_metadata):
            success = True
            error = None
            goal_met = None

        khaos_checks = extra_metadata.get("khaos_checks") if isinstance(extra_metadata, dict) else None
        checks_met: bool | None = None
        check_errors: list[str] = []
        if isinstance(khaos_checks, dict):
            passed_val = khaos_checks.get("passed")
            if isinstance(passed_val, bool):
                checks_met = passed_val
            errors_val = khaos_checks.get("errors")
            if isinstance(errors_val, list):
                check_errors = [str(e) for e in errors_val if e]

        return RunResult(
            input_id=inp.id,
            success=success,
            latency_ms=latency_ms,
            response=response,
            error=error,
            goal_met=goal_met,
            checks_met=checks_met,
            check_errors=check_errors,
            metadata={
                "phase": phase_type.value,
                "run_index": run_index,
                **(extra_metadata or {}),
            },
        )

    def run_phase(
        self,
        phase: PackPhase,
        inputs: list[PackInput],
    ) -> PhaseResult:
        """Run a single phase with all inputs."""
        start = time.perf_counter()
        all_results: list[RunResult] = []
        total_runs = phase.runs * len(inputs)
        current = 0

        # Signal phase start BEFORE first run (enables phase-aware invokers)
        if self.on_progress:
            self.on_progress(phase.type.value, 0, total_runs)

        for run_idx in range(phase.runs):
            for inp in inputs:
                result = self._run_input(inp, phase.type, run_idx)
                all_results.append(result)
                current += 1

                if self.on_progress:
                    self.on_progress(phase.type.value, current, total_runs)

                # Notify about individual test result
                if self.on_result:
                    # For baseline/resilience: passed = success and goal_met
                    # For security: we track this differently (via security events)
                    passed = (
                        result.success
                        and (result.goal_met is None or result.goal_met)
                        and (result.checks_met is None or result.checks_met)
                    )
                    self.on_result(
                        phase.type.value,
                        inp.id,
                        passed,
                        result.latency_ms,
                        result.error,
                    )

        total_time = (time.perf_counter() - start) * 1000

        return PhaseResult(
            phase_type=phase.type,
            runs=all_results,
            total_time_ms=total_time,
            error_count=sum(1 for r in all_results if not r.success),
        )

    def run_pack(self, pack: Pack) -> EvaluationResult:
        """Run a complete evaluation pack."""
        start = time.perf_counter()
        phase_results: dict[PhaseType, PhaseResult] = {}

        # Run each phase in order
        for phase in pack.phases:
            result = self.run_phase(phase, pack.inputs)
            phase_results[phase.type] = result

        total_time = (time.perf_counter() - start) * 1000

        # Build report
        report = self._build_report(pack, phase_results)

        # Write unified manifest
        manifest = RunManifest(
            run_id=report.run_id,
            execution_mode="pack",
            config_hash=report.config_hash,
            agent_code_hash=self.code_hash,
            pack_name=pack.name,
            pack_version=pack.version,
            artifacts=[],  # Pack mode typically doesn't persist local files
            metadata={"agent_name": self.agent_name, "agent_version": self.agent_version},
        )
        write_manifest(manifest)

        return EvaluationResult(
            pack=pack,
            phases=phase_results,
            report=report,
            total_time_ms=total_time,
        )

    def _build_report(
        self,
        pack: Pack,
        phase_results: dict[PhaseType, PhaseResult],
    ) -> EvaluationReport:
        """Build evaluation report from phase results."""
        # Compute config hash from pack definition for provenance
        import json
        pack_dict = pack.to_dict()
        pack_json = json.dumps(pack_dict, sort_keys=True)
        config_hash = hashlib.sha256(pack_json.encode()).hexdigest()[:16]

        # Increment scenario order for this run
        self._scenario_order += 1

        report = EvaluationReport(
            pack_name=pack.name,
            pack_version=pack.version,
            run_id=generate_run_id("pack"),
            timestamp=datetime.utcnow().isoformat(),
            config_hash=config_hash,
            # Evaluation primitive (Phase 0)
            evaluation_id=self.evaluation_id,
            scenario_order=self._scenario_order,
        )

        # Agent info
        report.agent = AgentInfo(
            name=self.agent_name,
            version=self.agent_version,
            code_hash=self.code_hash,
            framework=self.framework,
        )

        # Baseline metrics
        if PhaseType.BASELINE in phase_results:
            baseline_result = phase_results[PhaseType.BASELINE]
            report.baseline = self._compute_baseline_metrics(baseline_result)

        # Resilience metrics
        if PhaseType.RESILIENCE in phase_results:
            resilience_result = phase_results[PhaseType.RESILIENCE]
            baseline_result = phase_results.get(PhaseType.BASELINE)
            baseline_latency = (
                report.baseline.latency.mean if report.baseline else 0
            )
            resilience_metrics = self._compute_resilience_metrics(
                resilience_result, baseline_latency, pack=pack, baseline_result=baseline_result
            )
            if resilience_metrics.runs > 0:
                report.resilience = resilience_metrics

        # Security metrics
        if PhaseType.SECURITY in phase_results:
            security_result = phase_results[PhaseType.SECURITY]
            report.security = self._compute_security_metrics(security_result)

        # Collect all input results
        for phase_type, phase_result in phase_results.items():
            for result in phase_result.runs:
                # Build turn details for multi-turn results
                turns: list[TurnResultDetail] = []
                if result.is_multi_turn and result.turns:
                    turns = [
                        TurnResultDetail(
                            turn_index=t.turn_index,
                            user_input_preview=t.user_input[:100] if t.user_input else "",
                            response_preview=t.response[:200] if t.response else "",
                            latency_ms=t.latency_ms,
                            tokens_in=t.tokens_in,
                            tokens_out=t.tokens_out,
                            goal_met=t.goal_met,
                            faults_applied=list(t.faults_applied or []),
                            error=t.error,
                        )
                        for t in result.turns
                    ]

                report.input_results.append(
                    InputResult(
                        input_id=result.input_id,
                        phase=phase_type.value,
                        run_index=result.metadata.get("run_index", 0),
                        success=result.success,
                        latency_ms=result.latency_ms,
                        tokens_in=result.tokens_in,
                        tokens_out=result.tokens_out,
                        response_preview=result.response[:200] if result.response else "",
                        goal_met=result.goal_met,
                        checks_met=result.checks_met,
                        check_errors=list(result.check_errors or []),
                        error=result.error,
                        is_multi_turn=result.is_multi_turn,
                        turn_count=result.turn_count,
                        turns=turns,
                    )
                )

        # Compute overall score
        report.overall_score = report.compute_overall_score()

        return report

    def _compute_baseline_metrics(self, result: PhaseResult) -> BaselineMetrics:
        """Compute baseline metrics from phase result."""
        eligible_runs = [r for r in result.runs if not _is_khaos_skipped_run(r.metadata)]
        goals_met = sum(
            1 for r in eligible_runs if r.goal_met is True
        )
        goals_total = sum(
            1 for r in eligible_runs if r.goal_met is not None
        )

        # Compute output consistency if we have multiple runs of the same inputs
        output_consistency = self._compute_output_consistency(eligible_runs)

        return BaselineMetrics(
            runs=len(eligible_runs),
            latency=_compute_latency_metrics(result.latencies),
            tokens=_compute_token_metrics(eligible_runs),
            cost_usd=_estimate_cost(eligible_runs),
            task_completion_rate=result.success_rate,
            error_rate=1 - result.success_rate,
            goals_met=goals_met,
            goals_total=goals_total,
            output_consistency=output_consistency,
        )

    def _compute_output_consistency(
        self, runs: list[RunResult]
    ) -> OutputConsistencyMetrics | None:
        """Compute output consistency metrics from multiple runs of the same inputs.

        Returns None if there aren't enough runs to compare (need 2+ runs per input).
        """
        # Group runs by input_id
        runs_by_input: dict[str, list[RunResult]] = {}
        for run in runs:
            runs_by_input.setdefault(run.input_id, []).append(run)

        # Check if we have multiple runs for any input
        inputs_with_multiple_runs = [
            input_id for input_id, input_runs in runs_by_input.items()
            if len(input_runs) >= 2
        ]

        if not inputs_with_multiple_runs:
            # Not enough runs to compute consistency
            return None

        # Import the consistency evaluator
        from khaos.evaluator.consistency import OutputConsistencyEvaluator, RunOutput

        # Convert our runs to the format the evaluator expects
        # Organize by run_index first, then by input_id
        max_run_index = max(
            (run.metadata.get("run_index", 0) if isinstance(run.metadata, dict) else 0)
            for run in runs
        )

        run_outputs: list[list[RunOutput]] = []
        for run_idx in range(max_run_index + 1):
            run_idx_outputs: list[RunOutput] = []
            for run in runs:
                actual_run_idx = run.metadata.get("run_index", 0) if isinstance(run.metadata, dict) else 0
                if actual_run_idx != run_idx:
                    continue

                # Extract tool calls from check_errors (tool validation errors indicate tool usage)
                tool_calls: list[str] = []
                tool_args: list[dict] = []
                if run.check_errors:
                    for err in run.check_errors:
                        if isinstance(err, dict) and err.get("tool"):
                            tool_calls.append(err["tool"])
                            if err.get("args"):
                                tool_args.append(err["args"])

                run_output = RunOutput(
                    run_index=run_idx,
                    input_id=run.input_id,
                    output_text=run.response or "",
                    output_length=len(run.response or ""),
                    tool_calls=tool_calls,
                    tool_args=tool_args,
                    success=run.success,
                    goal_met=run.goal_met,
                )
                run_idx_outputs.append(run_output)

            if run_idx_outputs:
                run_outputs.append(run_idx_outputs)

        # Need at least 2 runs to compare
        if len(run_outputs) < 2:
            return None

        evaluator = OutputConsistencyEvaluator()
        return evaluator.evaluate(run_outputs)

    def _compute_resilience_metrics(
        self,
        result: PhaseResult,
        baseline_latency: float,
        pack: "Pack" | None = None,
        baseline_result: PhaseResult | None = None,
    ) -> ResilienceMetrics:
        """Compute resilience metrics from phase result."""
        eligible_runs = [r for r in result.runs if not _is_khaos_skipped_run(r.metadata)]
        if not eligible_runs:
            faults_available = 0
            if pack is not None:
                try:
                    from khaos.chaos.scenario import SUPPORTED_FAULT_TYPES

                    faults_available = len(SUPPORTED_FAULT_TYPES)
                except Exception:
                    faults_available = 0
            return ResilienceMetrics(
                score=100.0,
                runs=0,
                degradation_percent=0.0,
                error_rate=0.0,
                recovery_rate=0.0,
                fault_impacts=[],
                fault_coverage=FaultCoverage(
                    faults_used=0,
                    faults_available=faults_available,
                    fault_types_tested=[],
                )
                if pack is not None
                else None,
            )
        mean_latency = statistics.mean(result.latencies) if result.latencies else 0
        degradation = 0.0
        if baseline_latency > 0:
            degradation = ((mean_latency - baseline_latency) / baseline_latency) * 100

        # Score formula (GA semantics):
        # - Primary factor: goal recovery (if goals are defined), otherwise raw success recovery.
        # - Secondary factor: latency degradation penalty (capped at 20 points).
        recovery_rate = result.success_rate
        goals_total_under_faults = sum(1 for r in eligible_runs if r.goal_met is not None)
        goals_met_under_faults = sum(1 for r in eligible_runs if r.goal_met is True)
        goal_recovery_rate = (
            (goals_met_under_faults / goals_total_under_faults)
            if goals_total_under_faults > 0
            else None
        )
        effective_recovery_rate = goal_recovery_rate if goal_recovery_rate is not None else recovery_rate

        base_score = effective_recovery_rate * 100  # 0-100 based on recovery under faults
        latency_penalty = min(max(0, degradation), 20)  # Cap at 20 points
        score = max(0, base_score - latency_penalty)

        # Compute fault coverage and fault impacts
        fault_coverage = None
        fault_impacts = []
        faults_injected: list[FaultInjectedRecord] = []

        if pack:
            from khaos.chaos.scenario import SUPPORTED_FAULT_TYPES
            fault_types: set[str] = set()
            for run in eligible_runs:
                applied = run.metadata.get("applied_faults") if isinstance(run.metadata, dict) else None
                if isinstance(applied, list):
                    fault_types.update(str(f) for f in applied if f)
            fault_coverage = FaultCoverage(
                faults_used=len(fault_types),
                faults_available=len(SUPPORTED_FAULT_TYPES),
                fault_types_tested=sorted(fault_types),
            )

            # Track per-fault impacts
            fault_impacts = self._compute_fault_impacts(
                result, baseline_result, pack, baseline_latency
            )

            # Build faults_injected for dashboard timeline visualization
            faults_injected = self._build_faults_injected(eligible_runs, baseline_result)

        return ResilienceMetrics(
            score=score,
            runs=len(eligible_runs),
            degradation_percent=degradation,
            error_rate=1 - result.success_rate,
            recovery_rate=result.success_rate,
            goals_total_under_faults=goals_total_under_faults,
            goals_met_under_faults=goals_met_under_faults,
            goal_recovery_rate=goal_recovery_rate,
            fault_impacts=fault_impacts,
            fault_coverage=fault_coverage,
            faults_injected=faults_injected,
        )

    def _compute_fault_impacts(
        self,
        resilience_result: PhaseResult,
        baseline_result: PhaseResult | None,
        pack: "Pack",
        baseline_latency: float,
    ) -> list[FaultImpact]:
        """Compute per-fault type impact metrics.

        Compares resilience phase results to baseline for each fault type,
        measuring latency increase, error rate change, and recovery.
        """
        fault_impacts = []

        # Build baseline metrics by input_id
        baseline_by_input: dict[str, list[RunResult]] = {}
        if baseline_result:
            for run in baseline_result.runs:
                baseline_by_input.setdefault(run.input_id, []).append(run)

        # Get fault schedule from pack's resilience phase
        # Group inputs by observed fault type (post-gating).
        fault_type_inputs: dict[str, list[str]] = {}
        for run in resilience_result.runs:
            applied = run.metadata.get("applied_faults") if isinstance(run.metadata, dict) else None
            if not isinstance(applied, list):
                continue
            for fault_type in applied:
                if not fault_type:
                    continue
                fault_type_inputs.setdefault(str(fault_type), []).append(run.input_id)

        # Compute impact for each fault type
        for fault_type, input_ids in fault_type_inputs.items():
            # Get resilience runs for these inputs
            fault_runs = [r for r in resilience_result.runs if r.input_id in input_ids]
            if not fault_runs:
                continue

            # Calculate metrics
            fault_latencies = [r.latency_ms for r in fault_runs if r.success]
            fault_mean_latency = statistics.mean(fault_latencies) if fault_latencies else 0
            fault_success_rate = sum(1 for r in fault_runs if r.success) / len(fault_runs)
            fault_error_rate = 1 - fault_success_rate

            # Compare to baseline
            baseline_runs = []
            for input_id in input_ids:
                baseline_runs.extend(baseline_by_input.get(input_id, []))

            baseline_error_rate = 0.0
            baseline_completion_rate = 1.0
            if baseline_runs:
                baseline_error_rate = 1 - (sum(1 for r in baseline_runs if r.success) / len(baseline_runs))
                baseline_completion_rate = sum(1 for r in baseline_runs if r.success) / len(baseline_runs)

            # Calculate latency increase
            latency_increase = 0.0
            if baseline_latency > 0 and fault_mean_latency > 0:
                latency_increase = ((fault_mean_latency - baseline_latency) / baseline_latency) * 100

            fault_impacts.append(FaultImpact(
                fault_type=fault_type,
                latency_increase_percent=latency_increase,
                error_rate_increase=fault_error_rate - baseline_error_rate,
                task_completion_drop=baseline_completion_rate - fault_success_rate,
                recovered=fault_success_rate > 0.5,  # Recovered if >50% still succeeded
            ))

        return fault_impacts

    def _build_faults_injected(
        self,
        resilience_runs: list[RunResult],
        baseline_result: PhaseResult | None,
    ) -> list[FaultInjectedRecord]:
        """Build faults_injected array for dashboard timeline visualization.

        Creates FaultInjectedRecord entries for each fault applied during resilience runs.
        The dashboard uses this to show inline scenario cards in the trace viewer.

        Args:
            resilience_runs: List of runs from resilience phase
            baseline_result: Optional baseline result for comparison

        Returns:
            List of FaultInjectedRecord entries for the dashboard
        """
        records: list[FaultInjectedRecord] = []
        fault_idx = 0

        # Build baseline lookup for recovery determination
        baseline_by_input: dict[str, list[RunResult]] = {}
        if baseline_result:
            for run in baseline_result.runs:
                baseline_by_input.setdefault(run.input_id, []).append(run)

        for run in resilience_runs:
            # Get applied faults from run metadata
            applied = run.metadata.get("applied_faults") if isinstance(run.metadata, dict) else None
            if not isinstance(applied, list) or not applied:
                continue

            # Determine if the agent recovered under these faults
            # Recovery = run succeeded AND achieved its goal despite faults
            # This matches the CLI's "passed" definition for consistency:
            # passed = success and (goal_met is None or goal_met) and (checks_met is None or checks_met)
            agent_recovered = (
                run.success
                and (run.goal_met is None or run.goal_met)
                and (run.checks_met is None or run.checks_met)
            )

            # Estimate recovery time based on latency increase vs baseline
            recovery_time_ms: float | None = None
            if agent_recovered and baseline_result:
                baseline_runs = baseline_by_input.get(run.input_id, [])
                if baseline_runs:
                    baseline_latency = statistics.mean(r.latency_ms for r in baseline_runs if r.success)
                    if baseline_latency > 0 and run.latency_ms > baseline_latency:
                        # Recovery time is the additional latency beyond baseline
                        recovery_time_ms = run.latency_ms - baseline_latency

            # Use run timestamp if available, otherwise use current time
            timestamp = run.metadata.get("timestamp") if isinstance(run.metadata, dict) else None
            if not timestamp:
                timestamp = datetime.utcnow().isoformat()

            # Create a record for each fault type applied
            for fault_type in applied:
                if not fault_type:
                    continue
                fault_idx += 1
                records.append(FaultInjectedRecord(
                    fault_id=f"fault-{fault_idx}",
                    fault_type=str(fault_type),
                    timestamp=str(timestamp),
                    config={},  # Could extract from metadata if available
                    impact=FaultInjectedImpact(
                        agent_recovered=agent_recovered,
                        recovery_time_ms=recovery_time_ms,
                    ),
                ))

        return records

    def _compute_security_metrics(self, result: PhaseResult) -> SecurityMetrics:
        """Compute security metrics from phase result."""
        # For now, assume all runs in security phase are attack tests
        # In reality, we'd track which attacks succeeded/failed
        eligible_runs = [r for r in result.runs if not _is_khaos_skipped_run(r.metadata)]
        attacks_tested = len(eligible_runs)
        attacks_blocked = sum(1 for r in eligible_runs if r.success)

        score = (attacks_blocked / attacks_tested * 100) if attacks_tested > 0 else 100

        return SecurityMetrics(
            score=score,
            attacks_tested=attacks_tested,
            attacks_blocked=attacks_blocked,
            attacks_passed=attacks_tested - attacks_blocked,
            critical_vulnerabilities=0,
            high_vulnerabilities=0,
            medium_vulnerabilities=0,
            low_vulnerabilities=0,
            vulnerable_categories=[],
            vulnerabilities=[],
        )

def run_pack(
    pack_name: str,
    agent_invoker: AgentInvoker,
    agent_name: str = "agent",
    agent_version: str = "1.0.0",
    on_progress: Callable[[str, int, int], None] | None = None,
) -> EvaluationResult:
    """Run a built-in pack by name.

    Args:
        pack_name: Name of built-in pack (quickstart, full-eval, etc.)
        agent_invoker: Function that takes input text and returns response
        agent_name: Name of agent being tested
        agent_version: Version of agent
        on_progress: Optional callback for progress updates

    Returns:
        EvaluationResult with complete metrics and report
    """
    pack = get_builtin_pack(pack_name)
    runner = PackRunner(
        agent_invoker=agent_invoker,
        agent_name=agent_name,
        agent_version=agent_version,
        on_progress=on_progress,
    )
    return runner.run_pack(pack)
