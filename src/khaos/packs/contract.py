"""Evaluation data contract for cross-agent comparison.

This module defines the standardized output schema that enables
reliable comparison between different agents tested with Khaos.

The contract is versioned and should remain stable within major versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import json


# Contract version - increment on breaking changes
CONTRACT_VERSION = "1.0"


@dataclass
class AgentInfo:
    """Agent identification and metadata."""

    name: str
    version: str
    code_hash: str  # SHA256 of agent source
    framework: str | None = None  # crewai, langgraph, custom, etc.
    entrypoint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "code_hash": self.code_hash,
            "framework": self.framework,
            "entrypoint": self.entrypoint,
            "metadata": self.metadata,
        }


@dataclass
class LatencyMetrics:
    """Latency statistics in milliseconds."""

    p50: float
    p95: float
    p99: float
    min: float
    max: float
    mean: float

    def to_dict(self) -> dict[str, float]:
        return {
            "p50": round(self.p50, 2),
            "p95": round(self.p95, 2),
            "p99": round(self.p99, 2),
            "min": round(self.min, 2),
            "max": round(self.max, 2),
            "mean": round(self.mean, 2),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LatencyMetrics":
        return cls(
            p50=data.get("p50", 0.0),
            p95=data.get("p95", 0.0),
            p99=data.get("p99", 0.0),
            min=data.get("min", 0.0),
            max=data.get("max", 0.0),
            mean=data.get("mean", 0.0),
        )


@dataclass
class TokenMetrics:
    """Token usage statistics."""

    input_total: int
    output_total: int
    input_avg: float
    output_avg: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_total": self.input_total,
            "output_total": self.output_total,
            "input_avg": round(self.input_avg, 1),
            "output_avg": round(self.output_avg, 1),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenMetrics":
        return cls(
            input_total=data.get("input_total", 0),
            output_total=data.get("output_total", 0),
            input_avg=data.get("input_avg", 0.0),
            output_avg=data.get("output_avg", 0.0),
        )


@dataclass
class OutputConsistencyMetrics:
    """Metrics measuring output consistency across baseline runs.

    These metrics capture how consistent/deterministic agent outputs are
    when running the same inputs multiple times. High consistency indicates
    reliable, predictable behavior. Low consistency may indicate:
    - Non-deterministic responses (acceptable for creative tasks)
    - Unstable behavior (concerning for critical tasks)
    - Temperature/sampling variance

    All scores are 0.0-1.0 where 1.0 = perfectly consistent.
    """

    # Core similarity metrics
    content_similarity: float  # Textual overlap (character/word level)
    semantic_similarity: float  # Meaning preservation across runs
    result_consistency: float  # Same outcomes (tool calls, final results)

    # Structural consistency
    length_variance: float  # Coefficient of variation for output length (lower = more consistent)
    length_mean: float  # Average output length in characters
    length_std: float  # Standard deviation of output length

    # Tool/action consistency
    tool_call_consistency: float  # Same tools called in same order
    tool_args_similarity: float  # Similar arguments to tools

    # Aggregate score (weighted combination)
    overall_score: float  # 0-1, weighted aggregate

    # Metadata
    samples_compared: int  # Number of run pairs compared
    divergent_outputs: int  # Count of significantly divergent outputs

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_similarity": round(self.content_similarity, 3),
            "semantic_similarity": round(self.semantic_similarity, 3),
            "result_consistency": round(self.result_consistency, 3),
            "length_variance": round(self.length_variance, 3),
            "length_mean": round(self.length_mean, 1),
            "length_std": round(self.length_std, 1),
            "tool_call_consistency": round(self.tool_call_consistency, 3),
            "tool_args_similarity": round(self.tool_args_similarity, 3),
            "overall_score": round(self.overall_score, 3),
            "samples_compared": self.samples_compared,
            "divergent_outputs": self.divergent_outputs,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OutputConsistencyMetrics":
        return cls(
            content_similarity=data.get("content_similarity", 1.0),
            semantic_similarity=data.get("semantic_similarity", 1.0),
            result_consistency=data.get("result_consistency", 1.0),
            length_variance=data.get("length_variance", 0.0),
            length_mean=data.get("length_mean", 0.0),
            length_std=data.get("length_std", 0.0),
            tool_call_consistency=data.get("tool_call_consistency", 1.0),
            tool_args_similarity=data.get("tool_args_similarity", 1.0),
            overall_score=data.get("overall_score", 1.0),
            samples_compared=data.get("samples_compared", 0),
            divergent_outputs=data.get("divergent_outputs", 0),
        )

    @classmethod
    def perfect(cls) -> "OutputConsistencyMetrics":
        """Return metrics indicating perfect consistency (single run or identical outputs)."""
        return cls(
            content_similarity=1.0,
            semantic_similarity=1.0,
            result_consistency=1.0,
            length_variance=0.0,
            length_mean=0.0,
            length_std=0.0,
            tool_call_consistency=1.0,
            tool_args_similarity=1.0,
            overall_score=1.0,
            samples_compared=0,
            divergent_outputs=0,
        )

    @property
    def status(self) -> str:
        """Return a status label based on overall score."""
        if self.overall_score >= 0.9:
            return "excellent"
        elif self.overall_score >= 0.75:
            return "good"
        elif self.overall_score >= 0.6:
            return "moderate"
        elif self.overall_score >= 0.4:
            return "variable"
        else:
            return "inconsistent"


@dataclass
class BaselineMetrics:
    """Metrics from baseline phase (no faults)."""

    runs: int
    latency: LatencyMetrics
    tokens: TokenMetrics
    cost_usd: float
    task_completion_rate: float  # 0.0-1.0
    error_rate: float  # 0.0-1.0
    goals_met: int = 0  # Number of goals achieved
    goals_total: int = 0  # Total goals tested

    # Output consistency metrics (NEW - agent behavior intelligence)
    output_consistency: OutputConsistencyMetrics | None = None

    # Backwards compatibility aliases
    @property
    def expectations_met(self) -> int:
        return self.goals_met

    @property
    def expectations_total(self) -> int:
        return self.goals_total

    @property
    def goals_rate(self) -> float:
        if self.goals_total == 0:
            return 1.0
        return self.goals_met / self.goals_total

    @property
    def expectations_rate(self) -> float:
        return self.goals_rate

    @property
    def consistency_score(self) -> float:
        """Overall output consistency score (0-1). Higher = more consistent."""
        if self.output_consistency:
            return self.output_consistency.overall_score
        return 1.0  # Default to 1.0 if not measured

    @property
    def consistency_status(self) -> str:
        """Human-readable consistency status."""
        if self.output_consistency:
            return self.output_consistency.status
        return "unknown"

    def to_dict(self) -> dict[str, Any]:
        result = {
            "runs": self.runs,
            "latency": self.latency.to_dict(),
            "tokens": self.tokens.to_dict(),
            "cost_usd": round(self.cost_usd, 6),
            "task_completion_rate": round(self.task_completion_rate, 3),
            "error_rate": round(self.error_rate, 3),
            "goals_met": self.goals_met,
            "goals_total": self.goals_total,
            "goals_rate": round(self.goals_rate, 3),
        }
        if self.output_consistency:
            result["output_consistency"] = self.output_consistency.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaselineMetrics":
        output_consistency = None
        if data.get("output_consistency"):
            output_consistency = OutputConsistencyMetrics.from_dict(data["output_consistency"])

        return cls(
            runs=data.get("runs", 0),
            latency=LatencyMetrics.from_dict(data.get("latency", {})),
            tokens=TokenMetrics.from_dict(data.get("tokens", {})),
            cost_usd=data.get("cost_usd", 0.0),
            task_completion_rate=data.get("task_completion_rate", 0.0),
            error_rate=data.get("error_rate", 0.0),
            goals_met=data.get("goals_met", 0),
            goals_total=data.get("goals_total", 0),
            output_consistency=output_consistency,
        )


@dataclass
class FaultInjectedImpact:
    """Impact tracking for a single fault injection (for dashboard visualization)."""

    agent_recovered: bool = False
    recovery_time_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"agent_recovered": self.agent_recovered}
        if self.recovery_time_ms is not None:
            result["recovery_time_ms"] = round(self.recovery_time_ms, 1)
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FaultInjectedImpact":
        return cls(
            agent_recovered=data.get("agent_recovered", False),
            recovery_time_ms=data.get("recovery_time_ms"),
        )


@dataclass
class FaultInjectedRecord:
    """Record of a single fault injection event (for dashboard timeline visualization).

    This matches the format expected by the dashboard's transformFaultEvents():
    - fault_id: unique identifier
    - fault_type: the fault type string (e.g. "http_latency", "llm_timeout")
    - timestamp: ISO timestamp when fault was injected
    - config: optional fault configuration
    - impact: whether agent recovered and recovery time
    """

    fault_id: str
    fault_type: str
    timestamp: str
    config: dict[str, Any] = field(default_factory=dict)
    impact: FaultInjectedImpact = field(default_factory=FaultInjectedImpact)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fault_id": self.fault_id,
            "fault_type": self.fault_type,
            "timestamp": self.timestamp,
            "config": self.config,
            "impact": self.impact.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FaultInjectedRecord":
        impact_data = data.get("impact", {})
        return cls(
            fault_id=data.get("fault_id", ""),
            fault_type=data.get("fault_type", ""),
            timestamp=data.get("timestamp", ""),
            config=data.get("config", {}),
            impact=FaultInjectedImpact.from_dict(impact_data) if isinstance(impact_data, dict) else FaultInjectedImpact(),
        )


@dataclass
class FaultImpact:
    """Impact of a specific fault type."""

    fault_type: str
    latency_increase_percent: float  # vs baseline
    error_rate_increase: float  # absolute increase
    task_completion_drop: float  # absolute drop
    recovered: bool  # Did agent eventually succeed?

    def to_dict(self) -> dict[str, Any]:
        return {
            "fault_type": self.fault_type,
            "latency_increase_percent": round(self.latency_increase_percent, 1),
            "error_rate_increase": round(self.error_rate_increase, 3),
            "task_completion_drop": round(self.task_completion_drop, 3),
            "recovered": self.recovered,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FaultImpact":
        return cls(
            fault_type=data.get("fault_type", ""),
            latency_increase_percent=data.get("latency_increase_percent", 0.0),
            error_rate_increase=data.get("error_rate_increase", 0.0),
            task_completion_drop=data.get("task_completion_drop", 0.0),
            recovered=data.get("recovered", False),
        )


@dataclass
class FaultCoverage:
    """Fault coverage statistics."""

    faults_used: int  # Number of unique fault types tested
    faults_available: int  # Total fault types in the platform
    fault_types_tested: list[str] = field(default_factory=list)

    @property
    def coverage_percent(self) -> float:
        if self.faults_available == 0:
            return 100.0
        return (self.faults_used / self.faults_available) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "faults_used": self.faults_used,
            "faults_available": self.faults_available,
            "coverage_percent": round(self.coverage_percent, 1),
            "fault_types_tested": self.fault_types_tested,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FaultCoverage":
        return cls(
            faults_used=data.get("faults_used", 0),
            faults_available=data.get("faults_available", 0),
            fault_types_tested=data.get("fault_types_tested", []),
        )


@dataclass
class ResilienceMetrics:
    """Metrics from resilience phase (with faults)."""

    score: float  # 0-100, computed from degradation
    runs: int
    degradation_percent: float  # Overall performance drop vs baseline
    error_rate: float
    recovery_rate: float  # % of faulted runs that still completed
    # Goal-aware scoring (GA): when goals exist, track whether the goal is still achieved under strain.
    # These fields are optional/backwards compatible (older reports won't include them).
    goals_total_under_faults: int = 0
    goals_met_under_faults: int = 0
    goal_recovery_rate: float | None = None  # goals_met_under_faults / goals_total_under_faults
    fault_impacts: list[FaultImpact] = field(default_factory=list)
    fault_coverage: FaultCoverage | None = None  # Fault coverage stats
    # Timeline visualization: detailed fault injection records for dashboard
    faults_injected: list[FaultInjectedRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "score": round(self.score, 1),
            "runs": self.runs,
            "degradation_percent": round(self.degradation_percent, 1),
            "error_rate": round(self.error_rate, 3),
            "recovery_rate": round(self.recovery_rate, 3),
            "goals_total_under_faults": self.goals_total_under_faults,
            "goals_met_under_faults": self.goals_met_under_faults,
            "goal_recovery_rate": round(self.goal_recovery_rate, 3)
            if self.goal_recovery_rate is not None
            else None,
            "fault_impacts": [f.to_dict() for f in self.fault_impacts],
        }
        if self.fault_coverage:
            result["fault_coverage"] = self.fault_coverage.to_dict()
        if self.faults_injected:
            result["faults_injected"] = [f.to_dict() for f in self.faults_injected]
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResilienceMetrics":
        fault_coverage = None
        if data.get("fault_coverage"):
            fault_coverage = FaultCoverage.from_dict(data["fault_coverage"])
        faults_injected = [
            FaultInjectedRecord.from_dict(f) for f in data.get("faults_injected", [])
        ]
        return cls(
            score=data.get("score", 0.0),
            runs=data.get("runs", 0),
            degradation_percent=data.get("degradation_percent", 0.0),
            error_rate=data.get("error_rate", 0.0),
            recovery_rate=data.get("recovery_rate", 0.0),
            goals_total_under_faults=data.get("goals_total_under_faults", 0),
            goals_met_under_faults=data.get("goals_met_under_faults", 0),
            goal_recovery_rate=data.get("goal_recovery_rate", None),
            fault_impacts=[FaultImpact.from_dict(f) for f in data.get("fault_impacts", [])],
            fault_coverage=fault_coverage,
            faults_injected=faults_injected,
        )


@dataclass
class VulnerabilityDetail:
    """Details about a security vulnerability."""

    attack_id: str
    attack_type: str
    severity: str  # critical, high, medium, low
    description: str

    def to_dict(self) -> dict[str, str]:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilityDetail":
        return cls(
            attack_id=data.get("attack_id", ""),
            attack_type=data.get("attack_type", ""),
            severity=data.get("severity", "low"),
            description=data.get("description", ""),
        )


@dataclass
class SecurityAttackResultDetail:
    """Per-attack security outcome (for CLI + CI reporting)."""

    attack_id: str
    attack_name: str
    attack_type: str
    severity: str = "medium"
    injection_vector: str = "user_input"
    is_custom: bool = False
    classification: str = "inconclusive"  # blocked/inconclusive/compromised

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "injection_vector": self.injection_vector,
            "is_custom": self.is_custom,
            "classification": self.classification,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityAttackResultDetail":
        return cls(
            attack_id=str(data.get("attack_id", "") or ""),
            attack_name=str(data.get("attack_name", "") or ""),
            attack_type=str(data.get("attack_type", "") or ""),
            severity=str(data.get("severity", "medium") or "medium"),
            injection_vector=str(data.get("injection_vector", "user_input") or "user_input"),
            is_custom=bool(data.get("is_custom", False)),
            classification=str(data.get("classification", "inconclusive") or "inconclusive"),
        )


@dataclass
class SecurityMetrics:
    """Metrics from security phase (attack testing)."""

    score: float  # 0-100
    attacks_tested: int
    attacks_blocked: int
    attacks_passed: int  # Vulnerabilities found
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    attacks_inconclusive: int = 0
    # Previous/alternate score, if available (type-weighted). Optional for backwards compatibility.
    severity_score: float | None = None
    # Impact breakdown (GA semantics)
    dangerous_actions: int = 0
    data_exposures: int = 0
    policy_slips: int = 0
    vulnerable_categories: list[str] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityDetail] = field(default_factory=list)
    attack_results: list[SecurityAttackResultDetail] = field(default_factory=list)

    @property
    def block_rate(self) -> float:
        if self.attacks_tested == 0:
            return 1.0
        return self.attacks_blocked / self.attacks_tested

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "score": round(self.score, 1),
            "severity_score": round(self.severity_score, 1) if isinstance(self.severity_score, (int, float)) else None,
            "attacks_tested": self.attacks_tested,
            "attacks_blocked": self.attacks_blocked,
            "attacks_passed": self.attacks_passed,
            "attacks_inconclusive": self.attacks_inconclusive,
            "block_rate": round(self.block_rate, 3),
            "critical_vulnerabilities": self.critical_vulnerabilities,
            "high_vulnerabilities": self.high_vulnerabilities,
            "medium_vulnerabilities": self.medium_vulnerabilities,
            "low_vulnerabilities": self.low_vulnerabilities,
            "dangerous_actions": self.dangerous_actions,
            "data_exposures": self.data_exposures,
            "policy_slips": self.policy_slips,
            "vulnerable_categories": self.vulnerable_categories,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "attack_results": [a.to_dict() for a in self.attack_results],
        }
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityMetrics":
        return cls(
            score=data.get("score", 0.0),
            severity_score=data.get("severity_score"),
            attacks_tested=data.get("attacks_tested", 0),
            attacks_blocked=data.get("attacks_blocked", 0),
            attacks_passed=data.get("attacks_passed", 0),
            attacks_inconclusive=data.get("attacks_inconclusive", 0),
            critical_vulnerabilities=data.get("critical_vulnerabilities", 0),
            high_vulnerabilities=data.get("high_vulnerabilities", 0),
            medium_vulnerabilities=data.get("medium_vulnerabilities", 0),
            low_vulnerabilities=data.get("low_vulnerabilities", 0),
            dangerous_actions=data.get("dangerous_actions", 0) or 0,
            data_exposures=data.get("data_exposures", 0) or 0,
            policy_slips=data.get("policy_slips", 0) or 0,
            vulnerable_categories=data.get("vulnerable_categories", []),
            vulnerabilities=[VulnerabilityDetail.from_dict(v) for v in data.get("vulnerabilities", [])],
            attack_results=[
                SecurityAttackResultDetail.from_dict(a)
                for a in data.get("attack_results", [])
                if isinstance(a, dict)
            ],
        )


@dataclass
class TurnResultDetail:
    """Result for a single turn in a multi-turn conversation.

    Used to track per-turn metrics within a multi-turn input.
    """

    turn_index: int
    user_input_preview: str  # First 100 chars of user input
    response_preview: str  # First 200 chars of response
    latency_ms: float
    tokens_in: int = 0
    tokens_out: int = 0
    goal_met: bool | None = None  # Per-turn goal result
    faults_applied: list[str] = field(default_factory=list)  # Fault types applied this turn
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "turn_index": self.turn_index,
            "user_input_preview": self.user_input_preview,
            "response_preview": self.response_preview,
            "latency_ms": round(self.latency_ms, 2),
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
        }
        if self.goal_met is not None:
            result["goal_met"] = self.goal_met
        if self.faults_applied:
            result["faults_applied"] = list(self.faults_applied)
        if self.error:
            result["error"] = self.error
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TurnResultDetail":
        return cls(
            turn_index=data.get("turn_index", 0),
            user_input_preview=data.get("user_input_preview", ""),
            response_preview=data.get("response_preview", ""),
            latency_ms=data.get("latency_ms", 0.0),
            tokens_in=data.get("tokens_in", 0),
            tokens_out=data.get("tokens_out", 0),
            goal_met=data.get("goal_met"),
            faults_applied=list(data.get("faults_applied", []) or []),
            error=data.get("error"),
        )


@dataclass
class InputResult:
    """Result for a single input prompt.

    Supports both single-turn and multi-turn inputs. For multi-turn inputs,
    the `turns` field contains per-turn results.
    """

    input_id: str
    phase: str
    run_index: int
    success: bool
    latency_ms: float
    tokens_in: int
    tokens_out: int
    response_preview: str  # First 200 chars (final response for multi-turn)
    goal_met: bool | None = None  # Did the agent achieve the goal?
    checks_met: bool | None = None  # Additional Khaos checks (dependency usage, etc.)
    check_errors: list[str] = field(default_factory=list)
    error: str | None = None

    # Multi-turn fields (NEW)
    is_multi_turn: bool = False  # True if this was a multi-turn conversation
    turn_count: int = 1  # Number of turns in the conversation
    turns: list[TurnResultDetail] = field(default_factory=list)  # Per-turn results

    # Backwards compatibility alias
    @property
    def expectation_met(self) -> bool | None:
        return self.goal_met

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "input_id": self.input_id,
            "phase": self.phase,
            "run_index": self.run_index,
            "success": self.success,
            "latency_ms": round(self.latency_ms, 2),
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "response_preview": self.response_preview,
        }
        if self.goal_met is not None:
            result["goal_met"] = self.goal_met
        if self.checks_met is not None:
            result["checks_met"] = self.checks_met
        if self.check_errors:
            result["check_errors"] = list(self.check_errors)
        if self.error:
            result["error"] = self.error

        # Multi-turn fields (only include if multi-turn)
        if self.is_multi_turn:
            result["is_multi_turn"] = True
            result["turn_count"] = self.turn_count
            result["turns"] = [t.to_dict() for t in self.turns]

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InputResult":
        turns = []
        if data.get("turns"):
            turns = [TurnResultDetail.from_dict(t) for t in data["turns"]]

        return cls(
            input_id=data.get("input_id", ""),
            phase=data.get("phase", ""),
            run_index=data.get("run_index", 0),
            success=data.get("success", False),
            latency_ms=data.get("latency_ms", 0.0),
            tokens_in=data.get("tokens_in", 0),
            tokens_out=data.get("tokens_out", 0),
            response_preview=data.get("response_preview", ""),
            goal_met=data.get("goal_met"),
            checks_met=data.get("checks_met"),
            check_errors=list(data.get("check_errors", []) or []),
            error=data.get("error"),
            is_multi_turn=data.get("is_multi_turn", False),
            turn_count=data.get("turn_count", 1),
            turns=turns,
        )


@dataclass
class EvaluationReport:
    """Complete evaluation report - the data contract."""

    # Metadata
    contract_version: str = CONTRACT_VERSION
    pack_name: str = ""
    pack_version: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    run_id: str = ""

    # Agent info
    agent: AgentInfo | None = None

    # Phase metrics
    baseline: BaselineMetrics | None = None
    resilience: ResilienceMetrics | None = None
    security: SecurityMetrics | None = None

    # Detailed results (optional, for debugging)
    input_results: list[InputResult] = field(default_factory=list)

    # Summary scores
    overall_score: float = 0.0

    # Capability detection and applicability
    capabilities: dict[str, Any] = field(default_factory=dict)
    skipped: dict[str, Any] = field(default_factory=dict)

    # Reproducibility and provenance
    seed: int | None = None  # Random seed for reproducibility
    config_hash: str | None = None  # SHA256 hash of pack configuration

    # Evaluation primitive (Phase 0) - groups pack scenario runs
    evaluation_id: str | None = None
    scenario_order: int | None = None

    def compute_overall_score(self) -> float:
        """Compute weighted overall score from phase scores."""
        scores = []
        weights = []

        if self.baseline:
            # Baseline score based on completion and expectations
            baseline_score = (
                self.baseline.task_completion_rate * 50 +
                self.baseline.expectations_rate * 50
            )
            scores.append(baseline_score)
            weights.append(0.3)

        if self.resilience and getattr(self.resilience, "runs", 0) > 0:
            scores.append(self.resilience.score)
            weights.append(0.3)

        if self.security and getattr(self.security, "attacks_tested", 0) > 0:
            scores.append(self.security.score)
            weights.append(0.4)

        if not scores:
            return 0.0

        # Weighted average
        total_weight = sum(weights)
        return sum(s * w for s, w in zip(scores, weights)) / total_weight

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        self.overall_score = self.compute_overall_score()

        result = {
            "contract_version": self.contract_version,
            "pack_name": self.pack_name,
            "pack_version": self.pack_version,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "agent": self.agent.to_dict() if self.agent else None,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "resilience": self.resilience.to_dict() if self.resilience else None,
            "security": self.security.to_dict() if self.security else None,
            "overall_score": round(self.overall_score, 1),
            "input_results": [r.to_dict() for r in self.input_results],
            "capabilities": self.capabilities,
            "skipped": self.skipped,
        }
        # Include reproducibility fields if set
        if self.seed is not None:
            result["seed"] = self.seed
        if self.config_hash is not None:
            result["config_hash"] = self.config_hash
        # Include evaluation primitive fields if set
        if self.evaluation_id is not None:
            result["evaluation_id"] = self.evaluation_id
        if self.scenario_order is not None:
            result["scenario_order"] = self.scenario_order
        return result

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvaluationReport":
        """Deserialize from dictionary."""
        report = cls(
            contract_version=data.get("contract_version", CONTRACT_VERSION),
            pack_name=data.get("pack_name", ""),
            pack_version=data.get("pack_version", ""),
            timestamp=data.get("timestamp", ""),
            run_id=data.get("run_id", ""),
            overall_score=data.get("overall_score", 0.0),
            capabilities=data.get("capabilities", {}) if isinstance(data.get("capabilities"), dict) else {},
            skipped=data.get("skipped", {}) if isinstance(data.get("skipped"), dict) else {},
            seed=data.get("seed"),
            config_hash=data.get("config_hash"),
            evaluation_id=data.get("evaluation_id"),
            scenario_order=data.get("scenario_order"),
        )

        if data.get("agent"):
            agent_data = data["agent"]
            report.agent = AgentInfo(
                name=agent_data["name"],
                version=agent_data["version"],
                code_hash=agent_data["code_hash"],
                framework=agent_data.get("framework"),
                entrypoint=agent_data.get("entrypoint"),
                metadata=agent_data.get("metadata", {}),
            )

        # Parse phase metrics
        if data.get("baseline"):
            report.baseline = BaselineMetrics.from_dict(data["baseline"])

        if data.get("resilience"):
            report.resilience = ResilienceMetrics.from_dict(data["resilience"])

        if data.get("security"):
            report.security = SecurityMetrics.from_dict(data["security"])

        # Parse input results
        if data.get("input_results"):
            report.input_results = [
                InputResult.from_dict(r) for r in data["input_results"]
            ]

        return report
