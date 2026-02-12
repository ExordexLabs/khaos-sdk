"""Baseline comparison and regression detection for CI/CD.

Enables comparing current evaluation runs against stored baselines
to detect regressions in security, resilience, or functionality.

Usage:
    from khaos.ci.baseline import BaselineManager

    manager = BaselineManager()
    manager.save_baseline("abc123", name="main")

    result = manager.compare_to_baseline(new_report, baseline_name="main")
    if result.has_regression:
        print(f"Regression detected: {result.summary}")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from khaos.packs.contract import EvaluationReport


def _get_state_dir() -> Path:
    """Get the Khaos state directory."""
    state_dir = Path.home() / ".khaos"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


@dataclass
class BehaviorDivergenceResult:
    """Detailed behavioral divergence metrics for CI/CD.

    These metrics help identify when agent behavior has changed
    significantly between runs, even if scores remain similar.
    """

    # Overall assessment
    has_behavioral_regression: bool = False

    # Detailed metrics (0-1, higher is better/more similar)
    content_similarity: float = 1.0
    semantic_similarity: float = 1.0
    result_consistency: float = 1.0
    tool_call_consistency: float = 1.0
    overall_consistency: float = 1.0

    # Divergence counts
    divergent_outputs: int = 0
    total_comparisons: int = 0

    # Length analysis
    length_variance: float = 0.0  # Coefficient of variation

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_behavioral_regression": self.has_behavioral_regression,
            "content_similarity": round(self.content_similarity, 3),
            "semantic_similarity": round(self.semantic_similarity, 3),
            "result_consistency": round(self.result_consistency, 3),
            "tool_call_consistency": round(self.tool_call_consistency, 3),
            "overall_consistency": round(self.overall_consistency, 3),
            "divergent_outputs": self.divergent_outputs,
            "total_comparisons": self.total_comparisons,
            "length_variance": round(self.length_variance, 3),
        }


@dataclass
class RegressionResult:
    """Result of baseline comparison.

    Captures what regressed and by how much.
    """

    has_regression: bool
    baseline_run_id: str
    candidate_run_id: str

    # Specific regression flags
    security_regressed: bool = False
    resilience_regressed: bool = False
    behavior_regressed: bool = False  # NEW: behavioral divergence flag

    # New issues
    new_vulnerabilities: list[str] = field(default_factory=list)

    # Functional comparison
    functional_divergence: float = 1.0  # 0-1, higher is better

    # Score deltas
    security_delta: float = 0.0
    resilience_delta: float = 0.0

    # NEW: Detailed behavioral divergence
    behavior: BehaviorDivergenceResult | None = None

    # Human-readable summary
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "has_regression": self.has_regression,
            "baseline_run_id": self.baseline_run_id,
            "candidate_run_id": self.candidate_run_id,
            "security_regressed": self.security_regressed,
            "resilience_regressed": self.resilience_regressed,
            "behavior_regressed": self.behavior_regressed,
            "new_vulnerabilities": self.new_vulnerabilities,
            "functional_divergence": self.functional_divergence,
            "security_delta": self.security_delta,
            "resilience_delta": self.resilience_delta,
            "summary": self.summary,
        }
        if self.behavior:
            result["behavior"] = self.behavior.to_dict()
        return result


@dataclass
class BaselineInfo:
    """Stored baseline information."""

    run_id: str
    name: str
    timestamp: str
    pack_name: str
    pack_version: str
    overall_score: float
    security_score: float | None = None
    resilience_score: float | None = None
    report_path: Path | None = None
    config_hash: str | None = None  # SHA256 hash of pack configuration

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "run_id": self.run_id,
            "name": self.name,
            "timestamp": self.timestamp,
            "pack_name": self.pack_name,
            "pack_version": self.pack_version,
            "overall_score": self.overall_score,
            "security_score": self.security_score,
            "resilience_score": self.resilience_score,
            "report_path": str(self.report_path) if self.report_path else None,
        }
        if self.config_hash is not None:
            result["config_hash"] = self.config_hash
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BaselineInfo":
        """Create from dictionary."""
        return cls(
            run_id=data["run_id"],
            name=data["name"],
            timestamp=data["timestamp"],
            pack_name=data["pack_name"],
            pack_version=data["pack_version"],
            overall_score=data["overall_score"],
            security_score=data.get("security_score"),
            resilience_score=data.get("resilience_score"),
            report_path=Path(data["report_path"]) if data.get("report_path") else None,
            config_hash=data.get("config_hash"),
        )


class BaselineManager:
    """Manage baseline runs for regression detection.

    Baselines are stored in ~/.khaos/baselines/ as JSON files.

    Usage:
        manager = BaselineManager()

        # Save current run as baseline
        manager.save_baseline(run_id="abc123", name="main", report=report)

        # Compare against baseline
        result = manager.compare_to_baseline(new_report, baseline_name="main")

        # List all baselines
        baselines = manager.list_baselines()
    """

    def __init__(self, state_dir: Path | None = None):
        self.state_dir = state_dir or _get_state_dir()
        self.baselines_dir = self.state_dir / "baselines"
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

    def save_baseline(
        self,
        run_id: str,
        name: str = "default",
        report: EvaluationReport | None = None,
    ) -> Path:
        """Save a run as a named baseline.

        Args:
            run_id: The run ID to save as baseline
            name: Name for this baseline (e.g., "main", "release-1.0")
            report: Optional EvaluationReport to store with baseline

        Returns:
            Path to the saved baseline file
        """
        baseline_path = self.baselines_dir / f"{name}.json"
        report_path = None

        # Save full report if provided
        if report:
            report_path = self.baselines_dir / f"{name}_report.json"
            report_path.write_text(json.dumps(report.to_dict(), indent=2))

        info = BaselineInfo(
            run_id=run_id,
            name=name,
            timestamp=datetime.utcnow().isoformat() + "Z",
            pack_name=report.pack_name if report else "unknown",
            pack_version=report.pack_version if report else "unknown",
            overall_score=report.overall_score if report else 0.0,
            security_score=report.security.score if report and report.security else None,
            resilience_score=report.resilience.score if report and report.resilience else None,
            report_path=report_path,
            config_hash=report.config_hash if report else None,
        )

        baseline_path.write_text(json.dumps(info.to_dict(), indent=2))
        return baseline_path

    def get_baseline(self, name: str = "default") -> BaselineInfo | None:
        """Get baseline info by name.

        Args:
            name: Baseline name

        Returns:
            BaselineInfo if found, None otherwise
        """
        baseline_path = self.baselines_dir / f"{name}.json"
        if not baseline_path.exists():
            return None

        data = json.loads(baseline_path.read_text())
        return BaselineInfo.from_dict(data)

    def get_baseline_report(self, name: str = "default") -> EvaluationReport | None:
        """Load the full report for a baseline.

        Args:
            name: Baseline name

        Returns:
            EvaluationReport if found, None otherwise
        """
        info = self.get_baseline(name)
        if not info or not info.report_path:
            return None

        report_path = Path(info.report_path)
        if not report_path.exists():
            return None

        data = json.loads(report_path.read_text())
        return EvaluationReport.from_dict(data)

    def list_baselines(self) -> list[BaselineInfo]:
        """List all saved baselines.

        Returns:
            List of BaselineInfo objects
        """
        baselines = []
        for path in self.baselines_dir.glob("*.json"):
            if path.name.endswith("_report.json"):
                continue  # Skip report files
            try:
                data = json.loads(path.read_text())
                baselines.append(BaselineInfo.from_dict(data))
            except (json.JSONDecodeError, KeyError):
                continue
        return sorted(baselines, key=lambda b: b.timestamp, reverse=True)

    def delete_baseline(self, name: str) -> bool:
        """Delete a baseline by name.

        Args:
            name: Baseline name

        Returns:
            True if deleted, False if not found
        """
        baseline_path = self.baselines_dir / f"{name}.json"
        report_path = self.baselines_dir / f"{name}_report.json"

        deleted = False
        if baseline_path.exists():
            baseline_path.unlink()
            deleted = True
        if report_path.exists():
            report_path.unlink()

        return deleted

    def compare_to_baseline(
        self,
        candidate_report: EvaluationReport,
        baseline_name: str = "default",
        threshold_config: dict[str, Any] | None = None,
    ) -> RegressionResult:
        """Compare candidate run against baseline.

        Args:
            candidate_report: The new evaluation report to compare
            baseline_name: Name of baseline to compare against
            threshold_config: Optional thresholds for regression detection.
                Supported thresholds:
                - security_delta_min: Minimum allowed security score delta (default: 0)
                - resilience_delta_min: Minimum allowed resilience score delta (default: -5)
                - functional_similarity_min: Minimum functional similarity (default: 0.8)
                - behavior_consistency_min: Minimum behavior consistency score (default: 0.7)
                - content_similarity_min: Minimum content similarity (default: 0.6)
                - result_consistency_min: Minimum result consistency (default: 0.8)
                - max_divergent_outputs: Maximum allowed divergent outputs (default: 5)

        Returns:
            RegressionResult with comparison details including behavioral analysis
        """
        baseline_info = self.get_baseline(baseline_name)
        if not baseline_info:
            return RegressionResult(
                has_regression=False,
                baseline_run_id="",
                candidate_run_id=candidate_report.run_id,
                summary=f"No baseline '{baseline_name}' found for comparison",
            )

        baseline_report = self.get_baseline_report(baseline_name)

        # Use thresholds or defaults (with new behavioral thresholds)
        thresholds = {
            "security_delta_min": 0,  # No security regression allowed
            "resilience_delta_min": -5,  # Allow 5 point resilience drop
            "functional_similarity_min": 0.8,
            # NEW: Behavioral consistency thresholds
            "behavior_consistency_min": 0.7,  # Overall consistency threshold
            "content_similarity_min": 0.6,  # Content must be 60% similar
            "result_consistency_min": 0.8,  # Results must be 80% consistent
            "max_divergent_outputs": 5,  # Max divergent outputs before flagging
        }
        if threshold_config:
            thresholds.update(threshold_config)

        # Calculate score deltas
        security_delta = 0.0
        resilience_delta = 0.0

        if candidate_report.security and baseline_info.security_score is not None:
            security_delta = (
                candidate_report.security.score - baseline_info.security_score
            )

        if candidate_report.resilience and baseline_info.resilience_score is not None:
            resilience_delta = (
                candidate_report.resilience.score - baseline_info.resilience_score
            )

        # Check for score regressions
        security_regressed = security_delta < thresholds["security_delta_min"]
        resilience_regressed = resilience_delta < thresholds["resilience_delta_min"]

        # Find new vulnerabilities
        new_vulnerabilities = self._find_new_vulnerabilities(
            candidate_report, baseline_report
        )

        # Calculate functional divergence
        functional_divergence = 1.0
        if baseline_report:
            functional_divergence = self._calculate_functional_similarity(
                candidate_report, baseline_report
            )

        # NEW: Calculate behavioral divergence
        behavior_result = self._calculate_behavioral_divergence(
            candidate_report, baseline_report, thresholds
        )
        behavior_regressed = behavior_result.has_behavioral_regression

        # Determine if regression occurred (including behavioral)
        has_regression = (
            security_regressed
            or resilience_regressed
            or behavior_regressed
            or len(new_vulnerabilities) > 0
            or functional_divergence < thresholds["functional_similarity_min"]
        )

        # Build summary (enhanced with behavioral info)
        summary = self._build_regression_summary(
            security_regressed,
            resilience_regressed,
            new_vulnerabilities,
            functional_divergence,
            security_delta,
            resilience_delta,
            behavior_result,
        )

        return RegressionResult(
            has_regression=has_regression,
            baseline_run_id=baseline_info.run_id,
            candidate_run_id=candidate_report.run_id,
            security_regressed=security_regressed,
            resilience_regressed=resilience_regressed,
            behavior_regressed=behavior_regressed,
            new_vulnerabilities=new_vulnerabilities,
            functional_divergence=functional_divergence,
            security_delta=security_delta,
            resilience_delta=resilience_delta,
            behavior=behavior_result,
            summary=summary,
        )

    def _find_new_vulnerabilities(
        self,
        candidate: EvaluationReport,
        baseline: EvaluationReport | None,
    ) -> list[str]:
        """Find vulnerabilities in candidate that weren't in baseline."""
        if not candidate.security or not candidate.security.vulnerabilities:
            return []

        if not baseline or not baseline.security or not baseline.security.vulnerabilities:
            # All vulnerabilities are "new" if no baseline
            return [v.attack_type for v in candidate.security.vulnerabilities]

        baseline_types = {v.attack_type for v in baseline.security.vulnerabilities}
        new_vulns = []

        for vuln in candidate.security.vulnerabilities:
            if vuln.attack_type not in baseline_types:
                new_vulns.append(vuln.attack_type)

        return new_vulns

    def _calculate_functional_similarity(
        self,
        candidate: EvaluationReport,
        baseline: EvaluationReport,
    ) -> float:
        """Calculate functional similarity between runs.

        Returns a value between 0 and 1, where 1 means identical behavior.
        """
        if not candidate.baseline or not baseline.baseline:
            return 1.0

        # Compare task completion rates
        candidate_rate = candidate.baseline.task_completion_rate
        baseline_rate = baseline.baseline.task_completion_rate

        if baseline_rate == 0:
            return 1.0 if candidate_rate == 0 else 0.0

        # Similarity as ratio of completion rates (capped at 1.0)
        ratio = candidate_rate / baseline_rate
        return min(ratio, 1.0)

    def _calculate_behavioral_divergence(
        self,
        candidate: EvaluationReport,
        baseline: EvaluationReport | None,
        thresholds: dict[str, Any],
    ) -> BehaviorDivergenceResult:
        """Calculate behavioral divergence between candidate and baseline.

        This analyzes output consistency metrics to detect behavioral changes.
        """
        if not baseline:
            return BehaviorDivergenceResult()

        # Extract output consistency from candidate's baseline metrics
        candidate_consistency = None
        if candidate.baseline and candidate.baseline.output_consistency:
            candidate_consistency = candidate.baseline.output_consistency

        # Extract output consistency from stored baseline
        baseline_consistency = None
        if baseline.baseline and baseline.baseline.output_consistency:
            baseline_consistency = baseline.baseline.output_consistency

        # If neither has consistency metrics, return default (no regression)
        if not candidate_consistency and not baseline_consistency:
            return BehaviorDivergenceResult()

        # Use candidate's consistency metrics as the primary source
        if candidate_consistency:
            content_sim = candidate_consistency.content_similarity
            semantic_sim = candidate_consistency.semantic_similarity
            result_consistency = candidate_consistency.result_consistency
            tool_consistency = candidate_consistency.tool_call_consistency
            overall = candidate_consistency.overall_score
            divergent = candidate_consistency.divergent_outputs
            total = candidate_consistency.samples_compared
            length_var = candidate_consistency.length_variance
        else:
            # Fallback to defaults if only baseline has metrics
            content_sim = 1.0
            semantic_sim = 1.0
            result_consistency = 1.0
            tool_consistency = 1.0
            overall = 1.0
            divergent = 0
            total = 0
            length_var = 0.0

        # Determine if behavioral regression occurred based on thresholds
        has_regression = (
            overall < thresholds.get("behavior_consistency_min", 0.7)
            or content_sim < thresholds.get("content_similarity_min", 0.6)
            or result_consistency < thresholds.get("result_consistency_min", 0.8)
            or divergent > thresholds.get("max_divergent_outputs", 5)
        )

        return BehaviorDivergenceResult(
            has_behavioral_regression=has_regression,
            content_similarity=content_sim,
            semantic_similarity=semantic_sim,
            result_consistency=result_consistency,
            tool_call_consistency=tool_consistency,
            overall_consistency=overall,
            divergent_outputs=divergent,
            total_comparisons=total,
            length_variance=length_var,
        )

    def _build_regression_summary(
        self,
        security_regressed: bool,
        resilience_regressed: bool,
        new_vulnerabilities: list[str],
        functional_divergence: float,
        security_delta: float,
        resilience_delta: float,
        behavior: BehaviorDivergenceResult | None = None,
    ) -> str:
        """Build human-readable regression summary."""
        if not any([
            security_regressed,
            resilience_regressed,
            new_vulnerabilities,
            behavior and behavior.has_behavioral_regression,
        ]):
            if functional_divergence >= 0.8:
                return "No regressions detected"

        issues = []

        if security_regressed:
            issues.append(f"Security score dropped by {abs(security_delta):.0f} points")

        if resilience_regressed:
            issues.append(
                f"Resilience score dropped by {abs(resilience_delta):.0f} points"
            )

        if new_vulnerabilities:
            issues.append(
                f"{len(new_vulnerabilities)} new vulnerabilities: {', '.join(new_vulnerabilities[:3])}"
            )

        if functional_divergence < 0.8:
            issues.append(
                f"Functional similarity dropped to {functional_divergence:.0%}"
            )

        # NEW: Behavioral divergence reporting
        if behavior and behavior.has_behavioral_regression:
            behavior_issues = []
            if behavior.overall_consistency < 0.7:
                behavior_issues.append(f"consistency {behavior.overall_consistency:.0%}")
            if behavior.divergent_outputs > 5:
                behavior_issues.append(f"{behavior.divergent_outputs} divergent outputs")
            if behavior_issues:
                issues.append(f"Behavioral divergence detected ({', '.join(behavior_issues)})")

        return "; ".join(issues) if issues else "No regressions detected"
