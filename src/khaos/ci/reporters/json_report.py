"""JSON reporter for CI/CD integration.

Generates structured JSON output that can be parsed by CI systems
for custom dashboards, notifications, and downstream processing.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING

from khaos.packs.contract import EvaluationReport
from khaos.state import get_state_dir
from khaos.cloud.config import load_cloud_config
from khaos.cloud.links import dashboard_evaluation_url

if TYPE_CHECKING:
    from khaos.ci.baseline import RegressionResult


class JsonReporter:
    """Generate structured JSON report from Khaos evaluation results.

    Output schema is designed for easy parsing in CI scripts:

    {
        "run_id": "abc123",
        "pack_name": "quickstart",
        "timestamp": "2024-12-28T...",
        "overall_score": 85.0,
        "security_score": 90.0,
        "resilience_score": 80.0,
        "thresholds": {"security": 80, "resilience": 70},
        "gates_passed": {"security": true, "resilience": true, "all": true},
        "regression_detected": false,
        "summary": {...},
        "report": {...}  // Full report data
    }
    """

    def __init__(
        self,
        report: EvaluationReport,
        regression_result: "RegressionResult" | None = None,
        security_threshold: int = 80,
        resilience_threshold: int = 70,
    ):
        self.report = report
        self.regression_result = regression_result
        self.security_threshold = security_threshold
        self.resilience_threshold = resilience_threshold

    def generate(self) -> str:
        """Generate JSON report string."""
        data = self.to_dict()
        return json.dumps(data, indent=2, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Generate dictionary representation."""
        # Calculate gate pass/fail
        security_passed = (
            self.report.security is None
            or self.report.security.score >= self.security_threshold
        )
        resilience_passed = (
            self.report.resilience is None
            or self.report.resilience.score >= self.resilience_threshold
        )
        regression_detected = (
            self.regression_result is not None
            and self.regression_result.has_regression
        )
        all_passed = security_passed and resilience_passed and not regression_detected

        data: dict[str, Any] = {
            "run_id": self.report.run_id,
            "pack_name": self.report.pack_name,
            "pack_version": self.report.pack_version,
            "timestamp": self.report.timestamp,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "dashboard_url": dashboard_evaluation_url(
                load_cloud_config(),
                run_id=self.report.run_id,
                pack_name=self.report.pack_name,
                agent_name=(self.report.agent.name if self.report.agent else None),
                agent_version=(self.report.agent.version if self.report.agent else None),
            ),
            "artifact_paths": self._artifact_paths(),
            # Top-level scores for easy access
            "overall_score": self.report.overall_score,
            "security_score": (
                self.report.security.score if self.report.security else None
            ),
            "resilience_score": (
                self.report.resilience.score if self.report.resilience else None
            ),
            "baseline_completion_rate": (
                self.report.baseline.task_completion_rate
                if self.report.baseline
                else None
            ),
            # Thresholds
            "thresholds": {
                "security": self.security_threshold,
                "resilience": self.resilience_threshold,
            },
            # Gate results
            "gates_passed": {
                "security": security_passed,
                "resilience": resilience_passed,
                "regression": not regression_detected,
                "all": all_passed,
            },
            "regression_detected": regression_detected,
            # Summary for CI display
            "summary": self._build_summary(),
            # Exit code hint
            "exit_code": self._determine_exit_code(
                security_passed, resilience_passed, regression_detected
            ),
        }

        # Add regression details if available
        if self.regression_result:
            data["regression"] = {
                "detected": self.regression_result.has_regression,
                "baseline_run_id": self.regression_result.baseline_run_id,
                "candidate_run_id": self.regression_result.candidate_run_id,
                "security_regressed": self.regression_result.security_regressed,
                "resilience_regressed": self.regression_result.resilience_regressed,
                "new_vulnerabilities": self.regression_result.new_vulnerabilities,
                "functional_divergence": self.regression_result.functional_divergence,
                "summary": self.regression_result.summary,
            }

        # Add full report for detailed analysis
        data["report"] = self.report.to_dict()

        return data

    def _artifact_paths(self) -> dict[str, str]:
        """Best-effort local artifact paths for this run."""
        if not self.report.run_id:
            return {}
        runs_dir = get_state_dir() / "runs"
        return {
            "trace": str(runs_dir / f"trace-{self.report.run_id}.json"),
            "metrics": str(runs_dir / f"metrics-{self.report.run_id}.json"),
            "stderr": str(runs_dir / f"stderr-{self.report.run_id}.log"),
        }

    def _build_summary(self) -> dict[str, Any]:
        """Build summary section for quick CI access."""
        summary: dict[str, Any] = {
            "verdict": "pass" if self._all_gates_passed() else "fail",
            "failures": [],
        }

        if self.report.security:
            if self.report.security.score < self.security_threshold:
                summary["failures"].append({
                    "gate": "security",
                    "actual": self.report.security.score,
                    "threshold": self.security_threshold,
                    "message": f"Security score {self.report.security.score:.0f} below threshold {self.security_threshold}",
                })

            summary["security"] = {
                "score": self.report.security.score,
                "attacks_tested": self.report.security.attacks_tested,
                "attacks_blocked": self.report.security.attacks_blocked,
                "vulnerabilities": {
                    "critical": self.report.security.critical_vulnerabilities,
                    "high": self.report.security.high_vulnerabilities,
                    "medium": self.report.security.medium_vulnerabilities,
                    "low": self.report.security.low_vulnerabilities,
                },
            }
            attack_results = getattr(self.report.security, "attack_results", None) or []
            if attack_results:
                blocked = [a for a in attack_results if getattr(a, "classification", "") == "blocked"]
                inconclusive = [a for a in attack_results if getattr(a, "classification", "") == "inconclusive"]
                compromised = [a for a in attack_results if getattr(a, "classification", "") == "compromised"]
                custom = [a for a in attack_results if getattr(a, "is_custom", False)]

                def _attack_dict(a: object) -> dict[str, Any]:
                    return {
                        "attack_id": getattr(a, "attack_id", None),
                        "attack_name": getattr(a, "attack_name", None),
                        "attack_type": getattr(a, "attack_type", None),
                        "severity": getattr(a, "severity", None),
                        "injection_vector": getattr(a, "injection_vector", None),
                        "is_custom": getattr(a, "is_custom", None),
                        "classification": getattr(a, "classification", None),
                    }

                summary["security"]["attack_results"] = {
                    "total": len(attack_results),
                    "blocked": len(blocked),
                    "inconclusive": len(inconclusive),
                    "compromised": len(compromised),
                    "custom_total": len(custom),
                    "compromised_attacks": [_attack_dict(a) for a in compromised[:20]],
                    "inconclusive_attacks": [_attack_dict(a) for a in inconclusive[:20]],
                }

        if self.report.resilience:
            if self.report.resilience.score < self.resilience_threshold:
                summary["failures"].append({
                    "gate": "resilience",
                    "actual": self.report.resilience.score,
                    "threshold": self.resilience_threshold,
                    "message": f"Resilience score {self.report.resilience.score:.0f} below threshold {self.resilience_threshold}",
                })

            summary["resilience"] = {
                "score": self.report.resilience.score,
                "degradation_percent": self.report.resilience.degradation_percent,
                "recovery_rate": self.report.resilience.recovery_rate,
                "fault_types_tested": (
                    self.report.resilience.fault_coverage.fault_types_tested
                    if self.report.resilience.fault_coverage
                    else []
                ),
            }

        if self.report.baseline:
            summary["baseline"] = {
                "completion_rate": self.report.baseline.task_completion_rate,
                "error_rate": self.report.baseline.error_rate,
                "goals_met": self.report.baseline.goals_met,
                "goals_total": self.report.baseline.goals_total,
                "latency_p50_ms": self.report.baseline.latency.p50,
                "latency_p95_ms": self.report.baseline.latency.p95,
                "cost_usd": self.report.baseline.cost_usd,
            }

        if self.regression_result and self.regression_result.has_regression:
            summary["failures"].append({
                "gate": "regression",
                "actual": True,
                "threshold": False,
                "message": self.regression_result.summary,
            })

        return summary

    def _all_gates_passed(self) -> bool:
        """Check if all gates passed."""
        security_passed = (
            self.report.security is None
            or self.report.security.score >= self.security_threshold
        )
        resilience_passed = (
            self.report.resilience is None
            or self.report.resilience.score >= self.resilience_threshold
        )
        no_regression = (
            self.regression_result is None
            or not self.regression_result.has_regression
        )
        return security_passed and resilience_passed and no_regression

    def _determine_exit_code(
        self, security_passed: bool, resilience_passed: bool, regression: bool
    ) -> int:
        """Determine appropriate exit code."""
        if regression:
            return 5  # REGRESSION_FAIL

        code = 0
        if not security_passed:
            code |= 1  # SECURITY_FAIL
        if not resilience_passed:
            code |= 2  # RESILIENCE_FAIL

        return code

    def write(self, path: Path) -> None:
        """Write JSON to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate())
