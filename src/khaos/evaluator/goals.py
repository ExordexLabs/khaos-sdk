"""Evaluator that executes scenario assertions and computes goal scores."""

from __future__ import annotations

from typing import Any
from collections.abc import Iterable

from khaos.chaos.scenario import AssertionDefinition, GoalDefinition
from khaos.validation import AssertionResult, run_assertions

from .base import EvaluationArtifact, EvaluationContext, Evaluator

class GoalEvaluator:
    """Run declarative assertions + goals defined in scenario documents."""

    name = "goal-evaluator"

    async def evaluate(
        self,
        context: EvaluationContext,
    ) -> Iterable[EvaluationArtifact]:
        metadata = context.metadata
        assertion_docs = metadata.get("scenario_assertions", []) or []
        goal_docs = metadata.get("scenario_goals", []) or []
        final_response = metadata.get("final_response")
        # Get trace for intermediate assertions (trace-based assertions)
        trace: list[dict[str, Any]] | None = metadata.get("trace")  # type: ignore[assignment]

        if not assertion_docs:
            # No assertions defined: goal_status = invalid, no score
            artifacts = [
                EvaluationArtifact(
                    name="goal_status",
                    value=0,
                    unit="status",
                    details={"status": "invalid", "reason": "no_assertions_defined"},
                )
            ]
            return artifacts

        assertions = [AssertionDefinition.model_validate(doc) for doc in assertion_docs]
        goals = [GoalDefinition.model_validate(doc) for doc in goal_docs]

        # Pass trace to assertions for intermediate target evaluation
        results = run_assertions(
            assertions=assertions,
            final_response=final_response,
            trace=trace,
        )
        artifacts: list[EvaluationArtifact] = []

        # Compute pass rate
        pass_rate = sum(1 for result in results if result.passed) / len(results) if results else 0.0

        # Check for critical assertion failures
        critical_failures = [
            result for result in results
            if not result.passed and self._is_critical(result.name, assertions)
        ]

        artifacts.append(
            EvaluationArtifact(
                name="assertion.pass_rate",
                value=round(pass_rate * 100, 2),
                unit="percent",
                details={
                    "assertions": [
                        {
                            "name": result.name,
                            "passed": result.passed,
                            "actual": result.actual,
                            "expected": result.expected,
                            "message": result.message,
                            "critical": self._is_critical(result.name, assertions),
                            "target": result.target,  # Include which target was evaluated
                        }
                        for result in results
                    ],
                    "critical_failures": len(critical_failures),
                    "trace_based_assertions": sum(
                        1 for a in assertions if a.target != "final_response"
                    ),
                },
            )
        )

        # Compute goal score and status
        goal_artifacts, overall_score = self._compute_goals(goals, results)
        artifacts.extend(goal_artifacts)

        # Always emit goal.score (use pass_rate if no goals defined)
        if overall_score is None:
            overall_score = pass_rate

        goal_score_value = round(overall_score * 100, 2)
        artifacts.append(
            EvaluationArtifact(
                name="goal.score",
                value=goal_score_value,
                unit="points",
                details={
                    "goal_count": len(goals),
                    "completed": sum(
                        1 for artifact in goal_artifacts if artifact.details.get("completed")
                    ),
                    "source": "goals" if goals else "assertion_pass_rate",
                },
            )
        )

        # Compute goal_status
        goal_status = self._compute_goal_status(
            overall_score=overall_score,
            critical_failures=critical_failures,
            has_final_response=final_response is not None,
        )

        artifacts.append(
            EvaluationArtifact(
                name="goal_status",
                value=self._status_to_numeric(goal_status),
                unit="status",
                details={
                    "status": goal_status,
                    "score": goal_score_value,
                    "critical_failures": len(critical_failures),
                    "invariant_violations": [
                        {
                            "assertion": failure.name,
                            "expected": failure.expected,
                            "actual": failure.actual,
                            "message": failure.message,
                        }
                        for failure in critical_failures
                    ],
                },
            )
        )

        return artifacts

    def _compute_goals(
        self,
        goals: list[GoalDefinition],
        results: list[AssertionResult],
    ) -> tuple[list[EvaluationArtifact], float | None]:
        if not goals:
            return ([], None)

        result_map = {result.name: result for result in results}
        artifacts: list[EvaluationArtifact] = []
        total_weight = sum(goal.weight for goal in goals) or 1.0
        weighted_score = 0.0

        for goal in goals:
            if not goal.assertions:
                continue
            goal_results = [result_map.get(name) for name in goal.assertions]
            filtered = [result for result in goal_results if result is not None]
            if not filtered:
                continue
            completion = sum(1 for result in filtered if result.passed) / len(filtered)
            completed = completion >= goal.success_threshold
            weighted_score += goal.weight * completion
            artifacts.append(
                EvaluationArtifact(
                    name=f"goal.{goal.name}",
                    value=round(completion * 100, 2),
                    unit="percent",
                    details={
                        "completed": completed,
                        "threshold": goal.success_threshold,
                        "assertions": [
                            {
                                "name": r.name,
                                "passed": r.passed,
                                "expected": r.expected,
                            }
                            for r in filtered
                        ],
                    },
                )
            )

        overall_score = weighted_score / total_weight if total_weight else None
        return artifacts, overall_score

    def _is_critical(self, assertion_name: str, assertions: list[AssertionDefinition]) -> bool:
        """Check if an assertion is marked as critical."""
        for assertion in assertions:
            if assertion.name == assertion_name:
                return assertion.critical
        return False

    def _compute_goal_status(
        self,
        overall_score: float,
        critical_failures: list,
        has_final_response: bool,
    ) -> str:
        """Compute discrete goal_status from score and failures.

        Returns: success | partial | failure | invalid
        """
        if not has_final_response:
            return "invalid"

        if critical_failures:
            return "failure"

        if overall_score >= 1.0:
            return "success"
        elif overall_score >= 0.5:
            return "partial"
        else:
            return "failure"

    def _status_to_numeric(self, status: str) -> int:
        """Convert status string to numeric for artifact storage."""
        mapping = {"success": 100, "partial": 50, "failure": 0, "invalid": -1}
        return mapping.get(status, -1)
