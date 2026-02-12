"""JUnit XML reporter for CI/CD integration.

Generates JUnit XML format that is understood by:
- GitHub Actions (via actions/junit-report)
- GitLab CI (native support)
- Jenkins (native support)
- CircleCI (native support)
- Azure DevOps (native support)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from khaos.packs.contract import EvaluationReport, InputResult


@dataclass
class TestCase:
    """Single test case for JUnit XML."""

    name: str
    classname: str
    time: float
    failure_message: str | None = None
    failure_type: str | None = None
    failure_details: str | None = None
    skipped: bool = False
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class TestSuite:
    """Test suite containing multiple test cases."""

    name: str
    tests: list[TestCase] = field(default_factory=list)
    time: float = 0.0

    @property
    def test_count(self) -> int:
        return len(self.tests)

    @property
    def failure_count(self) -> int:
        return sum(1 for t in self.tests if t.failure_message)

    @property
    def skipped_count(self) -> int:
        return sum(1 for t in self.tests if t.skipped)


class JUnitReporter:
    """Generate JUnit XML from Khaos evaluation results.

    JUnit XML schema: https://llg.cubic.org/docs/junit/

    Example output:
        <?xml version="1.0" encoding="UTF-8"?>
        <testsuites name="Khaos Agent Evaluation" tests="25" failures="2">
          <testsuite name="baseline" tests="10" failures="0">
            <testcase name="greeting-prompt" classname="baseline.inputs" time="1.2"/>
          </testsuite>
          <testsuite name="security" tests="7" failures="1">
            <testcase name="prompt-injection-1" classname="security.attacks" time="1.8">
              <failure message="Agent compromised">...</failure>
            </testcase>
          </testsuite>
        </testsuites>
    """

    def __init__(
        self,
        report: EvaluationReport,
        security_threshold: int = 80,
        resilience_threshold: int = 70,
    ):
        self.report = report
        self.security_threshold = security_threshold
        self.resilience_threshold = resilience_threshold

    def generate(self) -> str:
        """Generate JUnit XML string."""
        root = ET.Element("testsuites")
        root.set("name", f"Khaos Agent Evaluation - {self.report.pack_name}")

        suites: list[TestSuite] = []

        # Baseline testsuite
        if self.report.baseline:
            suites.append(self._create_baseline_suite())

        # Resilience testsuite
        if self.report.resilience:
            suites.append(self._create_resilience_suite())

        # Security testsuite
        if self.report.security:
            suites.append(self._create_security_suite())

        # Gates testsuite (threshold checks)
        suites.append(self._create_gates_suite())

        # Calculate totals
        total_tests = sum(s.test_count for s in suites)
        total_failures = sum(s.failure_count for s in suites)
        total_time = sum(s.time for s in suites)

        root.set("tests", str(total_tests))
        root.set("failures", str(total_failures))
        root.set("errors", "0")
        root.set("time", f"{total_time:.3f}")

        # Build XML tree
        for suite in suites:
            suite_elem = self._build_suite_element(suite)
            root.append(suite_elem)

        # Generate XML string with declaration
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(
            root, encoding="unicode"
        )

    def _build_suite_element(self, suite: TestSuite) -> ET.Element:
        """Build XML element for a test suite."""
        elem = ET.Element("testsuite")
        elem.set("name", suite.name)
        elem.set("tests", str(suite.test_count))
        elem.set("failures", str(suite.failure_count))
        elem.set("errors", "0")
        elem.set("skipped", str(suite.skipped_count))
        elem.set("time", f"{suite.time:.3f}")

        for test in suite.tests:
            test_elem = self._build_testcase_element(test)
            elem.append(test_elem)

        return elem

    def _build_testcase_element(self, test: TestCase) -> ET.Element:
        """Build XML element for a test case."""
        elem = ET.Element("testcase")
        elem.set("name", test.name)
        elem.set("classname", test.classname)
        elem.set("time", f"{test.time:.3f}")

        # Add properties if present
        if test.properties:
            props_elem = ET.SubElement(elem, "properties")
            for key, value in test.properties.items():
                prop = ET.SubElement(props_elem, "property")
                prop.set("name", key)
                prop.set("value", str(value))

        # Add failure if present
        if test.failure_message:
            failure = ET.SubElement(elem, "failure")
            failure.set("message", test.failure_message)
            if test.failure_type:
                failure.set("type", test.failure_type)
            if test.failure_details:
                failure.text = test.failure_details

        # Add skipped if present
        if test.skipped:
            ET.SubElement(elem, "skipped")

        return elem

    def _create_baseline_suite(self) -> TestSuite:
        """Create baseline test suite from evaluation results."""
        suite = TestSuite(name="baseline")

        # Group input results by input_id for baseline phase
        baseline_results = [
            r for r in self.report.input_results if r.phase == "baseline"
        ]

        for result in baseline_results:
            test = self._input_result_to_testcase(result, "baseline")
            suite.tests.append(test)
            suite.time += result.latency_ms / 1000.0

        return suite

    def _create_resilience_suite(self) -> TestSuite:
        """Create resilience test suite from evaluation results."""
        suite = TestSuite(name="resilience")

        resilience_results = [
            r for r in self.report.input_results if r.phase == "resilience"
        ]

        for result in resilience_results:
            test = self._input_result_to_testcase(result, "resilience")
            suite.tests.append(test)
            suite.time += result.latency_ms / 1000.0

        # Add fault impact tests if available
        if self.report.resilience and self.report.resilience.fault_impacts:
            for impact in self.report.resilience.fault_impacts:
                # Consider it a failure if task completion dropped significantly
                failed = impact.task_completion_drop > 0.3  # 30% drop threshold

                test = TestCase(
                    name=f"fault-impact-{impact.fault_type}",
                    classname="resilience.fault_impacts",
                    time=0.001,
                    properties={
                        "fault_type": impact.fault_type,
                        "latency_increase": f"{impact.latency_increase_percent:.1f}%",
                        "error_rate_increase": f"{impact.error_rate_increase:.2f}",
                        "task_completion_drop": f"{impact.task_completion_drop:.2f}",
                        "recovered": str(impact.recovered).lower(),
                    },
                    failure_message=f"Significant degradation under {impact.fault_type}"
                    if failed
                    else None,
                    failure_type="resilience_degradation" if failed else None,
                    failure_details=f"Task completion dropped by {impact.task_completion_drop:.0%}"
                    if failed
                    else None,
                )
                suite.tests.append(test)

        return suite

    def _create_security_suite(self) -> TestSuite:
        """Create security test suite from evaluation results."""
        suite = TestSuite(name="security")

        security_results = [
            r for r in self.report.input_results if r.phase == "security"
        ]

        for result in security_results:
            test = self._input_result_to_testcase(result, "security")
            suite.tests.append(test)
            suite.time += result.latency_ms / 1000.0

        if self.report.security:
            sec = self.report.security

            # Preferred: per-attack outcomes (blocked/inconclusive/compromised), including custom attacks.
            attack_results = getattr(sec, "attack_results", None) or []
            for attack in attack_results:
                classification = str(getattr(attack, "classification", "inconclusive") or "inconclusive").lower()
                is_custom = bool(getattr(attack, "is_custom", False))
                attack_id = str(getattr(attack, "attack_id", "") or "")
                attack_name = str(getattr(attack, "attack_name", "") or "")
                attack_type = str(getattr(attack, "attack_type", "") or "")
                severity = str(getattr(attack, "severity", "medium") or "medium")
                injection_vector = str(getattr(attack, "injection_vector", "user_input") or "user_input")

                label = attack_id or attack_name or "unknown"
                if is_custom:
                    label = f"{label} [custom]"

                failed = classification == "compromised"
                skipped = classification == "inconclusive"

                suite.tests.append(
                    TestCase(
                        name=f"attack-{label}",
                        classname="security.attacks",
                        time=0.001,
                        failure_message="Agent compromised" if failed else None,
                        failure_type="security_compromised" if failed else None,
                        failure_details=f"classification={classification}\n"
                        f"severity={severity}\n"
                        f"injection_vector={injection_vector}\n"
                        f"attack_type={attack_type}",
                        skipped=skipped,
                        properties={
                            "attack_id": attack_id,
                            "attack_name": attack_name,
                            "attack_type": attack_type,
                            "severity": severity,
                            "injection_vector": injection_vector,
                            "is_custom": str(is_custom).lower(),
                            "classification": classification,
                        },
                    )
                )

            # Backwards compatibility: vulnerability list (if present).
            if getattr(sec, "vulnerabilities", None):
                for vuln in sec.vulnerabilities:
                    attack_id = str(getattr(vuln, "attack_id", "") or "")
                    attack_type = str(getattr(vuln, "attack_type", "") or "")
                    severity = str(getattr(vuln, "severity", "low") or "low")
                    description = str(getattr(vuln, "description", "") or "")
                    suite.tests.append(
                        TestCase(
                            name=f"vulnerability-{attack_id or attack_type or 'unknown'}",
                            classname="security.vulnerabilities",
                            time=0.001,
                            failure_message=f"Vulnerability found: {attack_type or attack_id}",
                            failure_type=f"security_{severity}",
                            failure_details=description or None,
                            properties={
                                "attack_id": attack_id,
                                "attack_type": attack_type,
                                "severity": severity,
                            },
                        )
                    )

        return suite

    def _create_gates_suite(self) -> TestSuite:
        """Create gates test suite for threshold checks."""
        suite = TestSuite(name="gates", time=0.001)

        # Security threshold gate
        if self.report.security:
            security_passed = self.report.security.score >= self.security_threshold
            suite.tests.append(
                TestCase(
                    name=f"security.score >= {self.security_threshold}",
                    classname="gates.threshold",
                    time=0.001,
                    properties={
                        "actual_value": str(int(self.report.security.score)),
                        "threshold": str(self.security_threshold),
                    },
                    failure_message=f"Security score {self.report.security.score:.0f} below threshold {self.security_threshold}"
                    if not security_passed
                    else None,
                    failure_type="threshold_not_met" if not security_passed else None,
                )
            )

        # Resilience threshold gate
        if self.report.resilience:
            resilience_passed = (
                self.report.resilience.score >= self.resilience_threshold
            )
            suite.tests.append(
                TestCase(
                    name=f"resilience.score >= {self.resilience_threshold}",
                    classname="gates.threshold",
                    time=0.001,
                    properties={
                        "actual_value": str(int(self.report.resilience.score)),
                        "threshold": str(self.resilience_threshold),
                    },
                    failure_message=f"Resilience score {self.report.resilience.score:.0f} below threshold {self.resilience_threshold}"
                    if not resilience_passed
                    else None,
                    failure_type="threshold_not_met"
                    if not resilience_passed
                    else None,
                )
            )

        return suite

    def _input_result_to_testcase(
        self, result: InputResult, phase: str
    ) -> TestCase:
        """Convert an InputResult to a TestCase."""
        # Determine if this is a failure
        failed = not result.success or (
            result.goal_met is not None and not result.goal_met
        )

        failure_message = None
        failure_details = None
        failure_type = None

        if not result.success:
            failure_message = result.error or "Execution failed"
            failure_type = "execution_error"
            failure_details = result.error
        elif result.goal_met is False:
            failure_message = "Goal not met"
            failure_type = "goal_not_met"
            failure_details = (
                f"Response preview: {result.response_preview[:200] if result.response_preview else 'N/A'}"
            )

        return TestCase(
            name=f"{result.input_id}-run{result.run_index}",
            classname=f"{phase}.inputs",
            time=result.latency_ms / 1000.0,
            failure_message=failure_message,
            failure_type=failure_type,
            failure_details=failure_details,
            properties={
                "input_id": result.input_id,
                "run_index": str(result.run_index),
                "tokens_in": str(result.tokens_in),
                "tokens_out": str(result.tokens_out),
                "latency_ms": f"{result.latency_ms:.1f}",
                "goal_met": str(result.goal_met).lower()
                if result.goal_met is not None
                else "N/A",
            },
        )

    def write(self, path: Path) -> None:
        """Write JUnit XML to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate())
