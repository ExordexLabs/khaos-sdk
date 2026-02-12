"""JUnit XML reporter for @khaostest results.

Generates JUnit XML format understood by GitHub Actions, GitLab CI,
Jenkins, CircleCI, and Azure DevOps.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from khaos.testing.runner import TestResult, TestSummary


class TestJUnitReporter:
    """Generate JUnit XML from @khaostest TestSummary.

    One ``<testsuite name="khaos-tests">`` with one ``<testcase>`` per
    ``TestResult``.  Uses ``classname=khaos.{agent}`` to group by agent
    in CI viewers.

    Example output::

        <?xml version="1.0" encoding="UTF-8"?>
        <testsuites name="Khaos Agent Tests" tests="5" failures="1">
          <testsuite name="khaos-tests" tests="5" failures="1" time="2.340">
            <testcase name="test_resilience" classname="khaos.my-agent" time="0.450"/>
            <testcase name="test_security" classname="khaos.my-agent" time="1.200">
              <failure message="Score 60% below min_score 80%" type="AssertionError"/>
            </testcase>
          </testsuite>
        </testsuites>
    """

    def __init__(self, summary: TestSummary) -> None:
        self.summary = summary

    def generate(self) -> str:
        """Generate JUnit XML string."""
        root = ET.Element("testsuites")
        root.set("name", "Khaos Agent Tests")

        total = self.summary.total
        failures = self.summary.failed
        total_time = self.summary.duration_ms / 1000.0

        root.set("tests", str(total))
        root.set("failures", str(failures))
        root.set("errors", "0")
        root.set("time", f"{total_time:.3f}")

        suite = ET.SubElement(root, "testsuite")
        suite.set("name", "khaos-tests")
        suite.set("tests", str(total))
        suite.set("failures", str(failures))
        suite.set("errors", "0")
        suite.set("time", f"{total_time:.3f}")

        for result in self.summary.results:
            tc = self._build_testcase(result)
            suite.append(tc)

        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(
            root, encoding="unicode"
        )

    def _build_testcase(self, result: TestResult) -> ET.Element:
        """Build a ``<testcase>`` element from a TestResult."""
        elem = ET.Element("testcase")
        elem.set("name", result.name)
        elem.set("classname", f"khaos.{result.agent}" if result.agent else "khaos")
        elem.set("time", f"{result.duration_ms / 1000.0:.3f}")

        if not result.passed and result.error:
            failure = ET.SubElement(elem, "failure")
            failure.set("message", result.error)
            failure.set("type", "AssertionError")
            if result.traceback:
                failure.text = result.traceback

        return elem

    def write(self, path: Path) -> None:
        """Write JUnit XML to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate())
