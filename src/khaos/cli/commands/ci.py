"""The `ci` command - Unified CI/CD pipeline command.

Combines run, gate, and reporting in a single command optimized for CI systems.
Provides structured output (JUnit XML, JSON, Markdown) and clear exit codes.

Exit codes:
    0 - SUCCESS: All gates passed
    1 - SECURITY_FAIL: Security threshold not met
    2 - RESILIENCE_FAIL: Resilience threshold not met
    3 - BOTH_FAIL: Both security and resilience failed
    4 - BASELINE_FAIL: Baseline tests failed
    5 - REGRESSION_FAIL: Regression detected vs baseline
    6 - TEST_FAIL: @khaostest tests failed
    10 - CONFIG_ERROR: Configuration/setup error
    11 - RUNTIME_ERROR: Execution error

Usage:
    khaos ci <agent-name>
    khaos ci <agent-name> --eval full-eval --security-threshold 85
    khaos ci <agent-name> --baseline main --fail-on-regression
    khaos ci <agent-name> --format junit --output-file results.xml
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

import typer
from rich.table import Table
from rich.panel import Panel

from khaos.ci import ExitCode, JUnitReporter, MarkdownReporter, JsonReporter
from khaos.ci.baseline import BaselineManager, RegressionResult
from khaos.cloud.config import load_cloud_config
from khaos.cloud.links import dashboard_evaluation_url
from khaos.packs import get_builtin_pack, list_builtin_packs
from khaos.packs.contract import EvaluationReport
from khaos.cli.console import console

from .run_packs import run_with_pack
from .discover import resolve_agent_target


def _is_ci_env() -> bool:
    return bool(os.environ.get("GITHUB_ACTIONS")) or os.environ.get("KHAOS_CI") == "1"


def _ga_exit_code(exit_code: ExitCode) -> int:
    """Map detailed CI exit codes to GA-friendly 0/1/2 codes.

    - 0: pass
    - 1: evaluation thresholds failed
    - 2: infra/auth/config/runtime error
    """
    if exit_code == ExitCode.SUCCESS:
        return 0
    if exit_code in (
        ExitCode.SECURITY_FAIL,
        ExitCode.RESILIENCE_FAIL,
        ExitCode.BOTH_FAIL,
        ExitCode.BASELINE_FAIL,
        ExitCode.REGRESSION_FAIL,
        ExitCode.TEST_FAIL,
    ):
        return 1
    return 2


def _format_rerun_command(
    *,
    target: str,
    eval_name: str,
    security_threshold: int,
    resilience_threshold: int,
    sync_cloud: bool,
    exit_code_mode: str,
    baseline: str | None,
    fail_on_regression: bool,
) -> str:
    target_arg = f'"{target}"' if " " in target else target
    parts: list[str] = [
        "khaos",
        "ci",
        target_arg,
        "--eval",
        eval_name,
        "--security-threshold",
        str(security_threshold),
        "--resilience-threshold",
        str(resilience_threshold),
        "--exit-code-mode",
        exit_code_mode,
        "--verbose",
    ]
    parts.append("--sync" if sync_cloud else "--no-sync")
    if baseline:
        parts.extend(["--baseline", baseline])
        if fail_on_regression:
            parts.append("--fail-on-regression")
    return " ".join(parts)


def _print_quiet_failure_line(
    *,
    report: EvaluationReport,
    regression_result: RegressionResult | None,
    security_threshold: int,
    resilience_threshold: int,
    exit_code: ExitCode,
    rerun_command: str,
) -> None:
    reasons: list[str] = []
    if report.security and report.security.score < security_threshold:
        reasons.append(f"security {report.security.score:.0f}<{security_threshold}")
    if report.resilience and report.resilience.score < resilience_threshold:
        reasons.append(f"resilience {report.resilience.score:.0f}<{resilience_threshold}")
    if regression_result is not None and regression_result.has_regression:
        reasons.append("regression")

    if not reasons:
        reasons.append(exit_code.describe())

    try:
        config = load_cloud_config()
        dash_url = dashboard_evaluation_url(
            config,
            run_id=report.run_id,
            pack_name=report.pack_name,
            agent_name=(report.agent.name if report.agent else None),
            agent_version=(report.agent.version if report.agent else None),
        )
    except Exception:
        logger.debug("Failed to generate dashboard URL for failure line", exc_info=True)
        dash_url = None

    suffix = f" dashboard={dash_url}" if dash_url else ""
    console.print(
        f"Khaos CI FAIL run_id={report.run_id} reasons={';'.join(reasons)} rerun={rerun_command}{suffix}"
    )


def _write_github_outputs(
    *,
    report: EvaluationReport,
    exit_code: ExitCode,
    security_threshold: int,
    resilience_threshold: int,
) -> None:
    """Write step outputs for GitHub Actions ($GITHUB_OUTPUT) best-effort."""
    output_path_raw = os.environ.get("GITHUB_OUTPUT")
    if not output_path_raw:
        return

    def _sanitize(value: str) -> str:
        # GitHub outputs are line-based; keep it simple for now.
        return (value or "").replace("\n", " ").replace("\r", " ").strip()

    try:
        config = load_cloud_config()
        dash_url = dashboard_evaluation_url(
            config,
            run_id=report.run_id,
            pack_name=report.pack_name,
            agent_name=report.agent_name,
            agent_version=report.agent_version,
        )

        outputs: dict[str, str] = {
            "run_id": report.run_id or "",
            "pack_name": report.pack_name or "",
            "pack_version": report.pack_version or "",
            "overall_score": f"{report.overall_score:.0f}" if report.overall_score is not None else "",
            "security_score": f"{report.security.score:.0f}" if report.security else "",
            "resilience_score": f"{report.resilience.score:.0f}" if report.resilience else "",
            "security_threshold": str(security_threshold),
            "resilience_threshold": str(resilience_threshold),
            "exit_code": str(int(exit_code)),
            "exit_reason": exit_code.name,
            "dashboard_url": dash_url or "",
        }

        # Best-effort local artifacts.
        try:
            from khaos.state import get_state_dir

            runs_dir = get_state_dir() / "runs"
            outputs["trace_path"] = str(runs_dir / f"trace-{report.run_id}.json")
            outputs["metrics_path"] = str(runs_dir / f"metrics-{report.run_id}.json")
        except Exception:
            logger.debug("Failed to resolve local artifact paths for GitHub outputs", exc_info=True)

        path = Path(output_path_raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={_sanitize(value)}\n")
    except Exception:
        # Never fail CI because outputs couldn't be written.
        logger.debug("Failed to write GitHub outputs", exc_info=True)
        return


def _check_ci_sync_preflight(*, sync_cloud: bool) -> None:
    """Fail fast in CI when --sync is enabled but env auth isn't configured."""
    if not sync_cloud:
        return
    if not _is_ci_env():
        return

    config = load_cloud_config()
    missing: list[str] = []
    if not config.api_url:
        missing.append("KHAOS_API_URL")
    if not config.token:
        missing.append("KHAOS_API_TOKEN")
    if not config.project_id:
        missing.append("KHAOS_PROJECT_SLUG")

    if missing:
        console.print("[red]CI sync is enabled but cloud auth is not configured.[/red]")
        console.print("[dim]Set these env vars in your CI secrets/variables:[/dim]")
        for key in missing:
            console.print(f"  [dim]• {key}[/dim]")
        console.print(
            "[dim]Tip: disable upload for now with[/dim] [bold]--no-sync[/bold] [dim]if you only want local reports.[/dim]"
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)


def _ci_preflight(*, sync_cloud: bool, quiet: bool) -> dict:
    """Validate env auth + token reachability without running an evaluation."""
    if sync_cloud:
        _check_ci_sync_preflight(sync_cloud=True)

    from khaos.cloud.client import CloudAuthError, fetch_ingestion_status

    config = load_cloud_config()
    try:
        status = fetch_ingestion_status(config)
    except CloudAuthError as exc:
        if not quiet:
            console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    if not quiet:
        project = status.get("project") or config.project_id or "—"
        scopes = status.get("scopes") or config.scopes or []
        scopes_str = ", ".join([str(s) for s in scopes]) if isinstance(scopes, list) else str(scopes)
        console.print("[green]CI preflight passed[/green]")
        console.print(f"[dim]Project:[/dim] {project}")
        if scopes_str:
            console.print(f"[dim]Scopes:[/dim] {scopes_str}")

    return status if isinstance(status, dict) else {"status": "unknown"}


def ci(
    target: str = typer.Argument(
        ...,
        help="Agent name (from `khaos discover`), optionally pinned as name@version.",
    ),
    # Evaluation selection
    eval_name: str = typer.Option(
        "quickstart",
        "--eval",
        "-e",
        help="Evaluation to run (quickstart, full-eval, security, baseline).",
    ),
    # Deprecated flag (hidden for backward compatibility)
    pack: str | None = typer.Option(
        None,
        "--pack",
        "-p",
        hidden=True,
        help="[Deprecated] Use --eval instead.",
    ),
    # Thresholds
    security_threshold: int = typer.Option(
        80,
        "--security-threshold",
        min=0,
        max=100,
        help="Minimum security score (0-100) to pass.",
    ),
    resilience_threshold: int = typer.Option(
        70,
        "--resilience-threshold",
        min=0,
        max=100,
        help="Minimum resilience score (0-100) to pass.",
    ),
    # Output format
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text, json, junit, markdown, or all.",
    ),
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Write primary output to file (format inferred from extension if not specified).",
    ),
    json_file: Path | None = typer.Option(
        None,
        "--json-file",
        help="Write JSON results to this file (in addition to primary format).",
    ),
    # Baseline comparison
    baseline: str | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Compare against baseline by name (e.g., 'main', 'release-1.0').",
    ),
    save_baseline: str | None = typer.Option(
        None,
        "--save-baseline",
        help="Save this run as a named baseline for future comparisons.",
    ),
    fail_on_regression: bool = typer.Option(
        False,
        "--fail-on-regression",
        help="Exit non-zero if regression detected vs baseline.",
    ),
    # Execution options
    python: str = typer.Option(
        sys.executable,
        "--python",
        help="Python interpreter to use.",
    ),
    env: list[str] = typer.Option(
        [],
        "--env",
        help="Environment variables (KEY=VALUE format).",
    ),
    timeout: float = typer.Option(
        300.0,
        "--timeout",
        help="Maximum execution time in seconds.",
    ),
    # Output control
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Minimal output (for cleaner CI logs).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including agent responses.",
    ),
    sync_cloud: bool = typer.Option(
        bool(os.environ.get("GITHUB_ACTIONS")),
        "--sync/--no-sync",
        help="Upload artifacts to the dashboard (recommended in CI).",
    ),
    project: str | None = typer.Option(
        None,
        "--project",
        help="Project slug for cloud sync (sets KHAOS_PROJECT_SLUG for this run).",
    ),
    dashboard_url: str | None = typer.Option(
        None,
        "--dashboard-url",
        help="Dashboard base URL for links (sets KHAOS_DASHBOARD_URL for this run).",
    ),
    exit_code_mode: str = typer.Option(
        "ga" if bool(os.environ.get("GITHUB_ACTIONS")) else "detailed",
        "--exit-code-mode",
        help="Exit code mode: 'ga' (0/1/2) or 'detailed' (legacy multi-code).",
    ),
    github_summary: bool = typer.Option(
        True,
        "--github-summary/--no-github-summary",
        help="Write a Markdown summary to GITHUB_STEP_SUMMARY when available.",
    ),
    github_output: bool = typer.Option(
        True,
        "--github-output/--no-github-output",
        help="Write key outputs (run_id, scores, dashboard_url) to GITHUB_OUTPUT when available.",
    ),
    preflight: bool = typer.Option(
        True,
        "--preflight/--no-preflight",
        help="Fail fast in CI when required env vars are missing for --sync.",
    ),
    preflight_only: bool = typer.Option(
        False,
        "--preflight-only",
        help="Only validate cloud auth/project access (no evaluation run).",
    ),
    # @khaostest integration
    run_tests_flag: bool = typer.Option(
        False,
        "--test",
        help="Also run @khaostest-decorated tests and include results in output.",
    ),
    test_paths: Optional[list[str]] = typer.Option(
        None,
        "--test-path",
        help="Paths to search for @khaostest tests (default: tests/).",
    ),
) -> None:
    """Run agent evaluation in CI/CD pipeline mode.

    Single command that runs evaluation, checks thresholds, and generates reports.
    Designed for easy integration with GitHub Actions, GitLab CI, Jenkins, etc.

    \b
    Examples:
        # Basic CI run with defaults
        khaos ci my-agent

        # Custom thresholds
        khaos ci my-agent --security-threshold 90 --resilience-threshold 80

        # Generate JUnit XML for CI test reporting
        khaos ci my-agent --format junit --output-file results.xml

        # Compare against baseline and fail on regression
        khaos ci my-agent --baseline main --fail-on-regression

        # Save current run as new baseline
        khaos ci my-agent --save-baseline main

        # Full evaluation with all outputs
        khaos ci my-agent --eval full-eval --format all --output-file results
    """
    # Set CI environment indicator
    os.environ["KHAOS_CI"] = "1"

    # Handle deprecated --pack flag
    selected_eval = eval_name
    if pack is not None:
        if not quiet:
            console.print("[yellow]Warning: --pack is deprecated. Use --eval instead.[/yellow]")
        selected_eval = pack

    try:
        if project:
            os.environ["KHAOS_PROJECT_SLUG"] = project
        if dashboard_url:
            os.environ["KHAOS_DASHBOARD_URL"] = dashboard_url

        if preflight:
            _check_ci_sync_preflight(sync_cloud=sync_cloud)

        if preflight_only:
            status = _ci_preflight(sync_cloud=sync_cloud, quiet=quiet)
            if github_output and os.environ.get("GITHUB_OUTPUT"):
                try:
                    config = load_cloud_config()
                    output_path = Path(os.environ["GITHUB_OUTPUT"])
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    scopes = status.get("scopes")
                    scopes_str = ",".join([str(s) for s in scopes]) if isinstance(scopes, list) else ""
                    with output_path.open("a", encoding="utf-8") as handle:
                        handle.write(f"project={status.get('project') or config.project_id or ''}\n")
                        handle.write(f"scopes={scopes_str}\n")
                except Exception:
                    logger.debug("Failed to write preflight GitHub outputs", exc_info=True)
            # Use GA exit codes when requested (success is 0 in both modes).
            return

        # Resolve agent name to entrypoint path.
        try:
            target_path, agent_name = resolve_agent_target(target)
        except typer.BadParameter as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(ExitCode.CONFIG_ERROR)

        # Validate eval
        available_evals = list_builtin_packs()
        if selected_eval not in available_evals:
            console.print(f"[red]Error: Unknown eval '{selected_eval}'[/red]")
            console.print(f"[dim]Available evals: {', '.join(available_evals)}[/dim]")
            raise typer.Exit(ExitCode.CONFIG_ERROR)

        if not quiet:
            console.print(f"[bold]Khaos CI - Running {selected_eval} evaluation[/bold]")
            console.print(f"[dim]Agent: {agent_name}[/dim]")
            console.print()

        extra_env: dict[str, str] = {}
        for item in env:
            if "=" not in item:
                console.print(f"[red]Error: --env must be KEY=VALUE (got '{item}')[/red]")
                raise typer.Exit(ExitCode.CONFIG_ERROR)
            key, value = item.split("=", 1)
            extra_env[key] = value

        # Internal selector for decorator-based execution (agent name).
        extra_env["KHAOS_AGENT_HANDLER"] = agent_name

        # Run evaluation
        result = run_with_pack(
            target=str(target_path),
            pack_name=selected_eval,
            pack_override=None,
            python=python,
            extra_env=extra_env,
            timeout=timeout,
            json_output=False,
            verbose=verbose,
            quiet=quiet,
            sync_cloud=sync_cloud,
        )

        if result is None:
            console.print("[red]Error: Evaluation failed to produce results[/red]")
            raise typer.Exit(ExitCode.RUNTIME_ERROR)

        report = result.report

        # Baseline comparison (if requested)
        regression_result: RegressionResult | None = None
        if baseline:
            baseline_manager = BaselineManager()
            regression_result = baseline_manager.compare_to_baseline(
                candidate_report=report,
                baseline_name=baseline,
            )

        # Save as baseline (if requested)
        if save_baseline:
            baseline_manager = BaselineManager()
            baseline_path = baseline_manager.save_baseline(
                run_id=report.run_id,
                name=save_baseline,
                report=report,
            )
            if not quiet:
                console.print(f"[green]Saved as baseline: {save_baseline}[/green]")

        # Gate checks
        security_passed = (
            report.security is None
            or report.security.score >= security_threshold
        )
        resilience_passed = (
            report.resilience is None
            or report.resilience.score >= resilience_threshold
        )
        regression_detected = (
            regression_result is not None and regression_result.has_regression
        )

        # Determine exit code
        exit_code = ExitCode.from_gate_results(
            security_passed=security_passed,
            resilience_passed=resilience_passed,
            regression_detected=regression_detected,
            fail_on_regression=fail_on_regression,
        )

        # Run @khaostest tests if requested
        test_summary = None
        if run_tests_flag:
            from khaos.testing.runner import discover_tests as _discover_tests, run_tests as _run_khaos_tests

            search = [Path(p) for p in test_paths] if test_paths else None
            discovered = _discover_tests(search)
            if discovered:
                if not quiet:
                    console.print(f"[dim]Running {len(discovered)} @khaostest tests...[/dim]")
                test_summary = _run_khaos_tests(
                    discovered, verbose=verbose, timeout_ms=int(timeout * 1000),
                )
                if test_summary.failed > 0 and exit_code == ExitCode.SUCCESS:
                    exit_code = ExitCode.TEST_FAIL
            elif not quiet:
                console.print("[dim]No @khaostest tests found.[/dim]")

        if exit_code_mode not in {"ga", "detailed"}:
            console.print("[red]Error: --exit-code-mode must be 'ga' or 'detailed'[/red]")
            raise typer.Exit(ExitCode.CONFIG_ERROR)

        if github_output and os.environ.get("GITHUB_OUTPUT"):
            _write_github_outputs(
                report=report,
                exit_code=exit_code,
                security_threshold=security_threshold,
                resilience_threshold=resilience_threshold,
            )

        # Generate outputs
        _output_results(
            report=report,
            regression_result=regression_result,
            format=format,
            output_file=output_file,
            json_file=json_file,
            security_threshold=security_threshold,
            resilience_threshold=resilience_threshold,
            exit_code=exit_code,
            quiet=quiet,
            test_summary=test_summary,
        )

        if quiet and exit_code != ExitCode.SUCCESS:
            rerun = _format_rerun_command(
                target=agent_name,
                eval_name=selected_eval,
                security_threshold=security_threshold,
                resilience_threshold=resilience_threshold,
                sync_cloud=sync_cloud,
                exit_code_mode=exit_code_mode,
                baseline=baseline,
                fail_on_regression=fail_on_regression,
            )
            _print_quiet_failure_line(
                report=report,
                regression_result=regression_result,
                security_threshold=security_threshold,
                resilience_threshold=resilience_threshold,
                exit_code=exit_code,
                rerun_command=rerun,
            )

        # GitHub Actions: write job summary (best-effort).
        if github_summary and os.environ.get("GITHUB_STEP_SUMMARY"):
            try:
                summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
                markdown = MarkdownReporter(
                    report,
                    regression_result,
                    security_threshold=security_threshold,
                    resilience_threshold=resilience_threshold,
                ).generate()
                # Append test markdown if tests were run
                if test_summary is not None:
                    from khaos.testing.reporters import TestMarkdownReporter
                    markdown += "\n\n" + TestMarkdownReporter(test_summary).generate()
                summary_path.parent.mkdir(parents=True, exist_ok=True)
                summary_path.write_text(markdown + "\n", encoding="utf-8")
            except Exception:
                # Don't fail CI if summary writing fails.
                logger.debug("Failed to write GitHub step summary", exc_info=True)

        # Exit with appropriate code
        effective_exit_code = exit_code
        if exit_code_mode == "ga":
            ga_code = _ga_exit_code(exit_code)
            if ga_code != 0:
                raise typer.Exit(ga_code)
            return

        if effective_exit_code != ExitCode.SUCCESS:
            if not quiet:
                console.print()
                console.print(f"[red]Exit code {effective_exit_code}: {effective_exit_code.describe()}[/red]")
            raise typer.Exit(effective_exit_code)
        else:
            if not quiet:
                console.print()
                console.print("[green]All gates passed[/green]")

    except typer.Exit:
        raise
    except Exception as e:
        if verbose:
            console.print_exception()
        else:
            console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(_ga_exit_code(ExitCode.RUNTIME_ERROR) if exit_code_mode == "ga" else ExitCode.RUNTIME_ERROR)


def _output_results(
    report: EvaluationReport,
    regression_result: RegressionResult | None,
    format: str,
    output_file: Path | None,
    json_file: Path | None,
    security_threshold: int,
    resilience_threshold: int,
    exit_code: ExitCode,
    quiet: bool,
    test_summary: "TestSummary | None" = None,
) -> None:
    """Generate and output results in requested format(s)."""

    # Always write JSON if requested (useful for downstream processing)
    if json_file:
        reporter = JsonReporter(
            report,
            regression_result,
            security_threshold=security_threshold,
            resilience_threshold=resilience_threshold,
        )
        data = reporter.to_dict()
        # Merge test results into JSON if present
        if test_summary is not None:
            from khaos.testing.reporters import TestJsonReporter
            data["khaos_tests"] = TestJsonReporter(test_summary).to_dict()
        import json as _json
        json_file_path = Path(json_file)
        json_file_path.parent.mkdir(parents=True, exist_ok=True)
        json_file_path.write_text(_json.dumps(data, indent=2, default=str))
        if not quiet:
            console.print(f"[dim]JSON written to: {json_file}[/dim]")

    # Determine output format from file extension if not specified
    effective_format = format
    if output_file and format == "text":
        ext = output_file.suffix.lower()
        if ext == ".xml":
            effective_format = "junit"
        elif ext == ".json":
            effective_format = "json"
        elif ext in (".md", ".markdown"):
            effective_format = "markdown"

    # Generate primary output
    if effective_format == "junit":
        reporter = JUnitReporter(
            report,
            security_threshold=security_threshold,
            resilience_threshold=resilience_threshold,
        )
        if output_file:
            reporter.write(output_file)
            if not quiet:
                console.print(f"[dim]JUnit XML written to: {output_file}[/dim]")
            # Write a second JUnit file for @khaostest results
            if test_summary is not None:
                from khaos.testing.reporters import TestJUnitReporter
                test_xml_path = output_file.parent / f"{output_file.stem}-tests{output_file.suffix}"
                TestJUnitReporter(test_summary).write(test_xml_path)
                if not quiet:
                    console.print(f"[dim]Test JUnit XML written to: {test_xml_path}[/dim]")
        else:
            print(reporter.generate())

    elif effective_format == "markdown":
        reporter = MarkdownReporter(
            report,
            regression_result,
            security_threshold=security_threshold,
            resilience_threshold=resilience_threshold,
        )
        if output_file:
            reporter.write(output_file)
            if not quiet:
                console.print(f"[dim]Markdown written to: {output_file}[/dim]")
        else:
            print(reporter.generate())

    elif effective_format == "json":
        reporter = JsonReporter(
            report,
            regression_result,
            security_threshold=security_threshold,
            resilience_threshold=resilience_threshold,
        )
        if output_file:
            reporter.write(output_file)
            if not quiet:
                console.print(f"[dim]JSON written to: {output_file}[/dim]")
        else:
            print(reporter.generate())

    elif effective_format == "all":
        # Generate all formats
        if output_file:
            base = output_file.stem
            parent = output_file.parent
            parent.mkdir(parents=True, exist_ok=True)

            JUnitReporter(report, security_threshold, resilience_threshold).write(
                parent / f"{base}.xml"
            )
            MarkdownReporter(
                report, regression_result, security_threshold, resilience_threshold
            ).write(parent / f"{base}.md")
            JsonReporter(
                report, regression_result, security_threshold, resilience_threshold
            ).write(parent / f"{base}.json")

            # Write test JUnit alongside eval JUnit
            if test_summary is not None:
                from khaos.testing.reporters import TestJUnitReporter
                TestJUnitReporter(test_summary).write(parent / f"{base}-tests.xml")

            if not quiet:
                console.print(f"[dim]Reports written to: {parent}/{base}.[xml,md,json][/dim]")
        else:
            # Print text summary and JSON to stdout
            _print_ci_summary(
                report, regression_result, security_threshold, resilience_threshold
            )

    else:  # text (default)
        if not quiet:
            _print_ci_summary(
                report, regression_result, security_threshold, resilience_threshold
            )
            if test_summary is not None:
                _print_test_summary_compact(test_summary)


def _print_ci_summary(
    report: EvaluationReport,
    regression_result: RegressionResult | None,
    security_threshold: int,
    resilience_threshold: int,
) -> None:
    """Print CI-friendly text summary."""
    console.print()

    # Header
    console.print(Panel(
        f"[bold]Pack:[/bold] {report.pack_name} v{report.pack_version}\n"
        f"[bold]Run ID:[/bold] {report.run_id}\n"
        f"[bold]Overall Score:[/bold] {report.overall_score:.0f}/100",
        title="[bold cyan]Khaos Evaluation Results[/bold cyan]",
    ))

    # Score table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Gate", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Threshold", justify="right")
    table.add_column("Status", justify="center")

    if report.security:
        passed = report.security.score >= security_threshold
        status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        table.add_row(
            "Security",
            f"{report.security.score:.0f}",
            f"{security_threshold}",
            status,
        )

    if report.resilience:
        passed = report.resilience.score >= resilience_threshold
        status = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
        table.add_row(
            "Resilience",
            f"{report.resilience.score:.0f}",
            f"{resilience_threshold}",
            status,
        )

    if report.baseline:
        table.add_row(
            "Baseline",
            f"{report.baseline.task_completion_rate:.0%}",
            "-",
            "[green]PASS[/green]" if report.baseline.task_completion_rate > 0.5 else "[yellow]WARN[/yellow]",
        )

    console.print(table)

    # Regression info
    if regression_result:
        console.print()
        if regression_result.has_regression:
            console.print("[red bold]Regression Detected[/red bold]")
            console.print(f"[dim]Baseline: {regression_result.baseline_run_id}[/dim]")
            console.print(f"[dim]{regression_result.summary}[/dim]")
        else:
            console.print(f"[green]No regression vs baseline: {regression_result.baseline_run_id}[/green]")

    # Quick stats
    if report.security and report.security.vulnerabilities:
        vuln_count = len(report.security.vulnerabilities)
        console.print(f"\n[yellow]Vulnerabilities found: {vuln_count}[/yellow]")

    if report.baseline and report.baseline.cost_usd:
        console.print(f"[dim]Estimated cost: ${report.baseline.cost_usd:.4f}[/dim]")


def _print_test_summary_compact(test_summary: "TestSummary") -> None:
    """Print a compact @khaostest summary after the eval summary."""
    console.print()
    if test_summary.failed == 0:
        console.print(
            f"[green]@khaostest: {test_summary.passed}/{test_summary.total} passed[/green]"
        )
    else:
        console.print(
            f"[red]@khaostest: {test_summary.failed}/{test_summary.total} failed[/red]"
        )
        for r in test_summary.results:
            if not r.passed:
                console.print(f"  [red]\u2717 {r.name}[/red] [dim]({r.error})[/dim]")
