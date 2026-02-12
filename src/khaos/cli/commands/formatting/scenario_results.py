"""Scenario run results formatting.

Pretty-prints results from scenario-based agent runs.
"""

from __future__ import annotations

from typing import Any
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .footer import print_run_footer
from khaos.cli.console import console


def print_run_results(result: dict[str, Any], verbose: bool = False) -> None:
    """Print run results in a beautiful format."""
    artifacts = result.get("artifacts", [])
    artifact_map = {a.name: a for a in artifacts if hasattr(a, "name")}

    console.print()
    _print_hero(result, artifact_map)
    _print_key_rates(result, artifact_map)
    _print_failure_summary(result, artifact_map)
    _print_failures(result, artifact_map, verbose=verbose)

    # Telemetry table
    llm_artifact = artifact_map.get("llm.observability")
    if llm_artifact and isinstance(llm_artifact.details, dict):
        table = Table(title="LLM Telemetry")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")

        details = llm_artifact.details
        table.add_row("Calls", f"{details.get('call_count', 0)}")
        table.add_row("Tokens In", f"{details.get('total_tokens_in', 0):,}")
        table.add_row("Tokens Out", f"{details.get('total_tokens_out', 0):,}")
        table.add_row("Cost", f"${details.get('cost_usd', 0):.4f}")
        table.add_row("Avg Latency", f"{details.get('avg_latency_ms', 0):.0f}ms")

        console.print(table)

    # Resilience table
    resilience_score = artifact_map.get("resilience.score")
    if resilience_score:
        table = Table(title="Resilience")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right")
        table.add_row("Score", f"{resilience_score.value:.1f}/100")
        report = result.get("resilience_report")
        if isinstance(report, dict):
            recovery = report.get("recovery") or {}
            if isinstance(recovery, dict):
                attempts = recovery.get("attempts")
                success = recovery.get("success_count")
                if isinstance(attempts, int) and isinstance(success, int) and attempts > 0:
                    table.add_row("Recovery", f"{success}/{attempts}")
        console.print(table)

    # Security summary
    security_artifact = artifact_map.get("security.score")
    if security_artifact:
        score = security_artifact.value
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
        ratio = ""
        if isinstance(getattr(security_artifact, "details", None), dict):
            d = security_artifact.details
            tested = d.get("attacks_tested")
            blocked = d.get("attacks_blocked")
            if isinstance(tested, int) and isinstance(blocked, int) and tested > 0:
                ratio = f" • blocked {blocked}/{tested}"
        console.print(f"\n[bold]Security Score:[/bold] {score:.0f}/100 ({grade}){ratio}")

    _print_helpful_commands(result, artifact_map)
    _print_footer(result)


def _get_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _artifact_score(artifact: Any) -> float | None:
    if artifact is None:
        return None
    try:
        return float(getattr(artifact, "value", None))
    except Exception:
        return None


def _scenario_overall_score(artifact_map: dict[str, Any]) -> float | None:
    # Prefer resilience.score when available (it already incorporates goal/recovery/stability).
    res = _artifact_score(artifact_map.get("resilience.score"))
    if res is not None:
        return res
    scores = [
        s
        for s in [
            _artifact_score(artifact_map.get("goal.score")),
            _artifact_score(artifact_map.get("security.score")),
        ]
        if s is not None
    ]
    if not scores:
        return None
    return sum(scores) / len(scores)


def _determine_verdict(artifact_map: dict[str, Any]) -> tuple[str, str, str]:
    security = artifact_map.get("security.score")
    if security is not None and isinstance(getattr(security, "details", None), dict):
        vulns = security.details.get("vulnerabilities_found") or []
        if isinstance(vulns, list) and len(vulns) > 0:
            return "failed", "[bold red]✗ EVALUATION FAILED[/bold red]", "red"

    overall = _scenario_overall_score(artifact_map)
    if overall is None:
        return "warning", "[bold yellow]⚠ NEEDS ATTENTION[/bold yellow]", "yellow"
    if overall >= 80:
        return "passed", "[bold green]✓ EVALUATION PASSED[/bold green]", "green"
    if overall >= 60:
        return "warning", "[bold yellow]⚠ NEEDS ATTENTION[/bold yellow]", "yellow"
    return "failed", "[bold red]✗ EVALUATION FAILED[/bold red]", "red"


def _print_hero(result: dict[str, Any], artifact_map: dict[str, Any]) -> None:
    """Print hero section - verdict and score, clean and minimal."""
    from rich import box

    verdict, verdict_text, verdict_style = _determine_verdict(artifact_map)
    score = _scenario_overall_score(artifact_map)
    grade = _get_grade(score) if score is not None else "—"

    scenario = str(result.get("scenario") or "scenario")

    hero = Text()

    # Verdict + Score on same line
    hero.append(f" {verdict_text}  ", style="bold")
    if score is None:
        hero.append("—", style=f"bold {verdict_style}")
    else:
        hero.append(f"{score:.0f}", style=f"bold {verdict_style}")
        hero.append(f"/100 ({grade})\n", style="dim")

    # Scenario name - subtle
    hero.append(f" {scenario}", style="dim")

    # Critical alerts only
    security = artifact_map.get("security.score")
    if security is not None and isinstance(getattr(security, "details", None), dict):
        vulns = security.details.get("vulnerabilities_found") or []
        if isinstance(vulns, list) and len(vulns) > 0:
            hero.append(f"\n [red]⚠ {len(vulns)} security vulnerability(s)[/red]")

    console.print(
        Panel(
            hero,
            border_style=verdict_style,
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )


def _print_failure_summary(result: dict[str, Any], artifact_map: dict[str, Any]) -> None:
    """Print compact failure summary - only critical issues."""
    bullets: list[str] = []

    goal = artifact_map.get("goal.score")
    if goal is not None:
        try:
            goal_score = float(getattr(goal, "value", 0.0) or 0.0)
        except Exception:
            goal_score = 0.0
        if goal_score < 80:
            bullets.append(f"Goal score {goal_score:.0f}/100")

    resilience = artifact_map.get("resilience.score")
    if resilience is not None:
        try:
            res_score = float(getattr(resilience, "value", 0.0) or 0.0)
        except Exception:
            res_score = 0.0
        if res_score < 80:
            bullets.append(f"Resilience {res_score:.0f}/100")

    security = artifact_map.get("security.score")
    if security is not None and isinstance(getattr(security, "details", None), dict):
        details = security.details
        vulns = details.get("vulnerabilities_found") or []
        if isinstance(vulns, list) and vulns:
            bullets.append(f"{len(vulns)} security vulnerabilities")

    if bullets:
        console.print()
        console.print("[bold red]Issues[/bold red]  " + "  •  ".join(bullets[:3]))


def _print_failures(result: dict[str, Any], artifact_map: dict[str, Any], *, verbose: bool) -> None:
    rows: list[tuple[str, str, str]] = []

    # Transport errors / recovery issues from resilience report if available.
    report = result.get("resilience_report")
    if isinstance(report, dict):
        recovery = report.get("recovery") or {}
        if isinstance(recovery, dict):
            attempts = recovery.get("attempts")
            success = recovery.get("success_count")
            if isinstance(attempts, int) and isinstance(success, int) and attempts > success:
                rows.append(("resilience", "recovery", f"{success}/{attempts} transport receives"))

        goal = report.get("goal") or {}
        if isinstance(goal, dict):
            assertions = goal.get("assertions") or []
            if isinstance(assertions, list):
                for a in assertions:
                    if not isinstance(a, dict):
                        continue
                    passed = a.get("passed")
                    if passed is True:
                        continue
                    name = str(a.get("name") or "assertion")
                    message = str(a.get("message") or "failed")
                    rows.append(("goal", name, message))
                    if len(rows) >= 8:
                        break

    # Security vulnerabilities: show first few vulnerable attacks.
    security = artifact_map.get("security.score")
    if security is not None and isinstance(getattr(security, "details", None), dict):
        details = security.details
        results_list = details.get("results") or []
        if isinstance(results_list, list):
            for r in results_list:
                if not isinstance(r, dict):
                    continue
                vulns = r.get("vulnerabilities") or []
                if not isinstance(vulns, list) or not vulns:
                    continue
                attack_id = str(r.get("attack_id") or "attack")
                attack_type = str(r.get("attack_type") or "security")
                rows.append(("security", f"{attack_type}:{attack_id}", ", ".join([str(v) for v in vulns[:2]])))
                if len(rows) >= 10:
                    break

    if not rows:
        return

    console.print()
    console.print("[bold red]What Failed[/bold red]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Area", style="cyan", no_wrap=True)
    table.add_column("Item", style="white")
    table.add_column("Details", style="red")

    for area, item, details in rows[:12]:
        detail_text = details if verbose else (details[:120] + ("..." if len(details) > 120 else ""))
        table.add_row(area, item, detail_text)

    console.print()
    console.print(table)


def _print_helpful_commands(result: dict[str, Any], artifact_map: dict[str, Any]) -> None:
    """Print helpful command hint - only if useful."""
    # Skip this section - it's verbose and not essential
    pass


def _print_key_rates(result: dict[str, Any], artifact_map: dict[str, Any]) -> None:
    """Print compact key metrics inline - skip verbose section."""
    # Key rates are now shown in the hero/summary, skip redundant display
    pass


def _print_footer(result: dict[str, Any]) -> None:
    run_id = str(result.get("run_id") or "").strip()
    if not run_id:
        return
    trace_file = result.get("trace_file")
    metrics_file = result.get("metrics_file")
    stderr_file = result.get("stderr_file")
    print_run_footer(
        console,
        run_id=run_id,
        name=str(result.get("name") or "") or None,
        scenario_identifier=str(result.get("scenario") or "") or None,
        trace_path=Path(trace_file) if trace_file else None,
        metrics_path=Path(metrics_file) if metrics_file else None,
        stderr_path=Path(stderr_file) if stderr_file else None,
    )
