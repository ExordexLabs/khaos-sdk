"""Scenario-based agent evaluation.

Executes agent with chaos scenarios for full resilience testing.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import uuid
from pathlib import Path
from typing import Any

import typer

from khaos.agent import discover_agent_metadata, record_agent_run
from khaos.artifacts import generate_run_id
from khaos.chaos import ChaosScenario
from khaos.engine import ChaosRuntime
from khaos.engine.runtime import EngineSettings
from khaos.transport import TransportContext, create_transport
from khaos.runtime_hooks import install_runtime_discovery
from khaos.state import get_state_dir
from khaos.cli.console import console

from .formatting import print_run_results


def run_with_scenario(
    target: str,
    *,
    target_name: str | None = None,
    scenario: str | None,
    quick: bool,
    security_attacks: list[dict[str, Any]] | None,
    extra_env: dict[str, str],
    python: str,
    timeout: float,
    json_output: bool,
    verbose: bool,
    quiet: bool,
    compare: str | None,
    sync_cloud: bool,
    seed: int | None = None,
    name: str | None = None,
) -> None:
    """Run agent with a chaos scenario (full evaluation mode)."""
    from khaos.chaos import ScenarioRegistry
    from khaos.cli.constants import SCENARIOS_ROOT

    # Pre-flight: ensure auth when syncing to cloud.
    # This runs BEFORE the evaluation so the user isn't interrupted after a
    # long-running run, and so that ~/.khaos/cloud.json has the correct
    # dashboard_url / project_id for the footer URL.
    if sync_cloud:
        from khaos.cloud.syncing import ensure_logged_in
        from khaos.cloud.config import load_cloud_config as _load_cloud_config

        try:
            ensure_logged_in()
        except Exception as exc:
            if not quiet:
                console.print(f"[yellow]Cloud sync requires authentication: {exc}[/yellow]")
                console.print("[dim]Run without --sync, or run 'khaos login' first.[/dim]")
            raise typer.Exit(code=1)

        cloud_config = _load_cloud_config()
        if not quiet and not json_output:
            project_label = cloud_config.project_id or "default"
            console.print(
                f"[dim]Syncing to[/dim] [bold cyan]{project_label}[/bold cyan] "
                f"[dim]on[/dim] {cloud_config.get_dashboard_url()}"
            )

    # Load scenario
    selected = _load_scenario(scenario, quick, SCENARIOS_ROOT)

    # Discover agent metadata
    entrypoint = Path(target)
    agent_metadata = _discover_agent(entrypoint, quiet)

    # Setup run directories
    run_id, runs_dir, stderr_path, llm_event_path, working_dir = _setup_run_directories()

    # Environment
    run_env = _build_run_environment(extra_env, llm_event_path, security_attacks)

    # Create transport
    transport_context = TransportContext(
        run_id=run_id,
        target=target,
        python_path=python,
        working_dir=working_dir,
        env=run_env,
        stderr_path=stderr_path,
        llm_event_path=llm_event_path,
        llm_content_mode="redact",
    )

    # Detect agent type and configure transport
    transport_options = _configure_transport(target, python)

    try:
        transport_adapter = create_transport("subprocess", transport_context, transport_options)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    install_runtime_discovery(entrypoint)

    # Determine seed: use provided or generate random
    effective_seed = seed if seed is not None else random.randint(0, 2**31 - 1)

    # Execute
    runtime = ChaosRuntime(settings=EngineSettings())
    try:
        result = asyncio.run(
            runtime.execute(transport_adapter, selected, run_id=run_id, seed=effective_seed)
        )
    except Exception as exc:
        if not quiet:
            console.print(f"[red]Error during execution: {exc}[/red]")
        raise typer.Exit(code=1)

    # Attach invocation context for better CLI suggestions.
    result["target"] = target_name or target
    result["trace_file"] = str(runs_dir / f"trace-{run_id}.json")
    result["metrics_file"] = str(runs_dir / f"metrics-{run_id}.json")
    result["stderr_file"] = str(stderr_path)

    # Record agent run
    if agent_metadata:
        record_agent_run(agent_metadata)

    # Display results
    if json_output:
        from khaos.cloud.config import load_cloud_config
        from khaos.cloud.links import dashboard_evaluation_url

        trace_path = runs_dir / f"trace-{run_id}.json"
        metrics_path = runs_dir / f"metrics-{run_id}.json"
        stderr_file = stderr_path if stderr_path.exists() else None

        result["artifact_paths"] = {
            "trace": str(trace_path) if trace_path.exists() else None,
            "metrics": str(metrics_path) if metrics_path.exists() else None,
            "stderr": str(stderr_file) if stderr_file else None,
        }
        result["dashboard_url"] = dashboard_evaluation_url(
            load_cloud_config(),
            run_id=run_id,
            name=name,
            scenario_identifier=selected.metadata.identifier,
            agent_name=(agent_metadata.name if agent_metadata else None),
            agent_version=(agent_metadata.version if agent_metadata else None),
        )
        typer.echo(json.dumps(result, indent=2, default=str))
    elif not quiet:
        print_run_results(result, verbose=verbose)

    if sync_cloud:
        from khaos.cloud.syncing import enqueue_and_sync, new_job

        trace_path = runs_dir / f"trace-{run_id}.json"
        metrics_path = runs_dir / f"metrics-{run_id}.json"

        job = new_job(
            run_id=run_id,
            scenario_id=selected.metadata.identifier,
            trace_path=str(trace_path),
            metrics_path=str(metrics_path) if metrics_path.exists() else None,
            stderr_path=str(stderr_path) if stderr_path.exists() else None,
            seed=effective_seed,
            agent_name=agent_metadata.name if agent_metadata else Path(target).stem,
            agent_version=agent_metadata.version if agent_metadata else "0.0.0",
            agent_code_hash=agent_metadata.code_hash if agent_metadata else "",
            agent_metadata=agent_metadata.metadata if agent_metadata else {},
            agent_category=(agent_metadata.category.value if agent_metadata and agent_metadata.category else None),
            agent_capabilities=(agent_metadata.capabilities if agent_metadata else []),
            agent_signals=(agent_metadata.signals if agent_metadata else []),
            name=name,
        )

        if not quiet and not json_output:
            console.print(f"\n[dim]Syncing {run_id} to dashboard...[/dim]", end=" ")
        attempt = enqueue_and_sync(job)
        if attempt.success:
            if not quiet and not json_output:
                console.print("[green]done[/green]")
            return
        if not quiet and not json_output:
            console.print("[yellow]upload failed; queued for retry[/yellow]")
            if attempt.error and verbose:
                console.print(f"[dim]{attempt.error}[/dim]")
            console.print("[dim]Run 'khaos sync' to retry.[/dim]")


def _load_scenario(
    scenario: str | None,
    quick: bool,
    scenarios_root: Path,
) -> ChaosScenario:
    """Load scenario by name, path, or defaults."""
    from khaos.chaos import ScenarioRegistry

    if scenario:
        # Check if it's a file path
        scenario_path = Path(scenario)
        if scenario_path.exists() and scenario_path.suffix in {".yaml", ".yml"}:
            return ChaosScenario.from_file(scenario_path)
        else:
            # Load from registry
            registry = ScenarioRegistry(search_paths=[scenarios_root])
            selected = registry.get(scenario)
            if selected is None:
                raise typer.BadParameter(f"Scenario '{scenario}' not found")
            return selected
    elif quick:
        # Use minimal baseline scenario
        registry = ScenarioRegistry(search_paths=[scenarios_root])
        selected = registry.get("baseline") or registry.get("quickstart")
        if selected is None:
            # Create minimal inline scenario
            return ChaosScenario(
                id="baseline",
                name="Baseline",
                description="Minimal baseline scenario",
                faults=[],
            )
        return selected
    else:
        # Use default full evaluation scenario
        registry = ScenarioRegistry(search_paths=[scenarios_root])
        selected = registry.get("release.v1.full") or registry.get("quickstart")
        if selected is None:
            return ChaosScenario(
                id="quickstart",
                name="Quickstart",
                description="Default evaluation scenario",
                faults=[{"type": "http_latency", "delay_ms": 50, "probability": 0.3}],
            )
        return selected


def _discover_agent(entrypoint: Path, quiet: bool) -> Any | None:
    """Discover agent metadata."""
    try:
        return discover_agent_metadata(entrypoint)
    except Exception as exc:
        if not quiet:
            console.print(f"[yellow]Warning: Could not discover agent metadata: {exc}[/yellow]")
        return None


def _setup_run_directories() -> tuple[str, Path, Path, Path, Path]:
    """Setup run directories and paths."""
    run_id = generate_run_id("scenario")
    runs_dir = get_state_dir() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    stderr_path = runs_dir / f"stderr-{run_id}.log"
    llm_event_path = runs_dir / f"llm-events-{run_id}.jsonl"
    working_dir = runs_dir / f"agent-{run_id}"
    working_dir.mkdir(parents=True, exist_ok=True)

    return run_id, runs_dir, stderr_path, llm_event_path, working_dir


def _build_run_environment(
    extra_env: dict[str, str],
    llm_event_path: Path,
    security_attacks: list[dict[str, Any]] | None,
) -> dict[str, str]:
    """Build environment for run."""
    run_env = {
        "PYTHONPATH": str(Path.cwd()),
        "KHAOS_LLM_EVENT_FILE": str(llm_event_path),
        "KHAOS_AUTO_WRAP": "1",
        "KHAOS_LLM_SHIM": "1",
        **extra_env,
    }

    # Add security attacks to environment
    if security_attacks:
        run_env["KHAOS_SECURITY_ATTACKS"] = json.dumps(security_attacks)
        run_env["KHAOS_SECURITY_ATTACK_MODE"] = "interleave"

    return run_env


def _configure_transport(target: str, python: str) -> dict[str, Any]:
    """Configure transport options for agent."""
    transport_options: dict[str, Any] = {}
    entrypoint_path = Path(target).resolve()

    if entrypoint_path.suffix == ".py":
        transport_options["command"] = [
            python,
            "-m",
            "khaos.agent_runner",
            "--script",
            str(entrypoint_path),
        ]

    return transport_options
