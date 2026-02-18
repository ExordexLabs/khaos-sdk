"""The `run` command - Execute agent with full evaluation.

This is the primary Khaos command. It runs an agent with:
- Automatic LLM telemetry capture (zero-code)
- Security attack testing (ON by default)
- Resilience evaluation
- Cost tracking

Usage:
    khaos run my-agent                    # Run by registered agent name
    khaos run my-agent --eval full-eval   # Comprehensive evaluation
    khaos run my-agent --eval baseline    # Baseline only (no faults/attacks)
    khaos run my-agent --inputs tests.yaml # Run baseline on custom inputs
    khaos run my-agent --eval full-eval --test math-reasoning  # Run single test
    khaos run my-agent --eval security --attack-id prompt_injection_directive_override  # Replay one attack
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer

from khaos.packs import get_builtin_pack, list_builtin_packs
from khaos.cli.console import console

from .run_packs import run_with_pack
from .discover import resolve_agent_target

@dataclass(frozen=True, slots=True)
class _CustomInputsSpec:
    items: list[Any]
    is_file: bool
    source: str


def _parse_attack_ids(values: list[str]) -> list[str]:
    """Normalize --attack-id values, supporting repeated flags or comma-separated IDs."""
    parsed: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for part in str(raw).split(","):
            attack_id = part.strip()
            if not attack_id or attack_id in seen:
                continue
            seen.add(attack_id)
            parsed.append(attack_id)
    return parsed


def _load_custom_inputs(spec: str) -> _CustomInputsSpec:
    """Load custom inputs from a raw prompt or a YAML/JSON file path.

    Accepted formats (file-based):
      - list[str]
      - list[dict] (expects one of: text/input/prompt/message/content)
      - {"inputs": [...]}
    """
    candidate = Path(spec)
    if candidate.exists() and candidate.is_file() and candidate.suffix.lower() in {".yaml", ".yml", ".json"}:
        try:
            if candidate.suffix.lower() in {".yaml", ".yml"}:
                import yaml

                data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
            else:
                data = json.loads(candidate.read_text(encoding="utf-8"))
        except Exception as exc:
            raise typer.BadParameter(f"Failed to parse inputs file '{candidate}': {exc}") from exc

        if data is None:
            return _CustomInputsSpec(items=[], is_file=True, source=str(candidate))
        if isinstance(data, list):
            return _CustomInputsSpec(items=data, is_file=True, source=str(candidate))
        if isinstance(data, dict) and "inputs" in data and isinstance(data["inputs"], list):
            return _CustomInputsSpec(items=data["inputs"], is_file=True, source=str(candidate))
        raise typer.BadParameter(
            f"Invalid inputs file format in '{candidate}'. Expected a list or a dict with an 'inputs' list."
        )

    return _CustomInputsSpec(items=[spec], is_file=False, source="raw")

def _as_pack_inputs(custom: _CustomInputsSpec) -> list["PackInput"]:
    """Convert loaded custom inputs into PackInput objects.

    Supports both single-turn and multi-turn inputs:
    - Single-turn: { "text": "...", "goal": {...} }
    - Multi-turn: { "messages": [...], "turn_goals": [...], "goal": {...} }
    """
    from khaos.packs import PackInput, GoalCriteria, PackMessage, FaultConfig

    def _parse_goal(goal_raw: dict | None) -> GoalCriteria | None:
        """Parse a goal dictionary into GoalCriteria."""
        if not isinstance(goal_raw, dict):
            return None
        allowed = {
            "contains",
            "contains_any",
            "contains_all",
            "not_contains",
            "min_length",
            "max_length",
            "matches_regex",
            "is_valid_json",
            "list_length",
        }
        return GoalCriteria(**{k: v for k, v in goal_raw.items() if k in allowed})

    def _parse_fault(fault_raw: dict) -> FaultConfig | None:
        """Parse a fault dictionary into FaultConfig."""
        if not isinstance(fault_raw, dict):
            return None
        fault_type = fault_raw.get("type")
        if not fault_type:
            return None
        return FaultConfig(
            type=str(fault_type),
            config=fault_raw.get("config", {}),
            probability=float(fault_raw.get("probability", 1.0)),
        )

    def _parse_message(msg_raw: dict) -> PackMessage | None:
        """Parse a message dictionary into PackMessage."""
        if not isinstance(msg_raw, dict):
            return None
        role = msg_raw.get("role", "user")
        content = msg_raw.get("content", "")
        if not content:
            return None
        faults = []
        for f in msg_raw.get("faults", []):
            parsed = _parse_fault(f)
            if parsed:
                faults.append(parsed)
        return PackMessage(role=str(role), content=str(content), faults=faults)

    pack_inputs: list[PackInput] = []
    for idx, item in enumerate(custom.items, start=1):
        if isinstance(item, str):
            # Simple string input
            text = item
            input_id = f"custom_{idx}"
            goal = None
            pack_inputs.append(PackInput(id=str(input_id), text=text, goal=goal))
            continue

        if not isinstance(item, dict):
            continue

        input_id = item.get("id") or f"custom_{idx}"

        # Check if this is a multi-turn input
        if "messages" in item and isinstance(item["messages"], list):
            # Multi-turn input
            messages = []
            for msg_raw in item["messages"]:
                parsed = _parse_message(msg_raw)
                if parsed:
                    messages.append(parsed)

            if not messages:
                continue

            # Parse turn_goals
            turn_goals = None
            turn_goals_raw = item.get("turn_goals")
            if isinstance(turn_goals_raw, list):
                turn_goals = []
                for tg in turn_goals_raw:
                    parsed_goal = _parse_goal(tg)
                    if parsed_goal:
                        turn_goals.append(parsed_goal)

            # Parse final goal
            goal_raw = item.get("goal") or item.get("expectation") or item.get("expect")
            goal = _parse_goal(goal_raw)

            pack_inputs.append(PackInput(
                id=str(input_id),
                messages=messages,
                turn_goals=turn_goals if turn_goals else None,
                goal=goal,
            ))
        else:
            # Single-turn input
            text = (
                item.get("text")
                or item.get("input")
                or item.get("prompt")
                or item.get("message")
                or item.get("content")
                or ""
            )
            goal_raw = item.get("goal") or item.get("expectation") or item.get("expect")
            goal = _parse_goal(goal_raw)

            if not isinstance(text, str) or not text.strip():
                continue

            pack_inputs.append(PackInput(id=str(input_id), text=text, goal=goal))

    return pack_inputs

def list_evals() -> None:
    """List available evaluations.

    Shows all built-in evals with their descriptions and estimated run times.
    """
    from rich.panel import Panel

    evals = list_builtin_packs()

    console.print("\n[bold cyan]Available Evaluations[/bold cyan]\n")

    for eval_name in evals:
        eval_config = get_builtin_pack(eval_name)
        phases = ", ".join(p.type.value for p in eval_config.phases)

        console.print(Panel(
            f"[dim]{eval_config.description}[/dim]\n\n"
            f"[cyan]Phases:[/cyan] {phases}\n"
            f"[cyan]Tests:[/cyan] {len(eval_config.inputs)} canonical prompts\n"
            f"[cyan]Time:[/cyan] {eval_config.estimated_time}",
            title=f"[bold]{eval_config.name}[/bold] v{eval_config.version}",
            subtitle=f"khaos run <agent-name> --eval {eval_config.name}",
            style="dim",
        ))
        console.print()

def run(
    target: str = typer.Argument(
        ...,
        help="Agent name (from `khaos discover`), optionally pinned as name@version.",
    ),
    # Evaluation selection
    eval_name: str | None = typer.Option(
        None,
        "--eval",
        "-e",
        help="Evaluation to run (quickstart, full-eval, security, baseline).",
    ),
    test: str | None = typer.Option(
        None,
        "--test",
        "-t",
        help="Run a specific test from the evaluation by its ID.",
    ),
    # Deprecated flags (hidden, for backward compatibility)
    pack: str | None = typer.Option(
        None,
        "--pack",
        "-p",
        hidden=True,
        help="[Deprecated] Use --eval instead.",
    ),
    scenario: str | None = typer.Option(
        None,
        "--scenario",
        "-s",
        hidden=True,
        help="[Deprecated] Scenarios are no longer supported. Use --eval instead.",
    ),
    quick: bool = typer.Option(
        False,
        "--quick",
        "-q",
        hidden=True,
        help="[Deprecated] Use --eval baseline instead.",
    ),
    # Security options (ON by default)
    security: bool = typer.Option(
        True,
        "--security/--no-security",
        help="Run security attack tests (default: ON).",
    ),
    attacks: Path | None = typer.Option(
        None,
        "--attacks",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Custom attack payloads YAML file.",
    ),
    attack_id: list[str] = typer.Option(
        [],
        "--attack-id",
        help="Run only specific security attack ID(s). Repeat or pass comma-separated values.",
    ),
    # Input options (custom prompts)
    inputs: str | None = typer.Option(
        None,
        "--input",
        "--inputs",
        "-i",
        help="Custom inputs: raw prompt string or path to YAML/JSON (list or {inputs:[...]}). "
        "When used with --eval, overrides the eval's built-in inputs.",
    ),
    # Output options
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show full debug output.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        help="Minimal output (errors only).",
    ),
    # Execution options
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        help="Maximum execution time in seconds.",
    ),
    env: list[str] = typer.Option(
        [],
        "--env",
        help="Environment variables (KEY=VALUE). Repeat for multiple.",
    ),
    python: str = typer.Option(
        sys.executable,
        "--python",
        help="Python interpreter to use.",
    ),
    # Run identification
    name: str | None = typer.Option(
        None,
        "--name",
        "-n",
        help="Name for this run (for easy identification in 'khaos compare').",
    ),
    # Advanced options (hidden by default)
    compare: str | None = typer.Option(
        None,
        "--compare",
        hidden=True,
        help="Baseline run ID to compare against.",
    ),
    sync_cloud: bool = typer.Option(
        False,
        "--sync",
        help="Sync results to the cloud dashboard (auto-login). Falls back to queue if upload fails.",
    ),
    seed: int | None = typer.Option(
        None,
        "--seed",
        help="Random seed for reproducibility. If not specified, a random seed is generated.",
    ),
    baseline_repeat: int | None = typer.Option(
        None,
        "--baseline-repeat",
        "--repeat",
        help="Number of baseline runs for consistency analysis (default: eval's setting). "
        "Use 2+ to calculate output consistency metrics.",
    ),
) -> None:
    """Run agent with full evaluation (security + resilience).

    By default, runs security attack tests and captures LLM telemetry.
    No configuration required - run by agent name after `khaos discover`.

    Examples:

        # Full evaluation with security (default: quickstart)
        khaos run my-agent

        # Run specific evaluation
        khaos run my-agent --eval full-eval

        # Run baseline only (no faults/attacks)
        khaos run my-agent --eval baseline

        # Run a single test from an evaluation
        khaos run my-agent --eval full-eval --test math-reasoning

        # Replay one security attack ID
        khaos run my-agent --eval security --attack-id prompt_injection_directive_override

        # Disable security tests
        khaos run my-agent --no-security

        # Pass environment variables
        khaos run my-agent --env OPENAI_API_KEY=sk-xxx
    """
    # Handle deprecated flags with warnings
    if scenario is not None:
        console.print(
            "[yellow]Warning: --scenario is deprecated and no longer supported. "
            "Use --eval instead.[/yellow]"
        )
        raise typer.Exit(code=1)

    if quick:
        console.print(
            "[yellow]Warning: --quick is deprecated. Use --eval baseline instead.[/yellow]"
        )
        eval_name = "baseline"

    # Handle --pack as alias for --eval (deprecated)
    if pack is not None:
        if eval_name is not None:
            raise typer.BadParameter("Cannot use both --pack and --eval. Use --eval (--pack is deprecated).")
        console.print(
            "[yellow]Warning: --pack is deprecated. Use --eval instead.[/yellow]"
        )
        eval_name = pack

    # Parse environment variables
    extra_env = {}
    for item in env:
        if "=" not in item:
            raise typer.BadParameter(f"Environment entry must be KEY=VALUE (got '{item}')")
        key, value = item.split("=", 1)
        extra_env[key] = value

    # Resolve agent name to entrypoint path + selector for protocol runner.
    target_path, agent_name = resolve_agent_target(target)
    extra_env["KHAOS_AGENT_HANDLER"] = agent_name

    loaded_inputs: _CustomInputsSpec | None = None
    if inputs:
        loaded_inputs = _load_custom_inputs(inputs)

    # If inputs are provided without an eval, run the baseline eval on those inputs.
    if eval_name is None and loaded_inputs is not None:
        eval_name = "baseline"

    # Default to quickstart if no eval specified
    if eval_name is None:
        eval_name = "quickstart"

    # Run evaluation
    custom_eval_inputs = _as_pack_inputs(loaded_inputs) if loaded_inputs is not None else None
    if loaded_inputs is not None and custom_eval_inputs is not None and not custom_eval_inputs:
        raise typer.BadParameter(f"No usable inputs found in '{inputs}'.")
    selected_attack_ids = _parse_attack_ids(attack_id)

    run_with_pack(
        target=str(target_path),
        pack_name=eval_name,
        pack_override=None,
        python=python,
        extra_env=extra_env,
        timeout=timeout,
        json_output=json_output,
        verbose=verbose,
        quiet=quiet,
        custom_inputs=custom_eval_inputs,
        custom_inputs_source=loaded_inputs.source if loaded_inputs is not None else None,
        sync_cloud=sync_cloud,
        name=name,
        test_filter=test,
        baseline_repeat=baseline_repeat,
        attack_ids=selected_attack_ids if selected_attack_ids else None,
    )
