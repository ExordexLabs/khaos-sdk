"""Scenario management commands for the Khaos CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from khaos.chaos import (
    ChaosScenario,
    InvalidScenario,
    ScenarioMetadata,
    ScenarioRegistry,
    ScenarioValidationError,
    build_default_registry,
    load_scenario_from_yaml,
    scenario_document_schema,
)
from khaos.scenario_lint import (
    lint_scenario,
    lint_against_sample,
    load_sample,
    load_auto_sample_from_traces,
)
from khaos.ui import console, print_error, print_success

from ..constants import PROJECT_ROOT
from ..utils.config import resolve_cache_dir


# Sub-app for scenario browsing
scenarios_app = typer.Typer(help="Browse built-in scenarios.")


def _build_registry(scenarios_path: Path | None) -> ScenarioRegistry:
    """Build a scenario registry from the given path or defaults."""
    cache_dir = resolve_cache_dir()
    if scenarios_path is not None:
        return ScenarioRegistry([scenarios_path], cache_dir=cache_dir)
    return build_default_registry(PROJECT_ROOT, cache_dir=cache_dir)


def _filter_metadata(
    rows: list[ScenarioMetadata],
    *,
    tags: list[str],
    fault_types: list[str],
    query: str | None,
) -> list[ScenarioMetadata]:
    """Filter scenarios by tags, fault types, and search query."""
    if not rows:
        return []

    normalized_tags = set(tags)
    normalized_faults = set(fault_types)
    filtered: list[ScenarioMetadata] = []

    for metadata in rows:
        scenario_tags = {tag.lower() for tag in metadata.tags}
        if normalized_tags and not normalized_tags.issubset(scenario_tags):
            continue
        scenario_faults = {fault.lower() for fault in metadata.fault_types}
        if normalized_faults and not normalized_faults.issubset(scenario_faults):
            continue
        if query and query not in metadata.identifier.lower() and query not in metadata.summary.lower():
            continue
        filtered.append(metadata)

    if not filtered and not normalized_tags and not normalized_faults and query is None:
        return rows

    return filtered


def _sort_metadata(
    rows: list[ScenarioMetadata],
    *,
    sort_by: str,
    descending: bool,
) -> list[ScenarioMetadata]:
    """Sort scenarios by the specified field."""
    if sort_by not in {"identifier", "faults", "difficulty"}:
        raise ValueError("sort-by must be one of: identifier, faults, difficulty")

    if sort_by == "identifier":
        key_fn = lambda meta: meta.identifier.lower()
    elif sort_by == "faults":
        key_fn = lambda meta: meta.fault_count
    else:
        key_fn = lambda meta: meta.difficulty
    return sorted(rows, key=key_fn, reverse=descending)


def _paginate_metadata(
    rows: list[ScenarioMetadata],
    *,
    page: int,
    limit: int | None,
) -> list[ScenarioMetadata]:
    """Paginate scenario results."""
    if limit is None:
        return rows

    start = (page - 1) * limit
    if start >= len(rows):
        return []
    end = start + limit
    return rows[start:end]


def _render_invalid(entries: list[InvalidScenario]) -> None:
    """Display invalid scenarios found during discovery."""
    if not entries:
        console.print("[green]No invalid scenarios detected during discovery.[/green]")
        return

    console.print("[red]Invalid scenarios detected:[/red]")
    for entry in entries:
        console.print(f" - {entry.path.name} ({entry.path}): {entry.error}")


def list_scenarios(
    scenarios_path: Path | None = typer.Option(
        None,
        exists=True,
        dir_okay=True,
        file_okay=False,
        help="Override the default scenarios directory.",
    ),
    show_invalid: bool = typer.Option(
        False,
        "--show-invalid",
        help="Display scenarios that failed validation during discovery.",
    ),
    tag: list[str] = typer.Option(
        [],
        "--tag",
        help="Filter scenarios by one or more tags (case-insensitive, repeatable).",
    ),
    fault_type: list[str] = typer.Option(
        [],
        "--fault-type",
        help="Filter scenarios that include the specified fault type(s). Repeatable.",
    ),
    query: str | None = typer.Option(
        None,
        "--query",
        help="Substring filter applied to identifiers and summaries (case-insensitive).",
    ),
    limit: int | None = typer.Option(
        None,
        min=1,
        help="Maximum number of scenarios to display per page.",
    ),
    page: int = typer.Option(
        1,
        min=1,
        help="Page number (1-indexed) when limit is provided.",
    ),
    sort_by: str = typer.Option(
        "identifier",
        "--sort-by",
        case_sensitive=False,
        help="Sort results by field (identifier|faults|difficulty).",
    ),
    descending: bool = typer.Option(
        False,
        "--desc",
        help="Sort in descending order.",
    ),
) -> None:
    """List discoverable chaos scenarios from the configured workspace."""
    registry = _build_registry(scenarios_path)
    rows = registry.list_metadata()
    rows = _filter_metadata(
        rows,
        tags=[value.lower() for value in tag],
        fault_types=[value.lower() for value in fault_type],
        query=query.lower() if query else None,
    )
    try:
        rows = _sort_metadata(rows, sort_by=sort_by.lower(), descending=descending)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    total = len(rows)
    rows = _paginate_metadata(rows, page=page, limit=limit)

    if not rows:
        console.print("[yellow]No scenarios discovered for the supplied filters.[/yellow]")
        return

    table = Table(title="Discovered Scenarios")
    table.add_column("Identifier", style="cyan", no_wrap=True)
    table.add_column("Summary", style="white")
    table.add_column("Difficulty", style="magenta")
    table.add_column("Faults", justify="right")
    table.add_column("Fault Types", style="white")
    table.add_column("Tags", style="white")

    for metadata in rows:
        tags_display = ", ".join(metadata.tags) if metadata.tags else "-"
        fault_types_display = ", ".join(metadata.fault_types) if metadata.fault_types else "-"
        difficulty_display = f"{metadata.difficulty_label} ({metadata.difficulty:.2f})"
        table.add_row(
            metadata.identifier,
            metadata.summary,
            difficulty_display,
            str(metadata.fault_count),
            fault_types_display,
            tags_display,
        )

    console.print(table)
    if limit:
        start_idx = (page - 1) * limit + 1
        end_idx = start_idx + len(rows) - 1
        console.print(f"[dim]Showing {start_idx}-{end_idx} of {total} scenarios[/dim]")

    if show_invalid:
        _render_invalid(registry.invalid_entries)


def show_scenario(
    identifier: str = typer.Argument(..., help="Scenario identifier or YAML path."),
    scenarios_path: Path | None = typer.Option(
        None,
        exists=True,
        dir_okay=True,
        file_okay=False,
        help="Override the default scenarios directory.",
    ),
) -> None:
    """Display details for a scenario."""
    path = Path(identifier)
    if path.exists():
        scenario = load_scenario_from_yaml(path)
    else:
        registry = _build_registry(scenarios_path)
        scenario = registry.get(identifier)

    payload = scenario.to_payload()
    console.print_json(data=payload)


def validate_scenario(
    scenario_path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        help="Path to a scenario YAML file.",
    ),
) -> None:
    """Validate a scenario file and report status."""
    try:
        load_scenario_from_yaml(scenario_path)
    except ScenarioValidationError as exc:
        raise typer.BadParameter(str(exc)) from exc

    console.print(f"[green]Scenario {scenario_path.name} is valid.[/green]")


def scenario_lint(
    scenario_path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        help="Path to a scenario YAML file.",
    ),
    sample_json: Path | None = typer.Option(
        None,
        "--sample-json",
        help="Optional JSON file containing a sample agent payload for assertion path checks.",
    ),
    sample_inline: str | None = typer.Option(
        None,
        "--sample-inline",
        help="Inline JSON string containing a sample agent payload.",
    ),
    fail_on_warn: bool = typer.Option(
        True,
        "--fail-on-warn/--no-fail-on-warn",
        help="Exit non-zero when lint warnings are found.",
    ),
    sample_auto: bool = typer.Option(
        False,
        "--sample-auto",
        help="Attempt to load a sample payload from the latest transport.receive event in the state dir.",
    ),
) -> None:
    """Lint scenario compatibility and optional assertion paths against a sample payload."""
    scenario = load_scenario_from_yaml(scenario_path)
    warnings = lint_scenario(scenario)
    sample = load_sample(sample_json, sample_inline)
    if not sample and sample_auto:
        sample = load_auto_sample_from_traces()
    if sample:
        warnings.extend(lint_against_sample(scenario, sample))

    if warnings:
        print_error("Scenario lint warnings detected:")
        for warn in warnings:
            print_error("-", warn)
        if fail_on_warn:
            raise typer.Exit(code=1)
    else:
        print_success("Scenario lint passed with no warnings.")


def scenario_schema(
    output: Path | None = typer.Option(
        None,
        dir_okay=False,
        help="Optional path to write the JSON schema instead of printing.",
    )
) -> None:
    """Display or export the scenario JSON schema."""
    schema = scenario_document_schema()
    if output is not None:
        output.write_text(json.dumps(schema, indent=2, sort_keys=True))
        console.print(f"[green]Wrote scenario schema to {output}.[/green]")
    else:
        console.print_json(data=schema)


# For backwards compatibility with scenarios_app sub-command
@scenarios_app.command("list")
def scenarios_list_cmd() -> None:
    """List built-in scenarios (alias for list-scenarios)."""
    list_scenarios(
        scenarios_path=None,
        show_invalid=False,
        tag=[],
        fault_type=[],
        query=None,
        limit=None,
        page=1,
        sort_by="identifier",
        descending=False,
    )
