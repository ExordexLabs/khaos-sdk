"""CLI commands for browsing Khaos taxonomy surfaces, branches, and ideas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.table import Table

from khaos.cli.console import console
from khaos.taxonomy import (
    load_branches,
    load_ideas,
    load_mapping_decisions,
    resolve_taxonomy_root,
)


taxonomy_app = typer.Typer(
    help="Browse taxonomy roots, branches, ideas, and quick starter plans.",
    no_args_is_help=True,
)


def _idea_turns(idea: dict[str, Any]) -> tuple[int, int]:
    attack = idea.get("attack_program", {})
    if not isinstance(attack, dict):
        return 1, 1
    return int(attack.get("turns_min", 1)), int(attack.get("turns_max", 1))


def _load_catalogs(
    taxonomy_root: Path | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    root = resolve_taxonomy_root(taxonomy_root)
    try:
        branches_doc = load_branches(root)
        ideas_doc = load_ideas(root)
        decisions_doc = load_mapping_decisions(root)
    except FileNotFoundError as exc:
        raise typer.BadParameter(
            f"Could not load taxonomy catalog from {root}: missing {exc.filename}"
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive for malformed local files
        raise typer.BadParameter(f"Failed to load taxonomy catalog from {root}: {exc}") from exc
    return branches_doc, ideas_doc, decisions_doc, root


@taxonomy_app.command("roots")
def roots(
    taxonomy_root: Path | None = typer.Option(
        None,
        "--taxonomy-root",
        help="Optional taxonomy root directory (defaults to packaged catalog).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List top-level taxonomy surfaces."""
    branches_doc, _, _, root = _load_catalogs(taxonomy_root)
    roots_raw = branches_doc.get("roots")
    if not isinstance(roots_raw, list):
        raise typer.BadParameter("Invalid branches catalog: missing list field 'roots'.")

    rows: list[dict[str, str]] = []
    for entry in roots_raw:
        if not isinstance(entry, dict):
            continue
        rows.append(
            {
                "id": str(entry.get("id", "")),
                "title": str(entry.get("title", "")),
                "description": str(entry.get("description", "")),
            }
        )
    rows.sort(key=lambda x: x["id"])

    if json_output:
        typer.echo(json.dumps({"taxonomy_root": str(root), "roots": rows}, indent=2))
        return

    table = Table(title=f"Taxonomy Roots ({root})")
    table.add_column("Root", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Description", style="dim")
    for row in rows:
        table.add_row(row["id"], row["title"], row["description"])
    console.print(table)


@taxonomy_app.command("branches")
def branches(
    root: str | None = typer.Option(None, "--root", help="Filter by root surface."),
    taxonomy_root: Path | None = typer.Option(
        None,
        "--taxonomy-root",
        help="Optional taxonomy root directory (defaults to packaged catalog).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List taxonomy branches."""
    branches_doc, _, _, catalog_root = _load_catalogs(taxonomy_root)
    branches_raw = branches_doc.get("branches")
    if not isinstance(branches_raw, list):
        raise typer.BadParameter("Invalid branches catalog: missing list field 'branches'.")

    rows: list[dict[str, Any]] = []
    for entry in branches_raw:
        if not isinstance(entry, dict):
            continue
        branch_root = str(entry.get("root", ""))
        if root and root != branch_root:
            continue
        rows.append(
            {
                "id": str(entry.get("id", "")),
                "root": branch_root,
                "title": str(entry.get("title", "")),
                "objective": str(entry.get("objective", "")),
                "signals": [str(s) for s in entry.get("primary_failure_signals", [])],
            }
        )

    rows.sort(key=lambda x: (x["root"], x["id"]))
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "taxonomy_root": str(catalog_root),
                    "count": len(rows),
                    "branches": rows,
                },
                indent=2,
            )
        )
        return

    table = Table(title=f"Taxonomy Branches ({len(rows)})")
    table.add_column("Branch", style="cyan", no_wrap=True)
    table.add_column("Root", style="magenta")
    table.add_column("Objective", style="white")
    table.add_column("Primary Signals", style="dim")
    for row in rows:
        signals = ", ".join(row["signals"]) if row["signals"] else "-"
        table.add_row(row["id"], row["root"], row["objective"], signals)
    console.print(table)


@taxonomy_app.command("ideas")
def ideas(
    root: str | None = typer.Option(None, "--root", help="Filter by root surface."),
    branch: str | None = typer.Option(None, "--branch", help="Filter by branch ID."),
    capability: list[str] = typer.Option(
        [],
        "--capability",
        help="Filter ideas requiring these capabilities (repeatable).",
    ),
    signal: list[str] = typer.Option(
        [],
        "--signal",
        help="Filter ideas containing these failure signals (repeatable).",
    ),
    max_turns: int | None = typer.Option(
        None,
        "--max-turns",
        min=1,
        help="Filter ideas with turns_max <= value.",
    ),
    limit: int | None = typer.Option(
        50,
        "--limit",
        min=1,
        help="Maximum ideas to display.",
    ),
    taxonomy_root: Path | None = typer.Option(
        None,
        "--taxonomy-root",
        help="Optional taxonomy root directory (defaults to packaged catalog).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """List taxonomy ideas with practical filters."""
    _, ideas_doc, _, catalog_root = _load_catalogs(taxonomy_root)
    ideas_raw = ideas_doc.get("ideas")
    if not isinstance(ideas_raw, list):
        raise typer.BadParameter("Invalid ideas catalog: missing list field 'ideas'.")

    req_caps = {str(c).strip() for c in capability if str(c).strip()}
    req_signals = {str(s).strip() for s in signal if str(s).strip()}

    rows: list[dict[str, Any]] = []
    for entry in ideas_raw:
        if not isinstance(entry, dict):
            continue
        row_root = str(entry.get("root", ""))
        row_branch = str(entry.get("branch_id", ""))
        if root and row_root != root:
            continue
        if branch and row_branch != branch:
            continue

        caps = {str(c) for c in entry.get("required_capabilities", [])}
        signals = {str(s) for s in entry.get("failure_signals", [])}
        turns_min, turns_max = _idea_turns(entry)

        if req_caps and not req_caps.issubset(caps):
            continue
        if req_signals and not req_signals.issubset(signals):
            continue
        if max_turns is not None and turns_max > max_turns:
            continue

        rows.append(
            {
                "idea_id": str(entry.get("idea_id", "")),
                "title": str(entry.get("title", "")),
                "root": row_root,
                "branch_id": row_branch,
                "severity": str(entry.get("scoring", {}).get("severity", "")),
                "turns_min": turns_min,
                "turns_max": turns_max,
                "required_capabilities": sorted(caps),
                "failure_signals": sorted(signals),
            }
        )

    rows.sort(key=lambda x: (x["root"], x["branch_id"], x["turns_max"], x["idea_id"]))
    if limit is not None:
        rows = rows[:limit]

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "taxonomy_root": str(catalog_root),
                    "count": len(rows),
                    "ideas": rows,
                },
                indent=2,
            )
        )
        return

    table = Table(title=f"Taxonomy Ideas ({len(rows)})")
    table.add_column("Idea ID", style="cyan", no_wrap=True)
    table.add_column("Branch", style="magenta")
    table.add_column("Turns", justify="center")
    table.add_column("Severity", style="yellow")
    table.add_column("Title", style="white")
    for row in rows:
        turns = f"{row['turns_min']}-{row['turns_max']}"
        table.add_row(
            row["idea_id"],
            row["branch_id"],
            turns,
            row["severity"] or "-",
            row["title"],
        )
    console.print(table)


@taxonomy_app.command("explain")
def explain(
    idea_id: str = typer.Argument(..., help="Idea ID (for example: idea:model.instruction_override_direct)."),
    taxonomy_root: Path | None = typer.Option(
        None,
        "--taxonomy-root",
        help="Optional taxonomy root directory (defaults to packaged catalog).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Explain one idea and show why it maps to a branch."""
    branches_doc, ideas_doc, decisions_doc, catalog_root = _load_catalogs(taxonomy_root)
    ideas_raw = ideas_doc.get("ideas")
    branches_raw = branches_doc.get("branches")
    decisions_raw = decisions_doc.get("decisions")
    if not isinstance(ideas_raw, list) or not isinstance(branches_raw, list):
        raise typer.BadParameter("Invalid taxonomy catalog: expected ideas/branches lists.")

    idea = next(
        (x for x in ideas_raw if isinstance(x, dict) and str(x.get("idea_id", "")) == idea_id),
        None,
    )
    if idea is None:
        raise typer.BadParameter(f"Idea not found: {idea_id}")

    branch_id = str(idea.get("branch_id", ""))
    branch = next(
        (x for x in branches_raw if isinstance(x, dict) and str(x.get("id", "")) == branch_id),
        None,
    )

    decision = None
    if isinstance(decisions_raw, list):
        decision = next(
            (
                x
                for x in decisions_raw
                if isinstance(x, dict) and str(x.get("idea_id", "")) == idea_id
            ),
            None,
        )

    turns_min, turns_max = _idea_turns(idea)
    payload = {
        "taxonomy_root": str(catalog_root),
        "idea_id": idea_id,
        "title": str(idea.get("title", "")),
        "root": str(idea.get("root", "")),
        "branch_id": branch_id,
        "branch_objective": str(branch.get("objective", "")) if isinstance(branch, dict) else None,
        "idea_statement": str(idea.get("idea_statement", "")),
        "threat_hypothesis": str(idea.get("threat_hypothesis", "")),
        "failure_signals": [str(x) for x in idea.get("failure_signals", [])],
        "required_capabilities": [str(x) for x in idea.get("required_capabilities", [])],
        "turns": {"min": turns_min, "max": turns_max},
        "mapping_decision": decision,
    }

    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return

    console.print()
    console.print(f"[bold cyan]{payload['idea_id']}[/bold cyan]")
    console.print(f"[bold]{payload['title']}[/bold]")
    console.print(f"[dim]Root:[/dim] {payload['root']}")
    console.print(f"[dim]Branch:[/dim] {payload['branch_id']}")
    if payload["branch_objective"]:
        console.print(f"[dim]Objective:[/dim] {payload['branch_objective']}")
    console.print(f"[dim]Turns:[/dim] {turns_min}-{turns_max}")
    console.print(f"[dim]Signals:[/dim] {', '.join(payload['failure_signals'])}")
    console.print(f"[dim]Capabilities:[/dim] {', '.join(payload['required_capabilities'])}")
    console.print()
    console.print(payload["idea_statement"])
    console.print(f"[dim]{payload['threat_hypothesis']}[/dim]")

    if isinstance(decision, dict):
        console.print()
        console.print(
            f"[bold]Mapping:[/bold] status={decision.get('status')} "
            f"score={decision.get('primary_score')} "
            f"margin={decision.get('margin_to_second')}"
        )
        candidates = decision.get("same_root_candidates", [])
        if isinstance(candidates, list) and candidates:
            table = Table(title="Top Same-Root Candidates")
            table.add_column("Branch", style="cyan")
            table.add_column("Score", justify="right")
            table.add_column("Signals", justify="right")
            table.add_column("Capabilities", justify="right")
            table.add_column("Lexical", justify="right")
            for candidate in candidates[:5]:
                if not isinstance(candidate, dict):
                    continue
                components = candidate.get("components", {})
                table.add_row(
                    str(candidate.get("branch_id", "")),
                    f"{float(candidate.get('score', 0.0)):.3f}",
                    f"{float(components.get('signal_overlap', 0.0)):.3f}",
                    f"{float(components.get('capability_overlap', 0.0)):.3f}",
                    f"{float(components.get('lexical_overlap', 0.0)):.3f}",
                )
            console.print(table)


@taxonomy_app.command("starter-plan")
def starter_plan(
    root: list[str] = typer.Option(
        [],
        "--root",
        help="Restrict starter plan to one or more roots (repeatable).",
    ),
    per_branch: int = typer.Option(
        1,
        "--per-branch",
        min=1,
        help="Ideas per branch to include.",
    ),
    max_turns: int = typer.Option(
        2,
        "--max-turns",
        min=1,
        help="Only include ideas with turns_max <= this value.",
    ),
    limit: int | None = typer.Option(
        24,
        "--limit",
        min=1,
        help="Maximum total ideas to include.",
    ),
    taxonomy_root: Path | None = typer.Option(
        None,
        "--taxonomy-root",
        help="Optional taxonomy root directory (defaults to packaged catalog).",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Generate a concrete first-pass test plan instead of random test selection."""
    branches_doc, ideas_doc, _, catalog_root = _load_catalogs(taxonomy_root)
    branches_raw = branches_doc.get("branches")
    ideas_raw = ideas_doc.get("ideas")
    if not isinstance(branches_raw, list) or not isinstance(ideas_raw, list):
        raise typer.BadParameter("Invalid taxonomy catalog: expected ideas/branches lists.")

    selected_roots = {str(r).strip() for r in root if str(r).strip()}
    if not selected_roots:
        selected_roots = {
            str(entry.get("root", ""))
            for entry in branches_raw
            if isinstance(entry, dict)
        }

    branches = [
        entry
        for entry in branches_raw
        if isinstance(entry, dict) and str(entry.get("root", "")) in selected_roots
    ]
    branches.sort(key=lambda x: (str(x.get("root", "")), str(x.get("id", ""))))

    ideas_by_branch: dict[str, list[dict[str, Any]]] = {}
    for entry in ideas_raw:
        if not isinstance(entry, dict):
            continue
        turns_min, turns_max = _idea_turns(entry)
        if turns_max > max_turns:
            continue
        branch_id = str(entry.get("branch_id", ""))
        ideas_by_branch.setdefault(branch_id, []).append(entry)

    rows: list[dict[str, Any]] = []
    for branch_entry in branches:
        branch_id = str(branch_entry.get("id", ""))
        branch_ideas = ideas_by_branch.get(branch_id, [])
        branch_ideas.sort(
            key=lambda x: (
                _idea_turns(x)[1],
                _idea_turns(x)[0],
                str(x.get("title", "")),
                str(x.get("idea_id", "")),
            )
        )
        for idea in branch_ideas[:per_branch]:
            turns_min, turns_max = _idea_turns(idea)
            rows.append(
                {
                    "root": str(branch_entry.get("root", "")),
                    "branch_id": branch_id,
                    "branch_title": str(branch_entry.get("title", "")),
                    "idea_id": str(idea.get("idea_id", "")),
                    "idea_title": str(idea.get("title", "")),
                    "turns_min": turns_min,
                    "turns_max": turns_max,
                    "failure_signals": [str(x) for x in idea.get("failure_signals", [])],
                }
            )

    rows.sort(key=lambda x: (x["root"], x["branch_id"], x["turns_max"], x["idea_id"]))
    if limit is not None:
        rows = rows[:limit]

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "taxonomy_root": str(catalog_root),
                    "count": len(rows),
                    "starter_plan": rows,
                },
                indent=2,
            )
        )
        return

    table = Table(title=f"Starter Plan ({len(rows)} ideas)")
    table.add_column("Root", style="magenta")
    table.add_column("Branch", style="cyan")
    table.add_column("Idea ID", style="white", no_wrap=True)
    table.add_column("Turns", justify="center")
    table.add_column("Signals", style="dim")
    for row in rows:
        signals = ", ".join(row["failure_signals"]) if row["failure_signals"] else "-"
        table.add_row(
            row["root"],
            row["branch_id"],
            row["idea_id"],
            f"{row['turns_min']}-{row['turns_max']}",
            signals,
        )
    console.print(table)

    console.print(
        "[dim]Tip:[/dim] Use [cyan]khaos taxonomy explain <idea_id>[/cyan] to inspect "
        "why each test exists and what failure signal it validates."
    )


__all__ = ["taxonomy_app"]
