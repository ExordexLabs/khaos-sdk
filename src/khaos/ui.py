"""
Khaos CLI UI Module
Provides reusable UI components for consistent CLI output.

All components use the shared console from khaos.cli.console.
"""

from typing import Any
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# Import shared console - single source of truth for theming
from khaos.cli.console import console, KHAOS_THEME

# --- Components ---

def print_header(text: str, subtitle: str | None = None) -> None:
    """Renders a full-width styled header."""
    console.print()
    grid = Table.grid(expand=True)
    grid.add_column(justify="left")
    grid.add_column(justify="right")
    
    title = Text(f" {text} ", style="bold white on dodger_blue2")
    sub = Text(f" {subtitle} " if subtitle else "", style="dim cyan")
    
    grid.add_row(title, sub)
    console.print(Panel(grid, style="panel.border", box=box.HEAVY_EDGE, padding=(0, 0)))
    console.print()

def print_step(text: str) -> None:
    """Renders a step in a process."""
    console.print(f"[bold cyan]➜[/bold cyan]  {text}")

def print_success(text: str) -> None:
    """Renders a success message."""
    console.print(f"[success]✔[/success]  {text}")

def print_error(text: str) -> None:
    """Renders an error message."""
    console.print(f"[error]✘  {text}[/error]")

def print_warning(text: str) -> None:
    """Renders a warning message."""
    console.print(f"[warning]⚠  {text}[/warning]")

def print_info(key: str, value: Any) -> None:
    """Renders a key-value pair."""
    console.print(f"[dim]•[/dim] [label]{key}:[/label] [value]{value}[/value]")

def create_table(title: str = "", **kwargs) -> Table:
    """Returns a Table pre-configured with the vintage style."""
    return Table(
        title=title,
        box=box.SIMPLE_HEAVY,
        header_style="table.header",
        border_style="table.border",
        title_style="bold cyan",
        **kwargs
    )

def print_panel(content: Any, title: str | None = None, style: str = "panel.border") -> None:
    """Renders content within a styled panel."""
    console.print(Panel(content, title=title, style=style, box=box.ROUNDED, padding=(1, 2)))

def print_logo(compact: bool = False) -> None:
    """Renders the KHAOS logo.

    Args:
        compact: If True, shows minimal one-line branding instead of full logo.
    """
    if compact:
        console.print()
        console.print("[bold cyan]khaos[/bold cyan] [dim]· agent testing platform[/dim]")
        console.print()
        return

    # Clean ASCII logo - simple and readable
    lines = [
        "  _  __ _   _    _     ___   ____  ",
        " | |/ /| | | |  / \\   / _ \\ / ___| ",
        " | ' / | |_| | / _ \\ | | | |\\___ \\ ",
        " | . \\ |  _  |/ ___ \\| |_| | ___) |",
        " |_|\\_\\|_| |_/_/   \\_\\\\___/ |____/ ",
    ]
    console.print()
    for line in lines:
        console.print(f"[bold cyan]{line}[/bold cyan]")
    console.print()
    console.print("[dim]Agent Testing & Observability Platform[/dim]")
    console.print()

from contextlib import contextmanager
from typing import Generator

@contextmanager
def animate_ordo_ring(status_text: str) -> Generator[None, None, None]:
    """Displays a custom 'Ordo Ring' spinner animation."""
    # Using 'dots12' as it closely resembles a rotating ring/scanner
    with console.status(f"[bold cyan]{status_text}[/bold cyan]", spinner="dots12", spinner_style="cyan") as status:
        yield

def print_section(text: str, icon: str = "") -> None:
    """Renders a section header within a flow."""
    console.print()
    if icon:
        console.print(f"[bold cyan]{icon} {text}[/bold cyan]")
    else:
        console.print(f"[bold cyan]{text}[/bold cyan]")


def render_gauge(value: float, max_val: float = 100.0, width: int = 20) -> Text:
    """Visual score bar with gradient coloring.

    Returns a Rich Text object like: ████████████████░░░░  90% (A)
    """
    pct = max(0.0, min(1.0, value / max_val)) if max_val > 0 else 0.0
    filled = int(pct * width)
    empty = width - filled

    # Pick color based on percentage
    if pct >= 0.9:
        fill_style = "gauge.excellent"
    elif pct >= 0.75:
        fill_style = "gauge.good"
    elif pct >= 0.6:
        fill_style = "gauge.fair"
    else:
        fill_style = "gauge.poor"

    # Letter grade
    if pct >= 0.9:
        grade = "A"
    elif pct >= 0.8:
        grade = "B"
    elif pct >= 0.7:
        grade = "C"
    elif pct >= 0.6:
        grade = "D"
    else:
        grade = "F"

    bar = Text()
    bar.append("█" * filled, style=fill_style)
    bar.append("░" * empty, style="gauge.empty")
    bar.append(f"  {pct:.0%} ({grade})", style="dim")
    return bar


def render_progress_bar(completed: int, total: int, width: int = 20) -> Text:
    """Progress bar for active operations.

    Returns a Rich Text like: ████████████░░░░░░░░  12/20
    """
    pct = max(0.0, min(1.0, completed / total)) if total > 0 else 0.0
    filled = int(pct * width)
    empty = width - filled

    bar = Text()
    bar.append("█" * filled, style="info")
    bar.append("░" * empty, style="gauge.empty")
    bar.append(f"  {completed}/{total}", style="dim")
    return bar


def print_section_header(text: str) -> None:
    """Branded section divider using Rich Rule."""
    from rich.rule import Rule
    console.print(Rule(title=text, style="rule", align="left"))


def print_error_panel(message: str, suggestion: str | None = None, details: str | None = None) -> None:
    """Error in a bordered panel with optional suggestion."""
    from rich.text import Text as RichText

    body = RichText()
    body.append(message)

    if suggestion:
        body.append("\n\n")
        body.append("💡 ", style="dim")
        body.append(suggestion, style="tip.title")

    console.print(Panel(
        body,
        title="Error",
        title_align="left",
        border_style="error.border",
        box=box.ROUNDED,
        padding=(1, 2),
    ))

    if details:
        console.print(f"[dim]Details: {details}[/dim]")


def print_verdict_banner(passed: bool, score: float, grade: str, subtitle: str | None = None) -> None:
    """Eye-catching verdict display with colored border."""
    if passed:
        icon = "✓"
        label = "EVALUATION PASSED"
        border = "green"
    else:
        icon = "✗"
        label = "EVALUATION FAILED"
        border = "red"

    content = Text(justify="center")
    content.append(f"{icon}  {label}\n", style=f"bold {border}")
    content.append(f"Score: {score:.0f}/100 ({grade})", style="dim")

    if subtitle:
        content.append(f"\n{subtitle}", style="dim")

    console.print(Panel(
        content,
        border_style=border,
        box=box.ROUNDED,
        padding=(1, 2),
    ))


def print_branded_header(subtitle: str | None = None) -> None:
    """Compact branded line for command startup."""
    line = Text()
    line.append("khaos", style="brand")
    line.append(" ── ", style="brand.dim")
    line.append(subtitle or "agent testing platform", style="brand.dim")
    console.print(line)


def print_divider(width: int = 50) -> None:
    """Renders a subtle horizontal divider."""
    console.print(f"[dim]{'─' * width}[/dim]")


def print_tip(text: str) -> None:
    """Renders an inline tip with lightbulb icon."""
    console.print(f"[dim]💡 Tip:[/dim] [italic dim]{text}[/italic dim]")

def print_example(code: str, language: str = "") -> None:
    """Renders a code example with proper styling."""
    from rich.syntax import Syntax
    if language:
        syntax = Syntax(code, language, theme="monokai", background_color="default")
        console.print(syntax)
    else:
        console.print(f"[dim]Example:[/dim] [white]{code}[/white]")
