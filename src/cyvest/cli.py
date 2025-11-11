"""
Click-based command-line interface for Cyvest.

Provides commands for managing investigations, displaying summaries,
and generating simple reports from serialized investigations.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from cyvest import __version__
from cyvest.io_rich import display_statistics, display_summary
from cyvest.io_serialization import load_investigation_json

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}
console = Console()


def _load_investigation(input_path: Path) -> dict[str, Any]:
    """Load a serialized investigation from disk."""
    with input_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _print_stats_overview(stats: dict[str, Any]) -> None:
    """Render a lightweight overview of statistics."""
    if not stats:
        console.print("  No statistics available.")
        return

    for key, value in stats.items():
        if isinstance(value, dict):
            continue
        console.print(f"  {key}: {value}")


def _write_markdown(data: dict[str, Any], output_path: Path) -> None:
    """Write a basic Markdown report derived from serialized data."""
    stats = data.get("stats", {})
    lines = [
        "# Investigation Report",
        "",
        f"**Score:** {data.get('score', 'N/A')}",
        f"**Level:** {data.get('level', 'N/A')}",
        "",
        "## Statistics",
        "",
    ]

    for key, value in stats.items():
        if isinstance(value, dict):
            continue
        lines.append(f"- **{key}:** {value}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, prog_name="Cyvest")
def cli() -> None:
    """Cyvest - Cybersecurity Investigation Framework."""


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--stats/--no-stats", default=False, help="Display statistics tables after the summary.")
@click.option(
    "--graph/--no-graph",
    default=True,
    show_default=True,
    help="Toggle observable graph rendering.",
)
def show(input: Path, stats: bool, graph: bool) -> None:
    """
    Display an investigation from a JSON file.
    """

    cv = load_investigation_json(input)
    display_summary(cv, console, show_graph=graph)

    if stats:
        console.print()
        display_statistics(cv, console)


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-d", "--detailed", is_flag=True, help="Show detailed breakdowns.")
def stats(input: Path, detailed: bool) -> None:
    """
    Display statistics for an investigation.
    """

    cv = load_investigation_json(input)
    console.print(f"[cyan]Statistics for: {input}[/cyan]\n")
    console.print("[bold]Overview:[/bold]")
    console.print(f"  Global Score: {cv.get_global_score()}")
    console.print(f"  Global Level: {cv.get_global_level()}")

    if detailed:
        console.print()
        display_statistics(cv, console)
    else:
        _print_stats_overview(cv.get_statistics())


@cli.command()
@click.argument("inputs", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
def merge(inputs: tuple[Path, ...], output: Path) -> None:
    """
    Merge multiple investigations together (placeholder).
    """

    if len(inputs) < 2:
        raise click.BadParameter("Provide at least two input files.", param_hint="inputs")

    console.print(f"[cyan]Merging {len(inputs)} investigation files...[/cyan]")
    console.print("[yellow]Merge functionality not yet implemented[/yellow]")
    console.print(f"[yellow]Requested output: {output}[/yellow]")


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "-f",
    "--format",
    "export_format",
    type=click.Choice(["json", "markdown"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format.",
)
def export(input: Path, output: Path, export_format: str) -> None:
    """
    Export an investigation to a different format.
    """

    data = _load_investigation(input)
    output_path = output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if export_format.lower() == "json":
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        console.print(f"[green]Exported to JSON: {output_path}[/green]")
        return

    _write_markdown(data, output_path)
    console.print(f"[green]Exported to Markdown: {output_path}[/green]")


def main() -> None:
    """Entry point used by the console script."""
    cli()


if __name__ == "__main__":
    main()
