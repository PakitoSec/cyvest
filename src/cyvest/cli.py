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
from logurich import logger
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
        logger.info("  No statistics available.")
        return

    for key, value in stats.items():
        if isinstance(value, dict):
            continue
        logger.info("  {}: {}", key, value)


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
        logger.info("")
        display_statistics(cv, console)


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-d", "--detailed", is_flag=True, help="Show detailed breakdowns.")
def stats(input: Path, detailed: bool) -> None:
    """
    Display statistics for an investigation.
    """

    cv = load_investigation_json(input)
    logger.info(f"[cyan]Statistics for: {input}[/cyan]\n")
    logger.info("[bold]Overview:[/bold]")
    logger.info("  Global Score: {}", cv.get_global_score())
    logger.info("  Global Level: {}", cv.get_global_level())

    if detailed:
        logger.info("")
        display_statistics(cv, console)
    else:
        _print_stats_overview(cv.get_statistics())


@cli.command()
@click.argument("inputs", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "rich"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Output format for merged investigation.",
)
@click.option(
    "--stats/--no-stats",
    default=True,
    show_default=True,
    help="Display merge statistics after merging.",
)
def merge(inputs: tuple[Path, ...], output: Path, output_format: str, stats: bool) -> None:
    """
    Merge multiple investigation JSON files into a single investigation.

    This command loads multiple investigation files and merges them together,
    automatically handling duplicate objects and score propagation.
    The merged investigation is saved to the specified output file.
    """
    from cyvest.io_serialization import save_investigation_json

    if len(inputs) < 2:
        raise click.BadParameter("Provide at least two input files.", param_hint="inputs")

    logger.info(f"[cyan]Merging {len(inputs)} investigation files...[/cyan]")

    # Load first investigation
    logger.info(f"  Loading: {inputs[0]}")
    main_investigation = load_investigation_json(inputs[0])

    # Merge all other investigations
    for input_path in inputs[1:]:
        logger.info(f"  Loading: {input_path}")
        other_investigation = load_investigation_json(input_path)
        logger.info(f"  Merging: {input_path.name}")
        main_investigation.merge_investigation(other_investigation)

    logger.info("[green]✓ Merge complete[/green]\n")

    # Display statistics if requested
    if stats:
        logger.info("[bold]Merged Investigation Statistics:[/bold]")
        investigation_stats = main_investigation.get_statistics()
        logger.info(f"  Total Observables: {investigation_stats.get('total_observables', 0)}")
        logger.info(f"  Total Checks: {investigation_stats.get('total_checks', 0)}")
        logger.info(f"  Total Threat Intel: {investigation_stats.get('total_threat_intel', 0)}")
        logger.info(f"  Total Containers: {investigation_stats.get('total_containers', 0)}")
        logger.info(f"  Global Score: {main_investigation.get_global_score()}")
        logger.info(f"  Global Level: {main_investigation.get_global_level()}\n")

    # Save merged investigation
    output_path = output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        save_investigation_json(main_investigation, str(output_path))
        logger.info(f"[green]✓ Saved merged investigation to: {output_path}[/green]")
    elif output_format == "rich":
        # Display rich summary
        logger.info("[bold]Merged Investigation Summary:[/bold]\n")
        main_investigation.display_summary(show_graph=True)
        # Also save as JSON
        json_output = output_path.with_suffix(".json")
        save_investigation_json(main_investigation, str(json_output))
        logger.info(f"\n[green]✓ Saved merged investigation to: {json_output}[/green]")


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
        logger.info(f"[green]Exported to JSON: {output_path}[/green]")
        return

    _write_markdown(data, output_path)
    logger.info(f"[green]Exported to Markdown: {output_path}[/green]")


def main() -> None:
    """Entry point used by the console script."""
    cli()


if __name__ == "__main__":
    main()
