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
from logurich.opt_click import click_logger_params
from rich.console import Console

from cyvest import __version__
from cyvest.io_schema import get_investigation_schema
from cyvest.io_serialization import load_investigation_json
from cyvest.io_visualization import VisualizationDependencyMissingError

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
    score_value = data.get("score", None)
    try:
        score_display = "N/A" if score_value is None else f"{float(score_value):.2f}"
    except (TypeError, ValueError):
        score_display = str(score_value)
    lines = [
        "# Investigation Report",
        "",
        f"**Score:** {score_display}",
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
@click_logger_params
@click.version_option(__version__, prog_name="Cyvest")
def cli() -> None:
    """Cyvest - Cybersecurity Investigation Framework."""
    logger.enable("cyvest")
    logger.info("> [green bold]CYVEST[/green bold]")


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
    cv.display_summary(show_graph=graph)

    if stats:
        logger.info("")
        cv.display_statistics()


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-d", "--detailed", is_flag=True, help="Show detailed breakdowns.")
def stats(input: Path, detailed: bool) -> None:
    """
    Display statistics for an investigation.
    """

    cv = load_investigation_json(input)
    logger.info(f"[cyan]Statistics for: {input}[/cyan]")
    logger.info("[bold]Overview:[/bold]")
    logger.info("  Global Score: {}", f"{cv.get_global_score():.2f}")
    logger.info("  Global Level: {}", cv.get_global_level())

    if detailed:
        logger.info("")
        cv.display_statistics()
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
        logger.info(f"  Total Observables: {investigation_stats.total_observables}")
        logger.info(f"  Total Checks: {investigation_stats.total_checks}")
        logger.info(f"  Total Threat Intel: {investigation_stats.total_threat_intel}")
        logger.info(f"  Total Containers: {investigation_stats.total_containers}")
        logger.info(f"  Global Score: {main_investigation.get_global_score():.2f}")
        logger.info(f"  Global Level: {main_investigation.get_global_level()}\n")

    # Save merged investigation
    output_path = output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        main_investigation.io_save_json(str(output_path))
        logger.info(f"[green]✓ Saved merged investigation to: {output_path}[/green]")
    elif output_format == "rich":
        # Display rich summary
        logger.info("[bold]Merged Investigation Summary:[/bold]\n")
        main_investigation.display_summary(show_graph=True)
        # Also save as JSON
        json_output = output_path.with_suffix(".json")
        main_investigation.io_save_json(str(json_output))
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


@cli.command(name="schema")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the JSON Schema to a file instead of stdout.",
)
def schema_cmd(output: Path | None) -> None:
    """
    Emit the JSON Schema describing serialized investigations.
    """
    schema = get_investigation_schema()
    if output:
        output_path = output.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        logger.info(f"[green]Schema written to: {output_path}[/green]")
        return

    logger.rich("INFO", json.dumps(schema, indent=2), prefix=False)


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to save HTML file (defaults to temporary directory).",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Do not automatically open the visualization in a browser.",
)
@click.option(
    "--min-level",
    type=click.Choice(["TRUSTED", "INFO", "SAFE", "NOTABLE", "SUSPICIOUS", "MALICIOUS"], case_sensitive=False),
    help="Minimum security level to include in the visualization.",
)
@click.option(
    "--types",
    help="Comma-separated list of observable types to include (e.g., 'ipv4,domain,url').",
)
@click.option(
    "--title",
    default="Cyvest Investigation Network",
    show_default=True,
    help="Title for the network graph.",
)
@click.option(
    "--physics",
    is_flag=True,
    help="Enable physics simulation for organic layout (default: static layout).",
)
@click.option(
    "--group-by-type",
    is_flag=True,
    help="Group observables by type using hierarchical layout.",
)
def visualize(
    input: Path,
    output_dir: Path | None,
    no_browser: bool,
    min_level: str | None,
    types: str | None,
    title: str,
    physics: bool,
    group_by_type: bool,
) -> None:
    """
    Generate an interactive network graph visualization of an investigation.

    This command creates an HTML file with a pyvis network graph showing
    observables as nodes (colored by level, sized by score, shaped by type)
    and relationships as edges (colored by direction, labeled by type).

    The visualization is saved to a temporary directory by default, or to
    the specified output directory. The HTML file automatically opens in
    your default browser unless --no-browser is specified.
    """
    from cyvest.levels import Level
    from cyvest.model_enums import ObservableType

    cv = load_investigation_json(input)

    # Parse min_level if provided
    min_level_enum = None
    if min_level is not None:
        min_level_enum = Level[min_level.upper()]

    # Parse observable types if provided
    observable_types = None
    if types is not None:
        parsed_types: list[ObservableType] = []
        for token in types.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                parsed_types.append(ObservableType(token.lower()))
            except ValueError:
                try:
                    parsed_types.append(ObservableType[token.upper()])
                except KeyError as exc:
                    raise click.ClickException(f"Unknown observable type: {token}") from exc
        observable_types = parsed_types or None

    # Convert output_dir to string if provided
    output_dir_str = str(output_dir.resolve()) if output_dir is not None else None

    # Generate visualization
    logger.info(f"[cyan]Generating network visualization for: {input}[/cyan]")

    try:
        html_path = cv.display_network(
            output_dir=output_dir_str,
            open_browser=not no_browser,
            min_level=min_level_enum,
            observable_types=observable_types,
            title=title,
            physics=physics,
            group_by_type=group_by_type,
        )
    except VisualizationDependencyMissingError as exc:
        raise click.ClickException(str(exc)) from exc

    logger.info(f"[green]✓ Visualization saved to: {html_path}[/green]")

    if not no_browser:
        logger.info("[cyan]Opening visualization in browser...[/cyan]")


def main() -> None:
    """Entry point used by the console script."""
    cli()


if __name__ == "__main__":
    main()
