"""
Command-line interface.

Every command that shows a number goes through the report, never through a stored field: the
serialized document carries a report, but a ``--engine`` override re-derives it, which is the
whole point of separating facts from evaluation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import click
from logurich import get_logger
from logurich.opt_click import click_logger_params
from pydantic import ValidationError
from rich.console import Console

from cyvest import __version__
from cyvest.compare import EngineMismatchError, ExpectedResult, compare_investigations
from cyvest.cyvest import Cyvest
from cyvest.enums import ObservableType
from cyvest.extract import (
    ExtractedObservable,
    extract_all,
    extract_from_url,
    observables_to_markdown,
    observables_to_markdown_table,
)
from cyvest.io_rich import display_diff
from cyvest.io_schema import get_investigation_schema, get_signal_schema
from cyvest.io_serialization import detect_schema_version, migrate_to_current
from cyvest.policy import DEFAULT_POLICY

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}
console = Console()
logger = get_logger(__name__)


def _read_json(path: Path) -> dict[str, Any]:
    """Read a JSON file, reporting a bad path or bad syntax as a clean CLI error."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise click.ClickException(f"Cannot read {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"{path} is not valid JSON: {exc}") from exc


def _prepare_output(path: Path) -> Path:
    """
    Resolve a destination and confirm it can be written, before the work that fills it runs.

    Both halves matter. ``mkdir`` creates a missing parent; the explicit probe catches a parent
    that exists but refuses writes, which ``mkdir(exist_ok=True)`` reports as success. Without it
    a read-only destination surfaced only at the final write, throwing away a whole merge.
    """
    resolved = Path(path).resolve()
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise click.ClickException(f"Cannot write to {resolved}: {exc.strerror or exc}") from exc
    if not os.access(resolved.parent, os.W_OK):
        raise click.ClickException(f"Cannot write to {resolved}: Permission denied")
    return resolved


def _write_json(data: dict[str, Any], path: Path) -> Path:
    """Write a JSON file, reporting an unwritable destination as a clean CLI error."""
    resolved = _prepare_output(path)
    try:
        resolved.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise click.ClickException(f"Cannot write to {resolved}: {exc.strerror or exc}") from exc
    return resolved


def _load_rules(path: Path) -> list[ExpectedResult]:
    """
    Read a tolerance-rules file.

    The shape is validated before splatting: a JSON object, or a list of anything but objects,
    would otherwise reach ``ExpectedResult(**rule)`` and surface as a ``TypeError`` traceback.
    """
    payload = _read_json(path)
    if not isinstance(payload, list) or not all(isinstance(rule, dict) for rule in payload):
        raise click.ClickException(f"{path} must contain a JSON list of rule objects.")
    try:
        return [ExpectedResult(**rule) for rule in payload]
    except ValidationError as exc:
        raise click.ClickException(f"Invalid rule in {path}: {exc}") from exc


def _open(path: Path, engine: str | None, *, migrate: bool = True) -> Cyvest:
    """
    Load an investigation, migrating older documents on the way in.

    Loading always drops the stored report and re-derives from the facts, so a hand-edited
    ``report`` block cannot mislead the CLI. ``--engine`` picks *which* engine does it, which is
    how you ask "what would this case look like under another one?" without touching the facts.
    """
    try:
        cv = Cyvest.io_load_json(path, migrate=migrate)
    except json.JSONDecodeError as exc:
        # Before ``ValueError``: ``JSONDecodeError`` subclasses it, and Python matches clauses in
        # order, so the broader one below would shadow this and report bad syntax unlabelled.
        raise click.ClickException(f"{path} is not valid JSON: {exc}") from exc
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    except OSError as exc:
        raise click.ClickException(f"Cannot read {path}: {exc.strerror or exc}") from exc
    if engine:
        # An unknown engine raises KeyError, which Click does not catch: a typo would otherwise
        # end in a traceback rather than the list of engines the user is asking for.
        try:
            cv.reevaluate(engine=engine)
        except KeyError as exc:
            raise click.ClickException(str(exc).strip("\"'")) from exc
    return cv


_engine_option = click.option(
    "--engine",
    default=None,
    help="Evaluate with this engine instead of the one recorded in the document header.",
)


@click.group(context_settings=CONTEXT_SETTINGS)
@click_logger_params
@click.version_option(__version__, prog_name="Cyvest")
def cli() -> None:
    """Cyvest - Cybersecurity Investigation Framework."""
    logger.info("> [green bold]CYVEST[/green bold]")


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--stats/--no-stats", default=False, help="Display statistics tables after the summary.")
@click.option("--graph/--no-graph", default=True, show_default=True, help="Toggle observable graph rendering.")
@_engine_option
def show(input: Path, stats: bool, graph: bool, engine: str | None) -> None:
    """Display an investigation from a JSON file."""
    cv = _open(input, engine)
    cv.display_summary(show_graph=graph)
    if stats:
        logger.info("")
        cv.display_statistics()


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-d", "--detailed", is_flag=True, help="Show detailed breakdowns.")
@_engine_option
def stats(input: Path, detailed: bool, engine: str | None) -> None:
    """Display statistics for an investigation."""
    cv = _open(input, engine)
    report = cv.get_report()
    logger.info(f"[cyan]Statistics for: {input}[/cyan]")
    logger.info("[bold]Overview:[/bold]")
    logger.info("  Engine:        %s", report.engine_id)
    logger.info("  Global score:  %.2f", cv.get_global_score())
    logger.info("  Global verdict: %s", cv.get_global_verdict().value)

    if detailed:
        logger.info("")
        cv.display_statistics()
        return

    statistics = cv.statistics()
    for key, value in statistics.model_dump(mode="json").items():
        if not isinstance(value, dict | list):
            logger.info("  %s: %s", key, value)


@cli.command(name="explain")
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("key")
@_engine_option
def explain_cmd(input: Path, key: str, engine: str | None) -> None:
    """
    Show how KEY got its score.

    KEY is an observable or a finding key, as it appears in the summary.
    """
    cv = _open(input, engine)
    try:
        cv.display_explanation(key)
    except KeyError as exc:
        raise click.ClickException(f"Unknown key: {key}") from exc


@cli.command(name="timeline")
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--time",
    "time_basis",
    type=click.Choice(["occurred", "asserted"], case_sensitive=False),
    default="occurred",
    show_default=True,
    help="Order by when things happened, or by when they were recorded.",
)
@click.option("--key-only", is_flag=True, help="Keep only entries marked as key moments.")
@_engine_option
def timeline_cmd(input: Path, time_basis: str, key_only: bool, engine: str | None) -> None:
    """Display the chronology of an investigation."""
    from cyvest.enums import Salience

    cv = _open(input, engine)
    kwargs: dict[str, Any] = {"time": time_basis}
    if key_only:
        kwargs["min_salience"] = Salience.KEY
    cv.display_timeline(**kwargs)


@cli.command(name="engines")
def engines_cmd() -> None:
    """List the registered engines and their aliases."""
    for name, target in sorted(Cyvest.ENGINES().items()):
        logger.info("  %s%s", name, "" if name == target else f" \u2192 {target}")


@cli.group(name="policy")
def policy_group() -> None:
    """Inspect scoring policies."""


@policy_group.command(name="show")
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=False)
def policy_show(input: Path | None) -> None:
    """
    Show the policy in effect.

    Without an argument, shows the default policy; with one, shows the policy version recorded in
    that investigation — a report is only reproducible against the policy that produced it.
    """
    if input is not None:
        data = _read_json(input)
        logger.info("  Policy version recorded in file: %s", data.get("policy_version", "unknown"))
        logger.info("  Engine recorded in file:         %s", data.get("engine_id", "unknown"))
        logger.info("")

    logger.rich("INFO", json.dumps(DEFAULT_POLICY.model_dump(mode="json"), indent=2), prefix=False)


@cli.command()
@click.argument("inputs", nargs=-1, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--stats/--no-stats", default=True, show_default=True, help="Display statistics after merging.")
@_engine_option
def merge(inputs: tuple[Path, ...], output: Path, stats: bool, engine: str | None) -> None:
    """
    Merge investigation files into one.

    Merging is a union of facts, so it is idempotent and order-independent; conflicting assertions
    about the same fact are settled by freshness, which means a score can go down.
    """
    if len(inputs) < 2:
        raise click.BadParameter("Provide at least two input files.", param_hint="inputs")

    # Checked up front: a missing parent directory would otherwise surface only after the whole
    # merge has run, throwing the result away.
    output = _prepare_output(output)

    logger.info(f"[cyan]Merging {len(inputs)} investigation files...[/cyan]")
    logger.info(f"  Loading: {inputs[0]}")
    merged = _open(inputs[0], engine)

    for input_path in inputs[1:]:
        logger.info(f"  Merging: {input_path}")
        merged.merge_investigation(_open(input_path, engine))

    logger.info("[green]\u2713 Merge complete[/green]\n")

    if stats:
        statistics = merged.statistics()
        logger.info("[bold]Merged investigation:[/bold]")
        logger.info(f"  Observables:    {statistics.total_observables}")
        logger.info(f"  Findings:       {statistics.total_findings}")
        logger.info(f"  Signals:        {statistics.total_signals}")
        logger.info(f"  Tags:           {statistics.total_tags}")
        logger.info(f"  Global score:   {merged.get_global_score():.2f}")
        logger.info(f"  Global verdict: {merged.get_global_verdict().value}\n")

    saved = merged.io_save_json(output)
    logger.info(f"[green]\u2713 Saved merged investigation to: {saved}[/green]")


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
@_engine_option
def export(input: Path, output: Path, export_format: str, engine: str | None) -> None:
    """Export an investigation to another format."""
    output = _prepare_output(output)
    cv = _open(input, engine)
    if export_format.lower() == "json":
        saved = cv.io_save_json(output)
        logger.info(f"[green]Exported to JSON: {saved}[/green]")
        return

    cv.io_save_markdown(output)
    logger.info(f"[green]Exported to Markdown: {output}[/green]")


@cli.command(name="schema")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the JSON Schema to a file instead of stdout.",
)
@click.option(
    "--which",
    type=click.Choice(["investigation", "signal"], case_sensitive=False),
    default="investigation",
    show_default=True,
    help="The serialized investigation, or the contract for ingesting an external signal.",
)
def schema_cmd(output: Path | None, which: str) -> None:
    """Emit a JSON Schema."""
    schema = get_signal_schema() if which == "signal" else get_investigation_schema()
    if output:
        written = _write_json(schema, output)
        logger.info(f"[green]Schema written to: {written}[/green]")
        return

    logger.rich("INFO", json.dumps(schema, indent=2), prefix=False)


@cli.command()
@click.argument("input", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--from",
    "from_version",
    default="auto",
    show_default=True,
    help="Source schema version, or 'auto' to detect it.",
)
def migrate(input: Path, output: Path, from_version: str) -> None:
    """
    Migrate an older investigation to the current schema.

    Migration is a chain of dict-to-dict steps, so a 5.x document reaches the current version by
    passing through every intermediate one.
    """
    source = _read_json(input)
    detected = detect_schema_version(source)
    if from_version != "auto" and not detected.startswith(from_version.split(".")[0]):
        raise click.ClickException(f"File looks like schema {detected}, not {from_version}.")

    logger.info("  Detected schema version: %s", detected)
    try:
        migrated = migrate_to_current(source)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    written = _write_json(migrated, output)
    logger.info(f"[green]Migrated investigation written to: {written}[/green]")


@cli.command()
@click.argument("actual", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("expected", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-r",
    "--rules",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON file with ExpectedResult tolerance rules.",
)
@click.option("--title", default="Investigation Diff", show_default=True, help="Title for the diff table.")
@_engine_option
def diff(actual: Path, expected: Path, rules: Path | None, title: str, engine: str | None) -> None:
    """
    Compare two investigation files.

    ACTUAL is the investigation under test, EXPECTED the reference. A rules file may loosen the
    comparison to a band rather than an exact value:

    \b
    [
      {"rule_id": "domain-reputation", "score": ">= 1.0"},
      {"key": "fnd:ai-analysis:obs:url:...", "verdict": "SUSPICIOUS", "score": "< 3.0"}
    ]

    Supported operators: >=, <=, >, <, ==, !=
    """
    logger.info("[cyan]Comparing investigations...[/cyan]")
    logger.info(f"  Actual:   {actual}")
    logger.info(f"  Expected: {expected}")

    actual_cv = _open(actual, engine)
    expected_cv = _open(expected, engine)

    result_expected: list[ExpectedResult] | None = None
    if rules:
        logger.info(f"  Rules:    {rules}")
        result_expected = _load_rules(rules)

    logger.info("")

    try:
        diffs = compare_investigations(actual_cv, expected_cv, result_expected=result_expected)
    except EngineMismatchError as exc:
        raise click.ClickException(f"{exc} Pass --engine to re-evaluate both with the same one.") from exc

    if not diffs:
        logger.info("[green]\u2713 No differences found[/green]")
        return

    display_diff(diffs, lambda renderable: logger.rich("INFO", renderable, width=150), title=title)


# =============================================================================
# Extract Command
# =============================================================================

_EXTRACT_TYPE_CHOICES = ["url", "ip", "ipv4", "ipv6", "email", "hash", "domain", "all"]


def _parse_extract_types(types: tuple[str, ...]) -> set[ObservableType] | None:
    """Parse extract type choices into ObservableType set."""
    if "all" in types or not types:
        return None  # None means all types

    result: set[ObservableType] = set()
    for t in types:
        t_lower = t.lower()
        if t_lower == "ip":
            result.add(ObservableType.IPV4)
            result.add(ObservableType.IPV6)
        elif t_lower == "ipv4":
            result.add(ObservableType.IPV4)
        elif t_lower == "ipv6":
            result.add(ObservableType.IPV6)
        elif t_lower == "url":
            result.add(ObservableType.URL)
        elif t_lower == "email":
            result.add(ObservableType.EMAIL)
        elif t_lower == "hash":
            result.add(ObservableType.HASH)
        elif t_lower == "domain":
            result.add(ObservableType.DOMAIN)
    return result if result else None


def _format_observables(
    observables: list[ExtractedObservable],
    output_format: str,
    *,
    group_by_type: bool = False,
    include_original: bool = False,
    defang_output: bool = False,
    title: str | None = None,
) -> str:
    """Format extracted observables for output."""
    import json as json_module

    if output_format == "json":
        return json_module.dumps(
            [obs.model_dump(mode="json", exclude_none=True) for obs in observables],
            indent=2,
            ensure_ascii=False,
        )
    elif output_format == "markdown":
        return observables_to_markdown(
            observables,
            include_original=include_original,
            group_by_type=group_by_type,
            title=title,
            defang_values=defang_output,
        )
    elif output_format == "markdown-table":
        return observables_to_markdown_table(
            observables,
            title=title,
            defang_values=defang_output,
        )
    else:
        # Text format: one per line, with type prefix
        lines = []
        for obs in observables:
            lines.append(f"{obs.obs_type}\t{obs.value}")
        return "\n".join(lines)


@cli.command()
@click.argument("input", type=click.File("r", encoding="utf-8"), default="-", required=False)
@click.option(
    "-t",
    "--types",
    multiple=True,
    type=click.Choice(_EXTRACT_TYPE_CHOICES, case_sensitive=False),
    default=["all"],
    show_default=True,
    help="Types of observables to extract. Can be specified multiple times.",
)
@click.option(
    "-r/-R",
    "--refang/--no-refang",
    default=True,
    show_default=True,
    help="Refang extracted observables (convert hxxp to http, [.] to ., etc.).",
)
@click.option(
    "-o",
    "--output",
    type=click.File("w", encoding="utf-8"),
    default="-",
    help="Output file (defaults to stdout).",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "markdown", "markdown-table"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format. Use 'markdown' or 'markdown-table' for LLM-friendly output.",
)
@click.option(
    "--from-url",
    "from_url",
    type=str,
    help="Fetch content from URL and extract observables (ignores INPUT argument).",
)
@click.option(
    "--group-by-type",
    is_flag=True,
    default=False,
    help="Group observables by type in markdown output.",
)
@click.option(
    "--include-original",
    is_flag=True,
    default=False,
    help="Include original (defanged) text in markdown output.",
)
@click.option(
    "--defang-output",
    is_flag=True,
    default=False,
    help="Defang values in output for safe sharing (markdown formats only).",
)
@click.option(
    "--title",
    type=str,
    default=None,
    help="Title header for markdown output.",
)
def extract(
    input,
    types: tuple[str, ...],
    refang: bool,
    output,
    output_format: str,
    from_url: str | None,
    group_by_type: bool,
    include_original: bool,
    defang_output: bool,
    title: str | None,
) -> None:
    """
    Extract observables (IOCs) from text input.

    Reads from stdin by default, or from a file if INPUT is specified.
    Use --from-url to fetch and extract from a web page.

    Supported observable types:
    - url: URLs (http, https, ftp, sftp, tcp, udp) including encoded
    - ip/ipv4/ipv6: IP addresses
    - email: Email addresses
    - hash: MD5, SHA1, SHA256, SHA512 hashes
    - domain: Domain names

    Supports defanged indicators (hxxp://, [.], [@], etc.) with automatic refanging.

    \b
    Examples:
        cat report.txt | cyvest extract
        cyvest extract report.txt -t url -t email
        cyvest extract -t ip --format json < input.txt
        cyvest extract --from-url https://example.com/iocs.txt -o extracted.txt
        cyvest extract report.txt --format markdown --group-by-type --title "IOCs"
        cyvest extract report.txt --format markdown-table --defang-output
    """
    observable_types = _parse_extract_types(types)

    try:
        if from_url:
            logger.info(f"[cyan]Fetching content from: {from_url}[/cyan]")
            observables = extract_from_url(
                from_url,
                types=observable_types,
                refang_output=refang,
            )
        else:
            text = input.read()
            observables = extract_all(
                text,
                types=observable_types,
                refang_output=refang,
            )
    except Exception as exc:
        raise click.ClickException(f"Extraction failed: {exc}") from exc

    if not observables:
        logger.info("[yellow]No observables found.[/yellow]")
        return

    logger.info(f"[green]✓ Extracted {len(observables)} observable(s)[/green]")

    formatted = _format_observables(
        observables,
        output_format,
        group_by_type=group_by_type,
        include_original=include_original,
        defang_output=defang_output,
        title=title,
    )

    # Use Rich Markdown rendering for markdown formats when outputting to stdout
    if output.name == "<stdout>" and output_format in ("markdown", "markdown-table"):
        from rich.markdown import Markdown

        logger.rich("INFO", Markdown(formatted), prefix=False)
    else:
        output.write(formatted)
        if not formatted.endswith("\n"):
            output.write("\n")


def main() -> None:
    """Entry point used by the console script."""
    cli()


if __name__ == "__main__":
    main()
