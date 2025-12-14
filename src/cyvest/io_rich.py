"""
Rich console output for Cyvest investigations.

Provides formatted display of investigation results using the Rich library.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from rich.align import Align
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from cyvest.levels import Level, get_color_level, get_color_score, normalize_level
from cyvest.model import Observable, Relationship, RelationshipDirection

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest


def _normalize_exclude_levels(levels: Level | str | Iterable[Level | str]) -> set[Level]:
    base_excluded: set[Level] = {Level.NONE}
    if levels is None:
        return base_excluded
    if isinstance(levels, (Level, str)):
        normalized_level = normalize_level(levels) if isinstance(levels, str) else levels
        return base_excluded | {normalized_level}

    collected = list(levels)
    if not collected:
        return set()

    normalized: set[Level] = set()
    for level in collected:
        normalized.add(normalize_level(level) if isinstance(level, str) else level)
    return base_excluded | normalized


def _sort_key_by_score(item: Any) -> tuple[Decimal, str]:
    score = getattr(item, "score", 0)
    try:
        decimal_score = Decimal(score)
    except (TypeError, ValueError, InvalidOperation):
        decimal_score = Decimal(0)

    item_id = getattr(item, "check_id", "")
    return (-decimal_score, item_id)


def _get_direction_symbol(rel: Relationship, reversed_edge: bool) -> str:
    """Return an arrow indicating direction relative to traversal."""
    direction = rel.direction
    if isinstance(direction, str):
        try:
            direction = RelationshipDirection(direction)
        except ValueError:
            direction = RelationshipDirection.OUTBOUND

    symbol_map = {
        RelationshipDirection.OUTBOUND: "→",
        RelationshipDirection.INBOUND: "←",
        RelationshipDirection.BIDIRECTIONAL: "↔",
    }
    symbol = symbol_map.get(direction, "→")
    if reversed_edge and direction != RelationshipDirection.BIDIRECTIONAL:
        symbol = "←" if direction == RelationshipDirection.OUTBOUND else "→"
    return symbol


def _build_observable_tree(
    parent_tree: Tree,
    obs: Any,
    *,
    all_observables: dict[str, Any],
    reverse_relationships: dict[str, list[tuple[Any, Relationship]]],
    visited: set[str],
    rel_info: str = "",
) -> None:
    if obs.key in visited:
        return
    visited.add(obs.key)

    color_level = get_color_level(obs.level)
    color_score = get_color_score(obs.score)

    generated_by = ""
    if obs.generated_by_checks:
        checks_str = "[cyan], [/cyan]".join(escape(check_id) for check_id in obs.generated_by_checks)
        generated_by = f"[cyan][[/cyan]{checks_str}[cyan]][/cyan] "

    whitelisted_str = " [green]WHITELISTED[/green]" if obs.whitelisted else ""

    obs_info = (
        f"{rel_info}{generated_by}[bold]{obs.key}[/bold] "
        f"[{color_score}]{obs.score}[/{color_score}] "
        f"[{color_level}]{obs.level.name}[/{color_level}]"
        f"{whitelisted_str}"
    )

    child_tree = parent_tree.add(obs_info)

    # Add outbound children
    for rel in obs.relationships:
        child_obs = all_observables.get(rel.target_key)
        if child_obs:
            direction_symbol = _get_direction_symbol(rel, reversed_edge=False)
            rel_label = f"[dim]{rel.relationship_type_name}[/dim] {direction_symbol} "
            _build_observable_tree(
                child_tree,
                child_obs,
                all_observables=all_observables,
                reverse_relationships=reverse_relationships,
                visited=visited,
                rel_info=rel_label,
            )

    # Add inbound children (observables pointing to this one)
    for source_obs, rel in reverse_relationships.get(obs.key, []):
        if source_obs.key == obs.key:
            continue
        direction_symbol = _get_direction_symbol(rel, reversed_edge=True)
        rel_label = f"[dim]{rel.relationship_type_name}[/dim] {direction_symbol} "
        _build_observable_tree(
            child_tree,
            source_obs,
            all_observables=all_observables,
            reverse_relationships=reverse_relationships,
            visited=visited,
            rel_info=rel_label,
        )


def _render_score_history_table(
    *,
    rich_print: Callable[[Any], None],
    title: str,
    groups: Iterable[tuple[str, Iterable[Any]]],
    started_at: datetime | None,
) -> None:
    materialized_groups: list[tuple[str, list[Any]]] = [(name, list(items)) for name, items in groups]

    def _coerce_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _format_elapsed(total_seconds: float) -> str:
        total_ms = int(round(total_seconds * 1000))
        if total_ms < 0:
            total_ms = 0
        hours, rem_ms = divmod(total_ms, 3_600_000)
        minutes, rem_ms = divmod(rem_ms, 60_000)
        seconds, ms = divmod(rem_ms, 1000)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{ms:03d}"

    table = Table(title=title, show_lines=False)
    table.add_column("Item")
    table.add_column("#", justify="right")
    table.add_column("Elapsed", style="dim")
    table.add_column("Score", justify="center")
    table.add_column("Level", justify="center")
    table.add_column("Reason")

    effective_start = _coerce_utc(started_at) if started_at is not None else None
    if effective_start is None:
        earliest: datetime | None = None
        for _group_name, items in materialized_groups:
            for item in items:
                for change in item.get_score_history():
                    ts = _coerce_utc(change.timestamp)
                    if earliest is None or ts < earliest:
                        earliest = ts
        effective_start = earliest

    has_history = False
    for group_name, items in materialized_groups:
        item_color = "cyan" if group_name.lower() == "observable" else "magenta"
        for item in items:
            score_history = sorted(item.get_score_history(), key=lambda change: change.timestamp)
            if not score_history:
                continue

            if has_history:
                table.add_section()

            for idx, change in enumerate(score_history, start=1):
                has_history = True

                change_timestamp = _coerce_utc(change.timestamp)
                old_score_color = get_color_score(change.old_score)
                new_score_color = get_color_score(change.new_score)
                score_str = (
                    f"[{old_score_color}]{change.old_score}[/{old_score_color}] "
                    f"→ "
                    f"[{new_score_color}]{change.new_score}[/{new_score_color}]"
                )

                old_level_color = get_color_level(change.old_level)
                new_level_color = get_color_level(change.new_level)
                level_str = (
                    f"[{old_level_color}]{change.old_level.name}[/{old_level_color}] "
                    f"→ "
                    f"[{new_level_color}]{change.new_level.name}[/{new_level_color}]"
                )

                reason = escape(change.reason) if change.reason else "[dim]-[/dim]"
                elapsed = ""
                if effective_start is not None:
                    elapsed = _format_elapsed((change_timestamp - effective_start).total_seconds())

                item_cell = f"[{item_color}]{escape(item.key)}[/{item_color}]"
                table.add_row(
                    item_cell,
                    str(idx),
                    elapsed,
                    score_str,
                    level_str,
                    reason,
                )

    table.caption = "No score changes recorded." if not has_history else ""
    rich_print(table)


def display_summary(
    cv: Cyvest,
    rich_print: Callable[[Any], None],
    show_graph: bool = True,
    exclude_levels: Level | str | Iterable[Level | str] = Level.NONE,
    show_score_history: bool = False,
) -> None:
    """
    Display a comprehensive summary of the investigation using Rich.

    Args:
        cv: Cyvest investigation to display
        rich_print: A rich renderable handler that is called with renderables for output
        show_graph: Whether to display the observable graph
        exclude_levels: Level(s) to omit from the report (default: Level.NONE)
        show_score_history: Whether to display score change history for observables and checks (default: False)
    """

    resolved_excluded_levels = _normalize_exclude_levels(exclude_levels)

    all_checks = cv.get_all_checks().values()
    filtered_checks = [c for c in all_checks if c.level not in resolved_excluded_levels]
    applied_checks = sum(1 for c in filtered_checks if c.level != Level.NONE)

    excluded_caption = ""
    if resolved_excluded_levels:
        excluded_names = ", ".join(level.name for level in sorted(resolved_excluded_levels, key=lambda lvl: lvl.value))
        excluded_caption = f" (excluding: {excluded_names})"

    caption_parts = [
        f"Total Checks: {len(cv.get_all_checks())}",
        f"Displayed: {len(filtered_checks)}{excluded_caption}",
        f"Applied: {applied_checks}",
    ]

    table = Table(
        title="Investigation Report",
        caption=" | ".join(caption_parts),
    )
    table.add_column("Name")
    table.add_column("Score", justify="right")
    table.add_column("Level", justify="center")

    # Checks section
    rule = Rule("[bold magenta]CHECKS[/bold magenta]")
    table.add_row(rule, "-", "-")

    # Organize checks by scope
    checks_by_scope: dict[str, list[Any]] = {}
    for check in cv.get_all_checks().values():
        if check.level in resolved_excluded_levels:
            continue
        if check.scope not in checks_by_scope:
            checks_by_scope[check.scope] = []
        checks_by_scope[check.scope].append(check)

    for scope_name, checks in checks_by_scope.items():
        scope_rule = Align(f"[bold magenta]{scope_name}[/bold magenta]", align="left")
        table.add_row(scope_rule, "-", "-")
        checks = sorted(checks, key=_sort_key_by_score)
        for check in checks:
            color_level = get_color_level(check.level)
            color_score = get_color_score(check.score)
            name = f"  {check.check_id}"
            score = f"[{color_score}]{check.score}[/{color_score}]"
            level = f"[{color_level}]{check.level.name}[/{color_level}]"
            table.add_row(name, score, level)

    # Containers section (if any)
    if cv.get_all_containers():
        table.add_section()
        rule = Rule("[bold magenta]CONTAINERS[/bold magenta]")
        table.add_row(rule, "-", "-")

        for container in cv.get_all_containers().values():
            agg_score = container.get_aggregated_score()
            agg_level = container.get_aggregated_level()
            color_level = get_color_level(agg_level)
            color_score = get_color_score(agg_score)

            name = f"  {container.path}"
            score = f"[{color_score}]{agg_score}[/{color_score}]"
            level = f"[{color_level}]{agg_level.name}[/{color_level}]"
            table.add_row(name, score, level)

    # Checks by level section
    table.add_section()
    rule = Rule("[bold magenta]BY LEVEL[/bold magenta]")
    table.add_row(rule, "-", "-")

    for level_enum in [Level.MALICIOUS, Level.SUSPICIOUS, Level.NOTABLE, Level.SAFE, Level.INFO, Level.TRUSTED]:
        if level_enum in resolved_excluded_levels:
            continue
        checks = [
            c for c in cv.get_all_checks().values() if c.level == level_enum and c.level not in resolved_excluded_levels
        ]
        checks = sorted(checks, key=_sort_key_by_score)
        if checks:
            color_level = get_color_level(level_enum)
            level_rule = Align(
                f"[bold {color_level}]{level_enum.name}: {len(checks)} check(s)[/bold {color_level}]",
                align="center",
            )
            table.add_row(level_rule, "-", "-")

            for check in checks:
                color_score = get_color_score(check.score)
                name = f"  {check.check_id}"
                score = f"[{color_score}]{check.score}[/{color_score}]"
                level = f"[{color_level}]{check.level.name}[/{color_level}]"
                table.add_row(name, score, level)

    # Enrichments section (if any)
    if cv.get_all_enrichments():
        table.add_section()
        rule = Rule(f"[bold magenta]ENRICHMENTS[/bold magenta]: {len(cv.get_all_enrichments())} enrichments")
        table.add_row(rule, "-", "-")

        for enr in cv.get_all_enrichments().values():
            table.add_row(f"  {enr.name}", "-", "-")

    # Statistics section
    table.add_section()
    rule = Rule("[bold magenta]STATISTICS[/bold magenta]")
    table.add_row(rule, "-", "-")

    stats = cv.get_statistics()
    stat_items = [
        ("Total Observables", stats.total_observables),
        ("Internal Observables", stats.internal_observables),
        ("External Observables", stats.external_observables),
        ("Whitelisted Observables", stats.whitelisted_observables),
        ("Total Threat Intel", stats.total_threat_intel),
    ]

    for stat_name, stat_value in stat_items:
        table.add_row(f"  {stat_name}", str(stat_value), "-")

    # Global score footer
    global_score = cv.get_global_score()
    global_level = cv.get_global_level()
    color_level = get_color_level(global_level)
    color_score = get_color_score(global_score)

    table.add_section()
    table.add_row(
        Align("[bold]GLOBAL SCORE[/bold]", align="center"),
        f"[{color_score}]{global_score}[/{color_score}]",
        f"[{color_level}]{global_level.name}[/{color_level}]",
    )

    # Print table
    rich_print(table)

    # Observable graph (if requested)
    if show_graph and cv.get_all_observables():
        tree = Tree("Observables", hide_root=True)

        # Precompute reverse relationships so we can traverse observables that only
        # appear as targets (e.g., child → parent links).
        all_observables = cv.get_all_observables()
        reverse_relationships: dict[str, list[tuple[Observable, Relationship]]] = {}
        for source_obs in all_observables.values():
            for rel in source_obs.relationships:
                reverse_relationships.setdefault(rel.target_key, []).append((source_obs, rel))

        # Start from root
        root = cv.observable_get_root()
        if root:
            _build_observable_tree(
                tree,
                root,
                all_observables=all_observables,
                reverse_relationships=reverse_relationships,
                visited=set(),
            )

        rich_print(tree)

    if show_score_history:
        all_observables = cv.get_all_observables()
        all_checks = cv.get_all_checks()
        if all_observables or all_checks:
            started_at = getattr(getattr(cv, "_investigation", None), "_started_at", None)
            _render_score_history_table(
                rich_print=rich_print,
                title="Score History",
                groups=[
                    ("Observable", [obs for _key, obs in sorted(all_observables.items())]),
                    ("Check", [check for _key, check in sorted(all_checks.items())]),
                ],
                started_at=started_at,
            )


def display_statistics(cv: Cyvest, rich_print: Callable[[Any], None]) -> None:
    """
    Display detailed statistics about the investigation.

    Args:
        cv: Cyvest investigation
        rich_print: A rich renderable handler that is called with renderables for output
    """
    stats = cv.get_statistics()

    # Observable statistics table
    obs_table = Table(title="Observable Statistics")
    obs_table.add_column("Type", style="cyan")
    obs_table.add_column("Total", justify="right")
    obs_table.add_column("INFO", justify="right", style="cyan")
    obs_table.add_column("NOTABLE", justify="right", style="yellow")
    obs_table.add_column("SUSPICIOUS", justify="right", style="orange3")
    obs_table.add_column("MALICIOUS", justify="right", style="red")

    obs_by_type_level = stats.observables_by_type_and_level
    for obs_type, count in stats.observables_by_type.items():
        levels = obs_by_type_level.get(obs_type, {})
        obs_table.add_row(
            obs_type.upper(),
            str(count),
            str(levels.get("INFO", 0)),
            str(levels.get("NOTABLE", 0)),
            str(levels.get("SUSPICIOUS", 0)),
            str(levels.get("MALICIOUS", 0)),
        )

    rich_print(obs_table)

    # Check statistics table
    rich_print("")
    check_table = Table(title="Check Statistics")
    check_table.add_column("Scope", style="cyan")
    check_table.add_column("Count", justify="right")

    for scope, count in stats.checks_by_scope.items():
        check_table.add_row(scope, str(count))

    rich_print(check_table)

    # Threat intel statistics
    if stats.total_threat_intel > 0:
        rich_print("")
        ti_table = Table(title="Threat Intelligence Statistics")
        ti_table.add_column("Source", style="cyan")
        ti_table.add_column("Count", justify="right")

        for source, count in stats.threat_intel_by_source.items():
            ti_table.add_row(source, str(count))

        rich_print(ti_table)
