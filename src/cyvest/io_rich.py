"""
Rich console output for Cyvest investigations.

Provides formatted display of investigation results using the Rich library.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from rich.align import Align
from rich.console import Group
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from cyvest.levels import Level, get_color_level, get_color_score, get_level_from_score, normalize_level
from cyvest.model import Observable, Relationship, RelationshipDirection, _format_score_decimal

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest


def _normalize_exclude_levels(levels: Level | Iterable[Level]) -> set[Level]:
    base_excluded: set[Level] = {Level.NONE}
    if levels is None:
        return base_excluded
    if isinstance(levels, Level):
        return base_excluded | {levels}
    if isinstance(levels, str):
        return base_excluded | {normalize_level(levels)}

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

    item_name = getattr(item, "check_name", "")
    return (-decimal_score, item_name)


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

    linked_checks = ""
    if obs.check_links:
        checks_str = "[cyan], [/cyan]".join(escape(check_id) for check_id in obs.check_links)
        linked_checks = f"[cyan][[/cyan]{checks_str}[cyan]][/cyan] "

    whitelisted_str = " [green]WHITELISTED[/green]" if obs.whitelisted else ""

    obs_info = (
        f"{rel_info}{linked_checks}[bold]{obs.key}[/bold] "
        f"[{color_score}]{obs.score_display}[/{color_score}] "
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


def _render_audit_log_table(
    *,
    rich_print: Callable[[Any], None],
    title: str,
    events: Iterable[Any],
    started_at: datetime | None,
) -> None:
    def _render_score_change(details: dict[str, Any]) -> str:
        old_score = details.get("old_score")
        new_score = details.get("new_score")
        old_level = details.get("old_level")
        new_level = details.get("new_level")

        parts: list[str] = []
        if old_score is not None and new_score is not None:
            old_score = old_score if isinstance(old_score, Decimal) else Decimal(str(old_score))
            new_score = new_score if isinstance(new_score, Decimal) else Decimal(str(new_score))
            old_score_color = get_color_score(old_score)
            new_score_color = get_color_score(new_score)
            score_str = (
                f"[{old_score_color}]{_format_score_decimal(old_score)}[/"
                f"{old_score_color}] → "
                f"[{new_score_color}]{_format_score_decimal(new_score)}[/"
                f"{new_score_color}]"
            )
            parts.append(f"Score: {score_str}")

        if old_level is not None and new_level is not None:
            old_level_enum = normalize_level(old_level)
            new_level_enum = normalize_level(new_level)
            old_level_color = get_color_level(old_level_enum)
            new_level_color = get_color_level(new_level_enum)
            level_str = (
                f"[{old_level_color}]{old_level_enum.name}[/"
                f"{old_level_color}] → "
                f"[{new_level_color}]{new_level_enum.name}[/"
                f"{new_level_color}]"
            )
            parts.append(f"Level: {level_str}")

        return " | ".join(parts) if parts else "[dim]-[/dim]"

    def _render_level_change(details: dict[str, Any]) -> str:
        old_level = details.get("old_level")
        new_level = details.get("new_level")
        score = details.get("score")
        if old_level is None or new_level is None:
            return "[dim]-[/dim]"
        old_level_enum = normalize_level(old_level)
        new_level_enum = normalize_level(new_level)
        old_level_color = get_color_level(old_level_enum)
        new_level_color = get_color_level(new_level_enum)
        level_str = (
            f"[{old_level_color}]{old_level_enum.name}[/"
            f"{old_level_color}] → "
            f"[{new_level_color}]{new_level_enum.name}[/"
            f"{new_level_color}]"
        )
        if score is None:
            return f"Level: {level_str}"
        score = score if isinstance(score, Decimal) else Decimal(str(score))
        score_color = get_color_score(score)
        score_str = f"[{score_color}]{_format_score_decimal(score)}[/{score_color}]"
        return f"Level: {level_str} | Score: {score_str}"

    def _render_merge_event(details: dict[str, Any]) -> str:
        from_name = details.get("from_investigation_name")
        into_name = details.get("into_investigation_name")
        from_id = details.get("from_investigation_id")
        into_id = details.get("into_investigation_id")
        from_label = escape(str(from_name)) if from_name else escape(str(from_id))
        into_label = escape(str(into_name)) if into_name else escape(str(into_id))
        if not from_label or from_label == "None":
            from_label = "[dim]-[/dim]"
        if not into_label or into_label == "None":
            into_label = "[dim]-[/dim]"

        object_changes = details.get("object_changes") or []
        counts: dict[str, int] = {}
        for change in object_changes:
            action = change.get("action")
            if not action:
                continue
            counts[action] = counts.get(action, 0) + 1

        if counts:
            parts = [f"{key}={value}" for key, value in sorted(counts.items())]
            summary = ", ".join(parts)
            return f"Merge: {from_label} → {into_label} | Changes: {summary}"

        return f"Merge: {from_label} → {into_label}"

    def _render_threat_intel_attached(details: dict[str, Any]) -> str:
        source = details.get("source")
        score = details.get("score")
        level = details.get("level")
        parts: list[str] = []
        if source:
            parts.append(f"Source: [cyan]{escape(str(source))}[/cyan]")
        if level is not None:
            level_enum = normalize_level(level)
            level_color = get_color_level(level_enum)
            parts.append(f"Level: [{level_color}]{level_enum.name}[/{level_color}]")
        if score is not None:
            score_value = score if isinstance(score, Decimal) else Decimal(str(score))
            score_color = get_color_score(score_value)
            score_str = f"[{score_color}]{_format_score_decimal(score_value)}[/{score_color}]"
            parts.append(f"Score: {score_str}")
        return " | ".join(parts) if parts else "[dim]-[/dim]"

    detail_renderers: dict[str, Callable[[dict[str, Any]], str]] = {
        "SCORE_CHANGED": _render_score_change,
        "SCORE_RECALCULATED": _render_score_change,
        "LEVEL_UPDATED": _render_level_change,
        "INVESTIGATION_MERGED": _render_merge_event,
        "THREAT_INTEL_ATTACHED": _render_threat_intel_attached,
    }

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
    table.add_column("#", justify="right")
    table.add_column("Elapsed", style="dim")
    table.add_column("Event")
    table.add_column("Object")
    table.add_column("Context")

    events_sorted = sorted(events, key=lambda evt: evt.timestamp)
    effective_start = _coerce_utc(started_at) if started_at is not None else None
    if effective_start is None and events_sorted:
        effective_start = _coerce_utc(events_sorted[0].timestamp)

    grouped_events: dict[str, list[Any]] = {}
    group_order: list[str] = []
    for event in events_sorted:
        group_key = event.object_key or ""
        if group_key not in grouped_events:
            grouped_events[group_key] = []
            group_order.append(group_key)
        grouped_events[group_key].append(event)

    row_idx = 1
    for group_key in group_order:
        if row_idx > 1:
            table.add_section()
        for event in grouped_events[group_key]:
            event_timestamp = _coerce_utc(event.timestamp)
            elapsed = ""
            if effective_start is not None:
                elapsed = _format_elapsed((event_timestamp - effective_start).total_seconds())

            event_type = escape(event.event_type)
            object_label = "[dim]-[/dim]"
            if event.object_key:
                object_label = escape(event.object_key)
            reason = escape(event.reason) if event.reason else "[dim]-[/dim]"
            details = "[dim]-[/dim]"
            renderer = detail_renderers.get(event.event_type)
            if renderer:
                details = renderer(getattr(event, "details", {}) or {})

            if reason == "[dim]-[/dim]":
                context = details
            elif details == "[dim]-[/dim]":
                context = reason
            else:
                context = details

            table.add_row(
                str(row_idx),
                elapsed,
                event_type,
                object_label,
                context,
            )
            row_idx += 1

    table.caption = "No audit events recorded." if not events_sorted else ""
    rich_print(table)


def display_summary(
    cv: Cyvest,
    rich_print: Callable[[Any], None],
    show_graph: bool = True,
    exclude_levels: Level | Iterable[Level] = Level.NONE,
    show_audit_log: bool = False,
) -> None:
    """
    Display a comprehensive summary of the investigation using Rich.

    Args:
        cv: Cyvest investigation to display
        rich_print: A rich renderable handler that is called with renderables for output
        show_graph: Whether to display the observable graph
        exclude_levels: Level(s) to omit from the report (default: Level.NONE)
        show_audit_log: Whether to display the investigation audit log (default: False)
    """

    resolved_excluded_levels = _normalize_exclude_levels(exclude_levels)

    all_checks = cv.check_get_all().values()
    filtered_checks = [c for c in all_checks if c.level not in resolved_excluded_levels]
    applied_checks = sum(1 for c in filtered_checks if c.level != Level.NONE)

    excluded_caption = ""
    if resolved_excluded_levels:
        excluded_names = ", ".join(level.name for level in sorted(resolved_excluded_levels, key=lambda lvl: lvl.value))
        excluded_caption = f" (excluding: {excluded_names})"

    caption_parts = [
        f"Total Checks: {len(cv.check_get_all())}",
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

    # Checks by level section
    rule = Rule(f"[bold magenta]CHECKS[/bold magenta]: {len(cv.check_get_all())} checks")
    table.add_row(rule, "-", "-")

    for level_enum in sorted(Level, reverse=True):
        if level_enum in resolved_excluded_levels:
            continue
        checks = [c for c in cv.check_get_all().values() if c.level == level_enum]
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
                name = f"  {check.check_name}"
                score = f"[{color_score}]{check.score_display}[/{color_score}]"
                level = f"[{color_level}]{check.level.name}[/{color_level}]"
                table.add_row(name, score, level)

    # Tags section (if any)
    all_tags = cv.tag_get_all()
    if all_tags:
        table.add_section()
        rule = Rule(f"[bold magenta]TAGS[/bold magenta]: {len(all_tags)} tags")
        table.add_row(rule, "-", "-")

        for tag in sorted(all_tags.values(), key=lambda t: t.name):
            agg_score = tag.get_aggregated_score()
            agg_level = tag.get_aggregated_level()
            color_level = get_color_level(agg_level)
            color_score = get_color_score(agg_score)

            name = f"  {tag.name}"
            score = f"[{color_score}]{agg_score:.2f}[/{color_score}]"
            level = f"[{color_level}]{agg_level.name}[/{color_level}]"
            table.add_row(name, score, level)

    # Enrichments section (if any)
    if cv.enrichment_get_all():
        table.add_section()
        rule = Rule(f"[bold magenta]ENRICHMENTS[/bold magenta]: {len(cv.enrichment_get_all())} enrichments")
        table.add_row(rule, "-", "-")

        for enr in cv.enrichment_get_all().values():
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
        f"[{color_score}]{global_score:.2f}[/{color_score}]",
        f"[{color_level}]{global_level.name}[/{color_level}]",
    )

    # Print table
    rich_print(table)

    # Observable graph (if requested)
    if show_graph and cv.observable_get_all():
        tree = Tree("Observables", hide_root=True)

        # Precompute reverse relationships to traverse observables that only
        # appear as targets (e.g., child → parent links).
        all_observables = cv.observable_get_all()
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

    if show_audit_log:
        investigation = getattr(cv, "_investigation", None)
        events = investigation.get_audit_log() if investigation else []
        if events:
            started_at = investigation.started_at if investigation else None
            _render_audit_log_table(
                rich_print=rich_print,
                title="Audit Log",
                events=events,
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
    check_table.add_column("Level", style="cyan")
    check_table.add_column("Count", justify="right")

    for level, count in stats.checks_by_level.items():
        check_table.add_row(level, str(count))

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


def _format_level_score(
    level: Level | None,
    score: Decimal | None,
    score_rule: str | None = None,
) -> str:
    """Format level and score for display."""
    if level is None and score is None and not score_rule:
        return "[dim]-[/dim]"

    parts: list[str] = []
    if level:
        color = get_color_level(level)
        parts.append(f"[{color}]{level.name}[/{color}]")

    if score_rule:
        parts.append(score_rule)
    elif score is not None:
        color = get_color_score(score)
        parts.append(f"[{color}]{_format_score_decimal(score)}[/{color}]")

    return " ".join(parts) if parts else "[dim]-[/dim]"


def display_diff(
    diffs: list,
    rich_print: Callable[[Any], None],
    title: str = "Diff",
) -> None:
    """
    Display investigation diff in a rich table with tree structure.

    Args:
        diffs: List of DiffItem objects representing differences
        rich_print: A rich renderable handler called with renderables for output
        title: Title for the diff table
    """
    # Import here to avoid circular dependency
    from cyvest.compare import DiffStatus

    # Count diffs by status
    added = sum(1 for d in diffs if d.status == DiffStatus.ADDED)
    removed = sum(1 for d in diffs if d.status == DiffStatus.REMOVED)
    mismatch = sum(1 for d in diffs if d.status == DiffStatus.MISMATCH)

    # Build caption with combined legend and counts
    caption = (
        f"[green]+ {added}[/green] added | [red]- {removed}[/red] removed | [yellow]\u2717 {mismatch}[/yellow] mismatch"
    )

    table = Table(title=title, caption=caption)
    table.add_column("Key")
    table.add_column("Expected", justify="center")
    table.add_column("Actual", justify="center")
    table.add_column("Status", justify="center", width=8)

    status_styles = {
        DiffStatus.ADDED: "green",
        DiffStatus.REMOVED: "red",
        DiffStatus.MISMATCH: "yellow",
    }

    for idx, diff in enumerate(diffs):
        # Add section separator between checks (except before first)
        if idx > 0:
            table.add_section()

        status_style = status_styles.get(diff.status, "white")

        # Check row (main row)
        expected_str = _format_level_score(diff.expected_level, diff.expected_score, diff.expected_score_rule)
        actual_str = _format_level_score(diff.actual_level, diff.actual_score)

        table.add_row(
            escape(diff.key),
            expected_str,
            actual_str,
            f"[{status_style}]{diff.status.value}[/{status_style}]",
        )

        # Observable rows (indented with └──)
        for obs_idx, obs in enumerate(diff.observable_diffs):
            is_last_obs = obs_idx == len(diff.observable_diffs) - 1
            obs_prefix = "└──" if is_last_obs else "├──"

            obs_label = obs.observable_key
            obs_expected = _format_level_score(obs.expected_level, obs.expected_score)
            obs_actual = _format_level_score(obs.actual_level, obs.actual_score)

            table.add_row(
                f"{obs_prefix} [cyan]{escape(obs_label)}[/cyan]",
                obs_expected,
                obs_actual,
                "",
            )

            # Threat intel rows (indented further with │   └── or     └──)
            for ti_idx, ti in enumerate(obs.threat_intel_diffs):
                is_last_ti = ti_idx == len(obs.threat_intel_diffs) - 1
                # Use │ continuation if not last observable, else spaces
                continuation = "│   " if not is_last_obs else "    "
                ti_prefix = "└──" if is_last_ti else "├──"

                ti_expected = _format_level_score(ti.expected_level, ti.expected_score)
                ti_actual = _format_level_score(ti.actual_level, ti.actual_score)

                table.add_row(
                    f"{continuation}{ti_prefix} [magenta]{escape(ti.source)}[/magenta]",
                    ti_expected,
                    ti_actual,
                    "",
                )

    rich_print(table)


def _format_extra_data(extra: dict[str, Any]) -> str:
    """Format extra data as a compact JSON string."""
    if not extra:
        return "[dim]-[/dim]"
    try:
        return escape(json.dumps(extra, indent=2, default=str))
    except (TypeError, ValueError):
        return escape(str(extra))


def _build_ti_tree_for_observable(
    ti_list: list,
    parent_tree: Tree,
) -> None:
    """Build a tree of threat intel entries for an observable."""
    for ti in ti_list:
        color_level = get_color_level(ti.level)
        color_score = get_color_score(ti.score)
        ti_label = (
            f"[magenta]{escape(ti.source)}[/magenta] "
            f"[{color_score}]{ti.score_display}[/{color_score}] "
            f"[bold {color_level}]{ti.level.name}[/bold {color_level}]"
        )
        ti_node = parent_tree.add(ti_label)

        # Add taxonomies as children
        if ti.taxonomies:
            for tax in ti.taxonomies:
                tax_color = get_color_level(tax.level)
                tax_label = f"[{tax_color}]{tax.level.name}[/{tax_color}] {escape(tax.name)}: {escape(tax.value)}"
                ti_node.add(tax_label)

        # Add comment if present
        if ti.comment:
            ti_node.add(f"[dim]Comment:[/dim] {escape(ti.comment)}")


def _build_relationship_tree_depth(
    obs_key: str,
    all_observables: dict[str, Any],
    all_threat_intels: dict[str, Any],
    max_depth: int,
) -> Tree:
    """Build a tree showing relationships up to max_depth with scores and levels."""
    tree = Tree(f"[bold]Relationships[/bold] (depth={max_depth})")

    if max_depth < 1:
        tree.add("[dim]No relationships (depth=0)[/dim]")
        return tree

    obs = all_observables.get(obs_key)
    if not obs:
        return tree

    # Build reverse relationship map
    reverse_relationships: dict[str, list[tuple[Any, Relationship]]] = {}
    for source_obs in all_observables.values():
        for rel in source_obs.relationships:
            reverse_relationships.setdefault(rel.target_key, []).append((source_obs, rel))

    visited: set[str] = {obs_key}

    def _add_relationships(current_obs: Any, parent_tree: Tree, depth: int) -> None:
        if depth > max_depth:
            return

        # Outbound relationships
        for rel in current_obs.relationships:
            target_obs = all_observables.get(rel.target_key)
            if not target_obs or target_obs.key in visited:
                continue

            visited.add(target_obs.key)
            direction_symbol = _get_direction_symbol(rel, reversed_edge=False)
            color_level = get_color_level(target_obs.level)
            color_score = get_color_score(target_obs.score)

            rel_label = (
                f"{direction_symbol} [dim]{rel.relationship_type_name}[/dim] "
                f"[bold]{escape(target_obs.key)}[/bold] "
                f"[{color_score}]{target_obs.score_display}[/{color_score}] "
                f"[bold {color_level}]{target_obs.level.name}[/bold {color_level}]"
            )
            child_node = parent_tree.add(rel_label)

            if depth < max_depth:
                _add_relationships(target_obs, child_node, depth + 1)

        # Inbound relationships
        for source_obs, rel in reverse_relationships.get(current_obs.key, []):
            if source_obs.key == current_obs.key or source_obs.key in visited:
                continue

            visited.add(source_obs.key)
            direction_symbol = _get_direction_symbol(rel, reversed_edge=True)
            color_level = get_color_level(source_obs.level)
            color_score = get_color_score(source_obs.score)

            rel_label = (
                f"{direction_symbol} [dim]{rel.relationship_type_name}[/dim] "
                f"[bold]{escape(source_obs.key)}[/bold] "
                f"[{color_score}]{source_obs.score_display}[/{color_score}] "
                f"[bold {color_level}]{source_obs.level.name}[/bold {color_level}]"
            )
            child_node = parent_tree.add(rel_label)

            if depth < max_depth:
                _add_relationships(source_obs, child_node, depth + 1)

    _add_relationships(obs, tree, 1)

    return tree


def display_check_query(
    cv: Cyvest,
    check_key: str,
    rich_print: Callable[[Any], None],
) -> None:
    """
    Display detailed information about a check.

    Args:
        cv: Cyvest investigation
        check_key: Key of the check to display
        rich_print: Rich renderable handler

    Raises:
        KeyError: If check not found
    """
    check = cv.check_get(check_key)
    if check is None:
        raise KeyError(f"Check '{check_key}' not found in investigation.")

    color_level = get_color_level(check.level)
    color_score = get_color_score(check.score)

    # Build info table
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Key", f"[bold]{escape(check.key)}[/bold]")
    table.add_row("Name", escape(check.check_name))
    table.add_row("Description", escape(check.description) if check.description else "[dim]-[/dim]")
    table.add_row(
        "Score",
        f"[bold {color_score}]{check.score_display}[/bold {color_score}]",
    )
    table.add_row(
        "Level",
        f"[bold {color_level}]{check.level.name}[/bold {color_level}]",
    )
    table.add_row("Comment", escape(check.comment) if check.comment else "[dim]-[/dim]")
    table.add_row(
        "Origin Investigation",
        escape(check.origin_investigation_id) if check.origin_investigation_id else "[dim]-[/dim]",
    )

    # Extra data
    if check.extra:
        table.add_row("Extra", _format_extra_data(check.extra))

    rich_print(
        Panel(
            table,
            title=f"[bold]Check:[/bold] {escape(check.check_name)}",
            border_style="blue",
            expand=False,
        )
    )

    # Linked observables tree
    observable_links = check.observable_links
    if observable_links:
        all_observables = cv.observable_get_all()

        tree = Tree("[bold]Linked Observables[/bold]")

        for link in observable_links:
            obs = all_observables.get(link.observable_key)
            if not obs:
                tree.add(f"[dim]{escape(link.observable_key)} (not found)[/dim]")
                continue

            obs_color_level = get_color_level(obs.level)
            obs_color_score = get_color_score(obs.score)
            whitelisted_str = " [green]WHITELISTED[/green]" if obs.whitelisted else ""
            prop_mode = f" [dim]({link.propagation_mode.value})[/dim]" if hasattr(link, "propagation_mode") else ""

            obs_label = (
                f"[bold]{escape(obs.key)}[/bold] "
                f"[{obs_color_score}]{obs.score_display}[/{obs_color_score}] "
                f"[bold {obs_color_level}]{obs.level.name}[/bold {obs_color_level}]"
                f"{whitelisted_str}{prop_mode}"
            )
            obs_node = tree.add(obs_label)

            # Add threat intel for this observable
            for ti in obs.threat_intels:
                ti_color_level = get_color_level(ti.level)
                ti_color_score = get_color_score(ti.score)
                ti_label = (
                    f"[magenta]{escape(ti.source)}[/magenta] "
                    f"[{ti_color_score}]{ti.score_display}[/{ti_color_score}] "
                    f"[bold {ti_color_level}]{ti.level.name}[/bold {ti_color_level}]"
                )
                obs_node.add(ti_label)

        rich_print(Panel(tree, border_style="green", expand=False))


def display_observable_query(
    cv: Cyvest,
    observable_key: str,
    rich_print: Callable[[Any], None],
    *,
    depth: int = 1,
) -> None:
    """
    Display detailed information about an observable.

    Args:
        cv: Cyvest investigation
        observable_key: Key of the observable to display
        rich_print: Rich renderable handler
        depth: Relationship traversal depth (default 1)

    Raises:
        KeyError: If observable not found
    """
    obs = cv.observable_get(observable_key)
    if obs is None:
        raise KeyError(f"Observable '{observable_key}' not found in investigation.")

    color_level = get_color_level(obs.level)
    color_score = get_color_score(obs.score)

    # Build info table
    obs_type_str = obs.obs_type.value if hasattr(obs.obs_type, "value") else str(obs.obs_type)
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Key", f"[bold]{escape(obs.key)}[/bold]")
    table.add_row("Type", escape(obs_type_str))
    table.add_row("Value", escape(obs.value))
    table.add_row(
        "Score",
        f"[bold {color_score}]{obs.score_display}[/bold {color_score}]",
    )
    table.add_row(
        "Level",
        f"[bold {color_level}]{obs.level.name}[/bold {color_level}]",
    )
    table.add_row("Internal", "[green]Yes[/green]" if obs.internal else "[yellow]No[/yellow]")
    table.add_row("Whitelisted", "[green]Yes[/green]" if obs.whitelisted else "[dim]No[/dim]")
    table.add_row("Comment", escape(obs.comment) if obs.comment else "[dim]-[/dim]")

    # Check links
    if obs.check_links:
        checks_str = ", ".join(escape(ck) for ck in obs.check_links)
        table.add_row("Linked Checks", f"[cyan]{checks_str}[/cyan]")

    # Extra data
    if obs.extra:
        table.add_row("Extra", _format_extra_data(obs.extra))

    rich_print(
        Panel(
            table,
            title=f"[bold]Observable:[/bold] {escape(obs_type_str)}",
            border_style="green",
            expand=False,
        )
    )

    # Build score breakdown, threat intel, and relationships panel
    all_observables = cv.observable_get_all()
    renderables = []

    # Get score mode from investigation
    score_mode = "MAX"
    try:
        score_mode = cv._investigation._score_engine._score_mode_obs.value.upper()
    except AttributeError:
        pass

    # Score breakdown table
    ti_scores: list[Decimal] = []
    child_scores: list[Decimal] = []

    if obs.threat_intels or obs.relationships:
        score_table = Table(title=f"[bold]Score Breakdown[/bold] (mode: {score_mode})")
        score_table.add_column("Source", style="cyan")
        score_table.add_column("Score", justify="right")
        score_table.add_column("Level", justify="center")
        score_table.add_column("Type", style="dim")

        # Add threat intel contributions
        for ti in obs.threat_intels:
            ti_color_score = get_color_score(ti.score)
            ti_color_level = get_color_level(ti.level)
            score_table.add_row(
                escape(ti.key),
                f"[{ti_color_score}]{ti.score_display}[/{ti_color_score}]",
                f"[{ti_color_level}]{ti.level.name}[/{ti_color_level}]",
                "threat_intel",
            )
            ti_scores.append(ti.score)

        # Add child observable contributions (OUTBOUND relationships)
        for rel in obs.relationships:
            if rel.direction == RelationshipDirection.OUTBOUND:
                child = all_observables.get(rel.target_key)
                if child and child.value != "root":
                    child_color_score = get_color_score(child.score)
                    child_color_level = get_color_level(child.level)
                    score_table.add_row(
                        escape(child.key),
                        f"[{child_color_score}]{child.score_display}[/{child_color_score}]",
                        f"[{child_color_level}]{child.level.name}[/{child_color_level}]",
                        "child",
                    )
                    child_scores.append(child.score)

        # Add computed total row
        if ti_scores or child_scores:
            score_table.add_section()
            if score_mode == "MAX":
                computed = max(ti_scores + child_scores, default=Decimal("0"))
                mode_label = "Computed (MAX)"
            else:
                max_ti = max(ti_scores, default=Decimal("0"))
                sum_children = sum(child_scores, Decimal("0"))
                computed = max_ti + sum_children
                mode_label = "Computed (SUM)"

            computed_color_score = get_color_score(computed)
            computed_level = get_level_from_score(computed)
            computed_color_level = get_color_level(computed_level)
            score_table.add_row(
                f"[bold]{mode_label}[/bold]",
                f"[bold {computed_color_score}]{_format_score_decimal(computed)}[/bold {computed_color_score}]",
                f"[bold {computed_color_level}]{computed_level.name}[/bold {computed_color_level}]",
                "",
            )
            renderables.append(score_table)

    # Threat intelligence tree
    if obs.threat_intels:
        if renderables:
            renderables.append("")
        ti_tree = Tree("[bold]Threat Intelligence[/bold]")
        _build_ti_tree_for_observable(obs.threat_intels, ti_tree)
        renderables.append(ti_tree)

    # Relationships tree
    if depth > 0:
        rel_tree = _build_relationship_tree_depth(
            observable_key,
            all_observables,
            cv.threat_intel_get_all(),
            depth,
        )
        if renderables:
            renderables.append("")
        renderables.append(rel_tree)

    if renderables:
        rich_print(Panel(Group(*renderables), border_style="magenta", expand=False))
    else:
        rich_print("[dim]No score contributions (no threat intel or child observables)[/dim]")


def display_threat_intel_query(
    cv: Cyvest,
    ti_key: str,
    rich_print: Callable[[Any], None],
) -> None:
    """
    Display detailed information about a threat intel entry.

    Args:
        cv: Cyvest investigation
        ti_key: Key of the threat intel to display
        rich_print: Rich renderable handler

    Raises:
        KeyError: If threat intel not found
    """
    ti = cv.threat_intel_get(ti_key)
    if ti is None:
        raise KeyError(f"Threat intel '{ti_key}' not found in investigation.")

    color_level = get_color_level(ti.level)
    color_score = get_color_score(ti.score)

    # Build info table
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Key", f"[bold]{escape(ti.key)}[/bold]")
    table.add_row("Source", f"[magenta]{escape(ti.source)}[/magenta]")
    table.add_row("Observable", f"[cyan]{escape(ti.observable_key)}[/cyan]")
    table.add_row(
        "Score",
        f"[bold {color_score}]{ti.score_display}[/bold {color_score}]",
    )
    table.add_row(
        "Level",
        f"[bold {color_level}]{ti.level.name}[/bold {color_level}]",
    )
    table.add_row("Comment", escape(ti.comment) if ti.comment else "[dim]-[/dim]")

    rich_print(
        Panel(
            table,
            title=f"[bold]Threat Intel:[/bold] {escape(ti.source)}",
            border_style="magenta",
            expand=False,
        )
    )

    # Taxonomies tree
    if ti.taxonomies:
        tax_tree = Tree("[bold]Taxonomies[/bold]")
        for tax in ti.taxonomies:
            tax_color = get_color_level(tax.level)
            tax_label = (
                f"[{tax_color}]{tax.level.name}[/{tax_color}] {escape(tax.name)}: [bold]{escape(tax.value)}[/bold]"
            )
            tax_tree.add(tax_label)
        rich_print(tax_tree)

    # Extra data
    if ti.extra:
        extra_str = _format_extra_data(ti.extra)
        extra_panel = Panel(
            extra_str,
            title="[bold]Extra Data[/bold]",
            border_style="dim",
        )
        rich_print(extra_panel)

    # Show linked observable info
    obs = cv.observable_get(ti.observable_key)
    if obs:
        obs_color_level = get_color_level(obs.level)
        obs_color_score = get_color_score(obs.score)
        obs_type_str = obs.obs_type.value if hasattr(obs.obs_type, "value") else str(obs.obs_type)

        obs_table = Table(
            show_header=False,
            box=None,
        )
        obs_table.add_column("Field", style="cyan")
        obs_table.add_column("Value")

        obs_table.add_row("Key", f"[bold]{escape(obs.key)}[/bold]")
        obs_table.add_row("Type", escape(obs_type_str))
        obs_table.add_row("Value", escape(obs.value))
        obs_table.add_row(
            "Score",
            f"[{obs_color_score}]{obs.score_display}[/{obs_color_score}]",
        )
        obs_table.add_row(
            "Level",
            f"[{obs_color_level}]{obs.level.name}[/{obs_color_level}]",
        )

        # Combine table and threat intel tree in one panel
        if obs.threat_intels:
            obs_ti_tree = Tree("[bold]Threat Intelligence[/bold]")
            _build_ti_tree_for_observable(obs.threat_intels, obs_ti_tree)
            content = Group(obs_table, "", obs_ti_tree)
        else:
            content = obs_table

        rich_print(Panel(content, title="[bold]Linked Observable[/bold]", border_style="green", expand=False))
