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

    # Checks section
    rule = Rule("[bold magenta]CHECKS[/bold magenta]")
    table.add_row(rule, "-", "-")

    # Organize checks by scope
    checks_by_scope: dict[str, list[Any]] = {}
    for check in cv.check_get_all().values():
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
            score = f"[{color_score}]{check.score_display}[/{color_score}]"
            level = f"[{color_level}]{check.level.name}[/{color_level}]"
            table.add_row(name, score, level)

    # Containers section (if any)
    if cv.container_get_all():
        table.add_section()
        rule = Rule("[bold magenta]CONTAINERS[/bold magenta]")
        table.add_row(rule, "-", "-")

        for container in cv.container_get_all().values():
            agg_score = container.get_aggregated_score()
            agg_level = container.get_aggregated_level()
            color_level = get_color_level(agg_level)
            color_score = get_color_score(agg_score)

            name = f"  {container.path}"
            score = f"[{color_score}]{agg_score:.2f}[/{color_score}]"
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
            c for c in cv.check_get_all().values() if c.level == level_enum and c.level not in resolved_excluded_levels
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
                score = f"[{color_score}]{check.score_display}[/{color_score}]"
                level = f"[{color_level}]{check.level.name}[/{color_level}]"
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
        events = investigation.get_event_log() if investigation else []
        if events:
            started_at = getattr(investigation, "_started_at", None) if investigation else None
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
