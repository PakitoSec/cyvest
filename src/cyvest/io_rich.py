"""
Rich console output for Cyvest investigations.

Provides formatted display of investigation results using the Rich library.
"""

from typing import Any

from rich.align import Align
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from cyvest.cyvest import Cyvest
from cyvest.levels import Level, get_color_level, get_color_score
from cyvest.model import Observable


def display_summary(cv: Cyvest, console: Console | None = None, show_graph: bool = True) -> None:
    """
    Display a comprehensive summary of the investigation using Rich.

    Args:
        cv: Cyvest investigation to display
        console: Optional Rich console instance (creates new one if not provided)
        show_graph: Whether to display the observable graph
    """
    if console is None:
        console = Console()

    # Create main table
    table = Table(
        title="Investigation Report",
        caption=f"Total Checks: {len(cv.get_all_checks())} | "
        f"Applied: {sum(1 for c in cv.get_all_checks().values() if c.level != Level.NONE)}",
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
        if check.scope not in checks_by_scope:
            checks_by_scope[check.scope] = []
        checks_by_scope[check.scope].append(check)

    for scope_name, checks in checks_by_scope.items():
        scope_rule = Align(f"[bold magenta]{scope_name}[/bold magenta]", align="left")
        table.add_row(scope_rule, "-", "-")

        for check in checks:
            if check.level == Level.NONE:
                continue

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
        checks = [c for c in cv.get_all_checks().values() if c.level == level_enum]
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
        ("Total Observables", stats.get("total_observables", 0)),
        ("Internal Observables", stats.get("internal_observables", 0)),
        ("External Observables", stats.get("external_observables", 0)),
        ("Whitelisted Observables", stats.get("whitelisted_observables", 0)),
        ("Total Threat Intel", stats.get("total_threat_intel", 0)),
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
    console.print(table)

    # Observable graph (if requested)
    if show_graph and cv.get_all_observables():
        console.print()
        console.print("[bold cyan]Observable Graph[/bold cyan]")

        tree = Tree("[bold]Investigation Observables[/bold]")

        def build_tree(parent_tree: Tree, obs: Observable, visited: set[str]) -> None:
            if obs.key in visited:
                return
            visited.add(obs.key)

            # Format observable info
            color_level = get_color_level(obs.level)
            color_score = get_color_score(obs.score)

            generated_by = ""
            if obs._generated_by_checks:
                checks_str = "][cyan], [/cyan][cyan]".join(obs._generated_by_checks)
                generated_by = f"[cyan][[/cyan]{checks_str}[cyan]][/cyan]"

            whitelisted_str = " [green]WHITELISTED[/green]" if obs.whitelisted else ""

            obs_info = (
                f"{generated_by} {obs.key} -> "
                f"[{color_score}]{obs.score}[/{color_score}] "
                f"[{color_level}]{obs.level.name}[/{color_level}]"
                f"{whitelisted_str}"
            )

            child_tree = parent_tree.add(obs_info)

            # Add children
            for rel in obs.relationships:
                child_obs = cv.observable_get(rel.target_key)
                if child_obs:
                    build_tree(child_tree, child_obs, visited)

        # Start from root
        root = cv.observable_get_root()
        if root:
            build_tree(tree, root, set())

        console.print(tree)


def display_statistics(cv: Cyvest, console: Console | None = None) -> None:
    """
    Display detailed statistics about the investigation.

    Args:
        cv: Cyvest investigation
        console: Optional Rich console instance
    """
    if console is None:
        console = Console()

    stats = cv.get_statistics()

    # Observable statistics table
    obs_table = Table(title="Observable Statistics")
    obs_table.add_column("Type", style="cyan")
    obs_table.add_column("Total", justify="right")
    obs_table.add_column("INFO", justify="right", style="cyan")
    obs_table.add_column("NOTABLE", justify="right", style="yellow")
    obs_table.add_column("SUSPICIOUS", justify="right", style="orange3")
    obs_table.add_column("MALICIOUS", justify="right", style="red")

    obs_by_type_level = stats.get("observables_by_type_and_level", {})
    for obs_type, count in stats.get("observables_by_type", {}).items():
        levels = obs_by_type_level.get(obs_type, {})
        obs_table.add_row(
            obs_type.upper(),
            str(count),
            str(levels.get("INFO", 0)),
            str(levels.get("NOTABLE", 0)),
            str(levels.get("SUSPICIOUS", 0)),
            str(levels.get("MALICIOUS", 0)),
        )

    console.print(obs_table)

    # Check statistics table
    console.print()
    check_table = Table(title="Check Statistics")
    check_table.add_column("Scope", style="cyan")
    check_table.add_column("Count", justify="right")

    for scope, count in stats.get("checks_by_scope", {}).items():
        check_table.add_row(scope, str(count))

    console.print(check_table)

    # Threat intel statistics
    if stats.get("total_threat_intel", 0) > 0:
        console.print()
        ti_table = Table(title="Threat Intelligence Statistics")
        ti_table.add_column("Source", style="cyan")
        ti_table.add_column("Count", justify="right")

        for source, count in stats.get("threat_intel_by_source", {}).items():
            ti_table.add_row(source, str(count))

        console.print(ti_table)
