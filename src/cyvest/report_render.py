from __future__ import annotations

import math
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from logurich import logger
from rich.align import Align
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from .models import get_color_level, get_color_score

if TYPE_CHECKING:
    from .visitors import Report


def _log_rich(level: str, renderable: Any) -> None:
    logger.rich(level, renderable)


def _to_stdout_check(check: dict[str, Any], *, indent: int = 0, short_name: bool = False) -> list[str] | None:
    level = check["level"]
    if level == "NONE":
        return None
    score = check["score"]
    color_level = get_color_level(level)
    color_score = get_color_score(score)
    space = indent * " "
    name = check["short_key"] if short_name else check["full_key"]
    return [f"{space}{name}", f"[{color_score}]{score}[/{color_score}]", f"[{color_level}]{level}[/{color_level}]"]


def _to_stdout_rec_checks(contained: dict[str, Any], *, indent: int = 0) -> list[list[str]]:
    rows: list[list[str]] = []
    for value in contained.values():
        values = value if isinstance(value, list) else [value]
        for entry in values:
            is_container = "container" in entry
            row = _to_stdout_check(entry, indent=indent, short_name=not is_container)
            if row:
                rows.append(row)
            if is_container:
                rows.extend(_to_stdout_rec_checks(entry["container"], indent=indent + 1))
    return rows


def _to_stdout_rec_obs(tree: Tree, obs: dict[str, Any], *, indent: int = 0) -> None:
    level = obs["level"]
    score = obs["score"]
    generates_by_checks = (
        "[cyan][[/cyan]" + "[cyan]][/cyan],[cyan][[/cyan]".join(obs["generated_by"]) + "[cyan]][/cyan]"
        if obs["generated_by"]
        else ""
    )
    color_level = get_color_level(level)
    color_score = get_color_score(score)
    more_detail = " [green]WHITELISTED[/green]" if obs["whitelisted"] is True else ""
    full_key = obs["full_key"]
    data = (
        f"{generates_by_checks} {full_key} -> "
        f"[{color_score}]{score}[/{color_score}] [{color_level}]{level}[/{color_level}] {more_detail}"
    )
    child_tree = tree.add(data)
    for child in obs["observables_children"]:
        _to_stdout_rec_obs(child_tree, child, indent=indent + 1)


def _get_check(full_key: str, json_data: dict[str, Any]) -> dict[str, Any] | None:
    root = json_data["checks"]
    match = re.match(r"^([^\.]+)\.(.*)", full_key)
    if match is None:
        return None
    scope = match.group(1)
    root = root.get(scope, {})
    current_path = match.group(2)
    while current_path:
        match = re.match(r"^(([^\#\.]+)(\#[^\#]+\#)?)\.?(.*)", current_path)
        if not match:
            logger.error("Impossible to match full key pattern {}", full_key)
            return None
        current_path = match.group(2)
        if match.group(3):
            identifier = match.group(3).strip("#")
            root = root.get(current_path, [])
            root = next((x for x in root if x["identifier"] == identifier), None)
            if root is None:
                return None
        else:
            root = root.get(current_path, {})
        if "container" in root:
            root = root.get("container", {})
        current_path = match.group(4)
    return root


def stdout_from_json(report: Report, json_data: dict[str, Any]) -> None:
    logger.info("[cyan]### JSON CONSOLE REPORT[/cyan]")
    checks = json_data["stats_checks"]["checks"]
    applied = json_data["stats_checks"]["applied"]
    table_report = Table(
        title="Report",
        caption=f"RESULT CHECKS: {checks} - APPLIED: {applied}",
    )
    table_report.add_column("Name")
    table_report.add_column("Score", justify="right")
    table_report.add_column("Level", justify="center")

    rule = Rule("[bold magenta]CHECKS[/bold magenta]")
    table_report.add_row(rule, "-", "-")
    for scope_name, checks in json_data["checks"].items():
        scope_rule = Align(f"[bold magenta]{scope_name}[/bold magenta]", align="left")
        table_report.add_row(scope_rule, "-", "-")
        rows = _to_stdout_rec_checks(checks, indent=1)
        for row in rows:
            table_report.add_row(*row)

    if report.graph:
        tree = Tree("Observables Graph")
        logger.info("[magenta]GRAPH: {}[/magenta]", len(json_data["graph"]))
        for obs in json_data["graph"]:
            _to_stdout_rec_obs(tree, obs)
        _log_rich("INFO", tree)

    table_report.add_section()
    rule = Rule("[bold magenta]BY LEVEL[/bold magenta]")
    table_report.add_row(rule, "-", "-")
    for level_name, list_checks in json_data["checks_by_level"].items():
        color_level = get_color_level(level_name)
        level_rule = Align(
            f"[bold {color_level}]{level_name}: {len(list_checks)} check(s)[/bold {color_level}]",
            align="center",
        )
        table_report.add_row(level_rule, "-", "-")
        for check_full_key in list_checks:
            check = _get_check(check_full_key, json_data)
            if check:
                row = _to_stdout_check(check)
                if row:
                    table_report.add_row(*row)

    table_report.add_section()
    enrichment_rule = Rule(f"[bold magenta]ENRICHMENTS[/bold magenta]: {len(report.enrichments)} enrichments")
    table_report.add_row(enrichment_rule, "-", "-")
    for enrichment in report.enrichments:
        table_report.add_row(str(enrichment), "-", "-")

    table_report.add_section()
    stats_rule = Rule("[bold magenta]STATISTICS[/bold magenta]")
    table_report.add_row(stats_rule, "-", "-")
    for stat_name, stat_value in json_data["stats"].items():
        table_report.add_row(" ".join(stat_name.split("_")).title(), str(stat_value), "-")

    global_level = json_data["level"]
    global_score = json_data["score"]
    color_level = get_color_level(global_level)
    color_score = get_color_score(global_score)
    table_report.add_section()
    table_report.add_row(
        Align("[bold]GLOBAL SCORE[/bold]", align="center"),
        f"[{color_score}]{global_score}[/{color_score}]",
        f"[{color_level}]{global_level}[/{color_level}]",
    )
    _log_rich("INFO", table_report)


def markdown_summary(json_data: dict[str, Any], *, exclude_checks: list[str] | None = None) -> str:
    def _first(keys: Iterable[str], src: dict[str, Any], default: Any | None = None) -> Any | None:
        for key in keys:
            if key in src and src[key] not in (None, ""):
                return src[key]
        return default

    def _result_of(check: dict[str, Any]) -> str:
        value = _first(("result", "status", "outcome"), check)
        if value is not None:
            return str(value)
        if isinstance(check.get("passed"), bool):
            return "PASS" if check["passed"] else "FAIL"
        if isinstance(check.get("ok"), bool):
            return "OK" if check["ok"] else "NOT OK"
        return "n/a"

    def _score_of(check: dict[str, Any]) -> str:
        score_value = check.get("score")
        if score_value is None:
            return "n/a"
        if isinstance(score_value, int):
            return str(score_value)
        if isinstance(score_value, float):
            return str(int(score_value)) if score_value.is_integer() else f"{score_value:.2f}"
        return str(score_value)

    def _level_of(check: dict[str, Any]) -> str:
        level_value = _first(("level", "severity"), check, default="UNKNOWN")
        return str(level_value).upper()

    def _name_of(check: dict[str, Any], fallback_key: str) -> str:
        return str(_first(("name", "title", "id"), check, default=fallback_key))

    def _desc_of(check: dict[str, Any]) -> str:
        desc_value = _first(("description", "desc", "details", "message"), check)
        return str(desc_value).strip() if desc_value is not None else "_No description provided._"

    def _is_check_node(node: Any) -> bool:
        if not isinstance(node, dict):
            return False
        keys = ("level", "severity", "description", "result", "status", "name", "score", "passed", "ok")
        return any(key in node for key in keys)

    def _flatten_checks(
        container: Any, path: tuple[str, ...] = ()
    ) -> Iterable[tuple[str, dict[str, Any], tuple[str, ...]]]:
        if isinstance(container, dict):
            if _is_check_node(container):
                key = path[-1] if path else "check"
                yield (key, container, path)
            else:
                for key, value in container.items():
                    yield from _flatten_checks(value, path + (str(key),))
        elif isinstance(container, list):
            for idx, value in enumerate(container):
                yield from _flatten_checks(value, path + (str(idx),))

    def _order_levels(levels: Iterable[str]) -> list[str]:
        priority: dict[str, int] = {
            "MALICIOUS": 0,
            "SUSPICIOUS": 1,
            "NOTABLE": 2,
            "INFO": 3,
            "SAFE": 4,
        }
        return sorted(set(levels), key=lambda level: priority.get(level, 999))

    global_level = str(json_data.get("level", "UNKNOWN")).upper()
    global_score = json_data.get("score", "n/a")
    if isinstance(global_score, (int, float)):
        global_score_str = (
            str(int(global_score))
            if isinstance(global_score, int) or (isinstance(global_score, float) and float(global_score).is_integer())
            else str(global_score)
        )
    else:
        global_score_str = str(global_score)

    raw_checks_root = json_data.get("checks") or {}
    flattened = list(_flatten_checks(raw_checks_root))

    groups: dict[str, list[tuple[str, dict[str, Any], tuple[str, ...]]]] = {}
    for key, check, path in flattened:
        level = _level_of(check)
        groups.setdefault(level, []).append((key, check, path))

    ordered_levels = _order_levels(groups.keys())
    md: list[str] = []
    md.append("# Report Summary")
    md.append("")
    md.append(f"**Global Score:** `{global_score_str}`  |  **Global Level:** {global_level}")
    md.append("")

    if not flattened:
        md.append("_No checks found in the report._")
    else:
        for level in ordered_levels:
            entries = groups[level]
            md.append(f"## {level} — {len(entries)} check(s)")
            md.append("")

            def _score_key(entry: tuple[str, dict[str, Any], tuple[str, ...]]) -> float:
                score_raw = entry[1].get("score")
                try:
                    return -float(score_raw) if score_raw is not None else math.inf
                except Exception:
                    return math.inf

            entries_sorted = sorted(
                entries,
                key=lambda entry: (_score_key(entry), _name_of(entry[1], entry[0]).lower()),
            )

            for key, check, path in entries_sorted:
                name = _name_of(check, key)
                if exclude_checks and name in exclude_checks:
                    continue
                result = _result_of(check)
                score_value = _score_of(check)
                desc = _desc_of(check)
                scope = " › ".join(path[:-1]) if len(path) > 1 else (path[0] if path else "")
                scope_note = f" _(scope: `{scope}`)_" if scope else ""
                comment = None
                details = check.get("details", {})
                if details:
                    comment = details.get("comment")

                md.append(f"- **{name}**{scope_note}")
                md.append(f"  - Level: {_level_of(check)}")
                md.append(f"  - Result: `{result}`")
                md.append(f"  - Score: `{score_value}`")
                md.append(f"  - Description: {desc}")
                if comment:
                    md.append(f"  - Note: {comment}")
            md.append("")

    return "\n".join(md)
