"""
Rich rendering.

Pure display: this layer reads the report and never recomputes a value. It is also the layer
that *may* read the clock — showing that a decision is nineteen months old changes nothing to the
score, whereas letting the evaluator consult the clock would make an archived report drift.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from cyvest.enums import DecisionKind, Effect, Status, Verdict
from cyvest.evaluation.report import Contribution, Report
from cyvest.stats import InvestigationStats

if TYPE_CHECKING:
    from cyvest.compare import DiffItem
    from cyvest.investigation import Investigation

VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.SAFE: "bright_green",
    Verdict.INFO: "cyan",
    Verdict.NOTABLE: "yellow",
    Verdict.SUSPICIOUS: "dark_orange",
    Verdict.MALICIOUS: "red",
}

DECISION_LABELS: dict[DecisionKind, str] = {
    DecisionKind.ALLOWLISTED: "ALLOWLISTED",
    DecisionKind.BLOCKLISTED: "BLOCKLISTED",
    DecisionKind.CONFIRMED: "CONFIRMED",
    DecisionKind.DISMISSED: "DISMISSED",
}


def verdict_text(verdict: Verdict) -> Text:
    return Text(verdict.value, style=VERDICT_STYLES.get(verdict, "white"))


def _score(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}"


def _applied_floor(report: Report, finding_key: str) -> float:
    for contribution in report.investigation.contributions:
        if contribution.source_key == finding_key and contribution.label.startswith("conclusion floor"):
            return contribution.value
    return 0.0


def _age(moment: datetime) -> str:
    """Display-only: how long ago something was decided. Never touches a score."""
    months = (datetime.now(UTC) - moment).days // 30
    if months >= 24:
        return f"il y a {months // 12} ans"
    if months >= 1:
        return f"il y a {months} mois"
    return "récemment"


def _decision_badges(investigation: Investigation, key: str) -> Text:
    badge = Text()
    for decision in investigation.get_decisions(key):
        badge.append(" ")
        badge.append(
            f"[{DECISION_LABELS[decision.kind]}]",
            style="bold green" if decision.kind in (DecisionKind.ALLOWLISTED, DecisionKind.DISMISSED) else "bold red",
        )
        when = decision.occurred_at or decision.asserted_at
        badge.append(f" {decision.source.name} · {_age(when)}", style="dim")
        if decision.justification:
            badge.append(f" « {decision.justification} »", style="dim italic")
    return badge


def build_summary(investigation: Investigation, *, show_graph: bool = False) -> Group:
    report = investigation.report
    header = investigation.store.header

    title = Text(header.name or header.investigation_id, style="bold")
    title.append("  ")
    title.append(_score(report.investigation.score), style="bold")
    title.append("  ")
    title.append(verdict_text(report.investigation.verdict))
    # The engine id always travels with the score: comparing scores across engines is meaningless.
    title.append(f"   [{report.engine_id} · {report.policy_version}]", style="dim")

    findings = Table(title="Findings", expand=True, title_justify="left")
    findings.add_column("Rule")
    findings.add_column("Score", justify="right")
    findings.add_column("Verdict")
    findings.add_column("Conf.", justify="right")
    findings.add_column("Status")
    findings.add_column("")

    for key, finding in sorted(investigation.get_all_findings().items()):
        result = report.finding(key)
        if result is None:
            continue
        notes = _decision_badges(investigation, key)
        if result.own_term_suppressed:
            notes.append(" contredit par un observable", style="dim italic")
        if finding.effect is Effect.FLOOR:
            applied = _applied_floor(report, key)
            note = f" conclusion · +{applied:.2f} sur le total" if applied > 0 else " conclusion · verdict déjà atteint"
            notes.append(note, style="dim italic")
        findings.add_row(
            finding.name or finding.rule_id,
            _score(result.score),
            verdict_text(result.verdict),
            f"{result.confidence:.2f}",
            Text(result.status.value, style="dim" if result.status is not Status.EVALUATED else ""),
            notes,
        )

    observables = Table(title="Observables", expand=True, title_justify="left")
    observables.add_column("Type")
    observables.add_column("Value", overflow="fold")
    observables.add_column("Score", justify="right")
    observables.add_column("Verdict")
    observables.add_column("")

    for key, observable in sorted(investigation.get_all_observables().items()):
        if key == header.root_key:
            continue
        result = report.observable(key)
        observables.add_row(
            str(observable.obs_type),
            observable.value,
            _score(result.score if result else None),
            verdict_text(result.verdict if result else Verdict.INFO),
            _decision_badges(investigation, key),
        )

    parts = [
        Panel(title, border_style=VERDICT_STYLES.get(report.investigation.verdict, "white")),
        findings,
        observables,
    ]
    if show_graph:
        parts.append(build_graph(investigation))
    return Group(*parts)


def build_graph(investigation: Investigation) -> Tree:
    """Walk down from the root; ``source_key`` is the parent, so no direction to interpret."""
    header = investigation.store.header
    report = investigation.report
    tree = Tree(Text("investigation", style="bold"))

    def label(key: str) -> Text:
        observable = investigation.get_observable(key)
        result = report.observable(key)
        text = Text(f"{observable.obs_type} ", style="dim") if observable else Text()
        text.append(observable.value if observable else key)
        if result is not None:
            text.append(f"  {_score(result.score)} ", style="dim")
            text.append(verdict_text(result.verdict))
        return text

    def walk(key: str, node: Tree, seen: set[str]) -> None:
        for relation in investigation.store.child_relations(key):
            if relation.target_key in seen:
                continue
            seen.add(relation.target_key)
            child = node.add(label(relation.target_key))
            child.label.append(f"  ({relation.kind.value})", style="dim italic")
            walk(relation.target_key, child, seen)

    if header.root_key:
        walk(header.root_key, tree, {header.root_key})
    return tree


def build_statistics(investigation: Investigation) -> Table:
    stats = InvestigationStats(investigation.store, investigation.report).get_summary()
    table = Table(title="Statistics", expand=True, title_justify="left")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    rows = [
        ("Observables", stats.total_observables),
        ("  internal", stats.internal_observables),
        ("  allowlisted", stats.allowlisted_observables),
        ("Relations", stats.total_relations),
        ("Signals", stats.total_signals),
        ("Evidences", stats.total_evidences),
        ("Findings", stats.total_findings),
        ("  counted", stats.evaluated_findings),
        ("Decisions", stats.total_decisions),
        ("Tags", stats.total_tags),
    ]
    for label, value in rows:
        table.add_row(label, str(value))
    return table


def build_explanation(investigation: Investigation, key: str) -> Table:
    """Show what moved the needle — including the terms that were overridden."""
    table = Table(title=f"Explanation · {key}", expand=True, title_justify="left")
    table.add_column("Contribution")
    table.add_column("Value", justify="right")
    table.add_column("Retained")
    table.add_column("Detail", overflow="fold")

    contributions: tuple[Contribution, ...] = investigation.explain(key)
    for contribution in contributions:
        table.add_row(
            contribution.label,
            f"{contribution.value:.2f}",
            Text("yes", style="green") if contribution.retained else Text("no", style="dim"),
            contribution.detail,
        )
    return table


def build_timeline(investigation: Investigation, **kwargs: object) -> Table:
    table = Table(title="Timeline", expand=True, title_justify="left")
    table.add_column("When")
    table.add_column("Kind")
    table.add_column("Title", overflow="fold")
    table.add_column("Salience")

    for entry in investigation.timeline(**kwargs):
        table.add_row(
            entry.when.strftime("%Y-%m-%d %H:%M"),
            entry.kind,
            entry.title,
            Text(entry.salience.value, style="bold" if entry.salience.value == "key" else "dim"),
        )
    return table


def build_diff(diffs: Sequence[DiffItem], *, title: str = "Investigation diff") -> Table:
    """Render a comparison as a table. An empty diff still produces a table, saying so."""
    table = Table(title=title, show_lines=False)
    table.add_column("", width=2)
    table.add_column("Finding")
    table.add_column("Expected")
    table.add_column("Actual")
    table.add_column("Observables")

    if not diffs:
        table.add_row("", Text("no difference", style="green"), "", "", "")
        return table

    for item in diffs:
        style = {"+": "green", "-": "red", "\u2717": "yellow"}[item.status.value]
        expected = item.expected_score_rule or _score_verdict(item.expected_score, item.expected_verdict)
        if item.expected_score_rule and item.expected_verdict:
            expected = f"{item.expected_score_rule} / {item.expected_verdict.value}"
        table.add_row(
            Text(item.status.value, style=style),
            item.rule_id or item.key,
            expected,
            _score_verdict(item.actual_score, item.actual_verdict),
            "\n".join(
                f"{diff.value or diff.observable_key}: "
                f"{_score_verdict(diff.expected_score, diff.expected_verdict)} \u2192 "
                f"{_score_verdict(diff.actual_score, diff.actual_verdict)}"
                for diff in item.observable_diffs
            ),
        )
    return table


def _score_verdict(score: float | None, verdict: Verdict | None) -> str:
    if score is None and verdict is None:
        return "\u2014"
    parts = []
    if score is not None:
        parts.append(f"{score:g}")
    if verdict is not None:
        parts.append(verdict.value)
    return " / ".join(parts)


def display_diff(
    diffs: Sequence[DiffItem],
    printer: Callable[[object], None] | None = None,
    *,
    title: str = "Investigation diff",
) -> None:
    """Print a diff, either to a console or through a caller-supplied printer (a logger, typically)."""
    table = build_diff(diffs, title=title)
    if printer is not None:
        printer(table)
    else:
        print_renderable(table)


def print_renderable(renderable: object, console: Console | None = None) -> None:
    (console or Console()).print(renderable)


__all__ = [
    "VERDICT_STYLES",
    "build_diff",
    "build_explanation",
    "build_graph",
    "build_statistics",
    "build_summary",
    "build_timeline",
    "display_diff",
    "print_renderable",
    "verdict_text",
]
