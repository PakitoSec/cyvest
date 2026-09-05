"""
Rich rendering.

Pure display: this layer reads the report and never recomputes a value. It is also the layer
that *may* read the clock — showing that a decision is nineteen months old changes nothing to the
score, whereas letting the evaluator consult the clock would make an archived report drift.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

try:
    from logurich import get_log_levels, get_logger
except ImportError:  # pragma: no cover - logurich is a required dependency of cyvest
    _logurich_logger = None
else:
    _logurich_logger = get_logger(__name__)

from cyvest.enums import DecisionKind, Effect, Salience, Verdict
from cyvest.evaluation.projection import verdict_from_score
from cyvest.evaluation.report import CONCLUSION_BOUND_LABELS, Contribution, Report
from cyvest.evaluation.timeline import TimeBasis
from cyvest.facts.decision import decision_label
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

#: Strongest band first: a report is read to find what is wrong.
_VERDICT_ORDER: tuple[Verdict, ...] = (
    Verdict.MALICIOUS,
    Verdict.SUSPICIOUS,
    Verdict.NOTABLE,
    Verdict.INFO,
    Verdict.SAFE,
)

_DECISION_STYLES: dict[DecisionKind, str] = {
    DecisionKind.REFUTE: "bold green",
    DecisionKind.UPHOLD: "bold red",
    DecisionKind.VACATED: "bold dim",
}

#: Keyed by ``DiffStatus`` value, so the renderer stays free of a compare-time import.
_STATUS_STYLES: dict[str, str] = {"+": "green", "-": "red", "\u2717": "yellow"}


def verdict_text(verdict: Verdict) -> Text:
    return Text(verdict.value, style=VERDICT_STYLES.get(verdict, "white"))


def _score(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}"


def _score_text(value: float | None, *, bold: bool = False) -> Text:
    """A score carries its own band: reading a number against the wrong colour is the whole risk."""
    prefix = "bold " if bold else ""
    if value is None:
        return Text("—", style=f"{prefix}dim")
    style = VERDICT_STYLES.get(verdict_from_score(value), "white")
    return Text(f"{value:.2f}", style=f"{prefix}{style}")


def _applied_bound(report: Report, finding_key: str) -> float:
    for contribution in report.investigation.contributions:
        if contribution.source_key == finding_key and contribution.label.startswith(CONCLUSION_BOUND_LABELS):
            return contribution.value
    return 0.0


def _age(moment: datetime) -> str:
    """Display-only: how long ago something was decided. Never touches a score."""
    months = (datetime.now(timezone.utc) - moment).days // 30
    if months >= 24:
        return f"{months // 12} years ago"
    if months >= 1:
        return f"{months} months ago"
    return "recently"


def _decision_badges(investigation: Investigation, key: str) -> Text:
    badge = Text()
    decision = investigation.get_decision(key)
    if decision is None:
        return badge
    badge.append(" ")
    badge.append(
        f"[{decision_label(decision)}]",
        style=_DECISION_STYLES.get(decision.kind, "bold red"),
    )
    when = decision.occurred_at or decision.asserted_at
    badge.append(f" {decision.source.name} · {_age(when)}", style="dim")
    badge.append(f" \u201c{decision.justification}\u201d", style="dim italic")
    return badge


def build_summary(
    investigation: Investigation,
    *,
    show_graph: bool = True,
    show_observables: bool = False,
    show_rule_ids: bool = True,
) -> Group:
    """
    One table, read top to bottom, ending on the number that matters.

    Findings are grouped by verdict rather than listed by key: an analyst reads a report to find
    what is wrong, and alphabetical order buries the one malicious rule under forty benign ones.

    Every finding is listed. A rule that has nothing to say must not assert a finding in the first
    place; hiding one at render time would only paper over a rule that should never have fired.
    Observables stay out by default: they are the *inputs*, and they do not belong between the
    analyst and the global score.
    """
    report = investigation.report
    header = investigation.store.header

    title = Text(header.name or header.investigation_id, style="bold")
    title.append("  ")
    title.append_text(_score_text(report.investigation.score, bold=True))
    title.append("  ")
    title.append(verdict_text(report.investigation.verdict))
    # The engine id always travels with the score: comparing scores across engines is meaningless.
    title.append(f"   [{report.engine_id} · {report.policy_version}]", style="dim")

    table = Table(title="Investigation Report", expand=True, show_lines=False)
    table.add_column("Name", overflow="fold", ratio=1)
    # Sized to their content: `SUSPICIOUS` truncated to `SUSPIC…` is the one thing a verdict
    # column must never do.
    table.add_column("Score", justify="right", no_wrap=True, min_width=7)
    table.add_column("Verdict", no_wrap=True, min_width=10)

    displayed, counted = _add_findings(table, investigation, report, show_rule_ids=show_rule_ids)
    _add_tags(table, investigation)
    _add_evidences(table, investigation)
    if show_observables:
        _add_observables(table, investigation, report)
    _add_statistics(table, investigation)

    table.add_section()
    table.add_row(
        Text("GLOBAL SCORE", style="bold"),
        _score_text(report.investigation.score, bold=True),
        verdict_text(report.investigation.verdict),
    )

    caption = f"Total findings: {displayed}"
    caption += f" | Counted: {counted} | Confidence: {report.investigation.confidence:.2f}"
    table.caption = caption

    parts = [Panel(title, border_style=VERDICT_STYLES.get(report.investigation.verdict, "white")), table]
    if show_graph:
        parts.append(build_graph(investigation))
    return Group(*parts)


def _section(table: Table, label: str) -> None:
    table.add_section()
    table.add_row(Text(label, style="bold cyan", justify="center"), "", "")


def _row(label: Text) -> Padding:
    """Indent through padding, not spaces, so a folded long name keeps its indent."""
    return Padding(label, (0, 0, 0, 2))


def _finding_notes(investigation: Investigation, report: Report, key: str) -> Text:
    finding = investigation.get_finding(key)
    result = report.finding(key)
    notes = _decision_badges(investigation, key)
    if result is not None and result.own_term_suppressed:
        notes.append(" · outweighed by an observable", style="dim italic")
    if finding is not None and finding.effect.concludes:
        applied = _applied_bound(report, key)
        notes.append(
            f" · conclusion {applied:+.2f} on the total" if applied else " · conclusion, verdict already reached",
            style="dim italic",
        )
    if result is not None and not result.counted:
        notes.append(f" · not counted ({result.status.value})", style="dim italic")
    return notes


def _add_findings(
    table: Table,
    investigation: Investigation,
    report: Report,
    *,
    show_rule_ids: bool = True,
) -> tuple[int, int]:
    """Group by verdict, strongest band first; returns (displayed, counted)."""
    by_verdict: dict[Verdict, list[tuple[str, str]]] = {verdict: [] for verdict in _VERDICT_ORDER}
    counted = 0
    for key, finding in investigation.get_all_findings().items():
        result = report.finding(key)
        if result is None:
            continue
        counted += 1 if result.counted else 0
        label = finding.rule_id if show_rule_ids else (finding.name or finding.rule_id)
        by_verdict.setdefault(result.verdict, []).append((label, key))

    displayed = sum(len(rows) for rows in by_verdict.values())
    _section(table, f"FINDINGS: {displayed} findings")

    for verdict in _VERDICT_ORDER:
        rows = by_verdict.get(verdict) or []
        if not rows:
            continue
        table.add_row(
            Text(f"{verdict.value}: {len(rows)} finding(s)", style=VERDICT_STYLES[verdict], justify="center"),
            "",
            "",
        )
        for name, key in sorted(rows):
            result = report.finding(key)
            label = Text(name)
            label.append_text(_finding_notes(investigation, report, key))
            table.add_row(_row(label), _score_text(result.score), verdict_text(result.verdict))
    return displayed, counted


def _add_tags(table: Table, investigation: Investigation) -> None:
    tags = investigation.get_all_tags()
    if not tags:
        return
    _section(table, f"TAGS: {len(tags)} tags")
    for tag in sorted(tags.values(), key=lambda item: item.name):
        score = investigation.get_tag_aggregated_score(tag.name)
        table.add_row(
            _row(Text(tag.name)),
            _score_text(score),
            verdict_text(investigation.get_tag_aggregated_verdict(tag.name)),
        )


def _add_evidences(table: Table, investigation: Investigation) -> None:
    evidences = investigation.get_all_evidences()
    if not evidences:
        return
    _section(table, f"EVIDENCES: {len(evidences)} evidences")
    for evidence in sorted(evidences.values(), key=lambda item: (item.evidence_type, item.external_id or item.key)):
        label = Text(evidence.external_id or evidence.key)
        label.append(f"  ({evidence.evidence_type})", style="dim")
        table.add_row(_row(label), "—", "—")


def _add_observables(table: Table, investigation: Investigation, report: Report) -> None:
    observables = {
        key: observable
        for key, observable in investigation.get_all_observables().items()
        if key != investigation.store.header.root_key
    }
    if not observables:
        return
    _section(table, f"OBSERVABLES: {len(observables)} observables")
    for key, observable in sorted(observables.items(), key=lambda item: (str(item[1].obs_type), item[1].value)):
        result = report.observable(key)
        label = Text(f"{observable.obs_type} {observable.value}")
        label.append_text(_decision_badges(investigation, key))
        table.add_row(
            _row(label),
            _score_text(result.score if result else None),
            verdict_text(result.verdict if result else Verdict.INFO),
        )


def _add_statistics(table: Table, investigation: Investigation) -> None:
    stats = InvestigationStats(investigation.store, investigation.report).get_summary()
    _section(table, "STATISTICS")
    rows = (
        ("Total Observables", stats.total_observables),
        ("Internal Observables", stats.internal_observables),
        ("External Observables", stats.external_observables),
        ("Allowlisted Observables", stats.allowlisted_observables),
        ("Total Threat Intel", stats.total_signals),
        ("Total Relations", stats.total_relations),
        ("Total Decisions", stats.total_decisions),
    )
    for label, value in rows:
        table.add_row(_row(Text(label)), str(value), "—")


def build_graph(investigation: Investigation) -> Tree:
    """Walk down from the root; ``source_key`` is the parent, so no direction to interpret."""
    header = investigation.store.header
    report = investigation.report

    # A node is read to find out which rule fired on it, so the findings travel with it.
    linked_findings: dict[str, list[str]] = {}
    for key, finding in investigation.get_all_findings().items():
        for link in finding.observable_links:
            linked_findings.setdefault(link.observable_key, []).append(key)

    def label(key: str) -> Text:
        observable = investigation.get_observable(key)
        result = report.observable(key)
        text = Text()
        findings = linked_findings.get(key)
        if findings:
            text.append(f"[{', '.join(sorted(findings))}] ", style="cyan")
        if observable is not None:
            text.append(f"{observable.obs_type} {observable.value}")
        else:
            text.append(key)
        if result is not None:
            text.append("  ")
            text.append_text(_score_text(result.score))
            text.append(" ")
            text.append_text(verdict_text(result.verdict))
        text.append_text(_decision_badges(investigation, key))
        return text

    def walk(key: str, node: Tree, seen: set[str]) -> None:
        for signal in investigation.store.signals_for(key):
            taxonomies = getattr(signal, "taxonomies", ())
            if not taxonomies:
                continue
            source = Text(f"{signal.source.name} · taxonomies", style="magenta")
            branch = node.add(source)
            for taxonomy in taxonomies:
                entry = verdict_text(taxonomy.verdict)
                entry.append(f" {taxonomy.name}: {taxonomy.value}", style="white")
                branch.add(entry)
        for relation in investigation.store.child_relations(key):
            if relation.target_key in seen:
                continue
            seen.add(relation.target_key)
            # Base style of a Text bleeds onto everything appended to it: keep it unset.
            child_label = Text()
            child_label.append(f"{relation.kind.value} \u2192 ", style="dim")
            child_label.append_text(label(relation.target_key))
            walk(relation.target_key, node.add(child_label), seen)

    root_key = header.root_key
    if not root_key:
        return Tree(Text("investigation", style="bold"))
    tree = Tree(label(root_key))
    walk(root_key, tree, {root_key})
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


def build_timeline(
    investigation: Investigation,
    *,
    time: TimeBasis = "occurred",
    since: datetime | None = None,
    until: datetime | None = None,
    entity_key: str | None = None,
    min_salience: Salience = Salience.NOTABLE,
    track_verdict_changes: bool = False,
) -> Table:
    table = Table(title="Timeline", expand=True, title_justify="left")
    table.add_column("When")
    table.add_column("Kind")
    table.add_column("Title", overflow="fold")
    table.add_column("Tactic")
    table.add_column("Salience")

    entries = investigation.timeline(
        time=time,
        since=since,
        until=until,
        entity_key=entity_key,
        min_salience=min_salience,
        track_verdict_changes=track_verdict_changes,
    )
    for entry in entries:
        # On the occurred axis an undated fact sits at its assertion time: say so rather than pass it off.
        when = entry.when.strftime("%Y-%m-%d %H:%M")
        when_text = Text(when) if entry.dated or time == "asserted" else Text(f"{when} (asserted)", style="dim")
        table.add_row(
            when_text,
            entry.kind,
            entry.title,
            entry.tactic.value if entry.tactic is not None else "",
            Text(entry.salience.value, style="bold" if entry.salience.value == "key" else "dim"),
        )
    return table


def build_diff(diffs: Sequence[DiffItem], *, title: str = "Investigation diff") -> Table:
    """
    Render a comparison as a tree: each finding, then what it links, then what asserted it.

    A bare score tells you *that* something moved; the observables and signals beneath it tell
    you *why*, which is the only thing a diff is read for. They are listed whether they moved or
    not — a branch that held still is what locates the one that did.

    An empty diff still produces a table, saying so.
    """
    counts = Counter(item.status.value for item in diffs)
    mismatched = counts["\u2717"]
    table = Table(
        title=title,
        caption=(
            f"[green]+ {counts['+']}[/green] added | "
            f"[red]- {counts['-']}[/red] removed | "
            f"[yellow]\u2717 {mismatched}[/yellow] mismatch"
        ),
    )
    table.add_column("Key")
    table.add_column("Expected", justify="center")
    table.add_column("Actual", justify="center")
    table.add_column("Status", justify="center", width=8)

    if not diffs:
        table.add_row(Text("no difference", style="green"), "", "", "")
        return table

    for index, item in enumerate(diffs):
        if index:
            table.add_section()
        expected = _verdict_score(item.expected_verdict, item.expected_score, item.expected_score_rule)
        actual = _verdict_score(item.actual_verdict, item.actual_score)
        # Only worth the width when an effect was expected *and* is what differs.
        expected_effect = item.expected_effect_rule or item.expected_effect
        if expected_effect is not None and expected_effect is not item.actual_effect:
            _append_effect(expected, expected_effect)
            _append_effect(actual, item.actual_effect)
        table.add_row(
            Text(item.rule_id or item.key),
            expected,
            actual,
            Text(item.status.value, style=_STATUS_STYLES.get(item.status.value, "white")),
        )
        _add_observable_rows(table, item)
    return table


def _add_observable_rows(table: Table, item: DiffItem) -> None:
    elbow, tee, pipe = "\u2514\u2500\u2500 ", "\u251c\u2500\u2500 ", "\u2502   "
    for obs_index, observable in enumerate(item.observable_diffs):
        last_obs = obs_index == len(item.observable_diffs) - 1
        label = Text(elbow if last_obs else tee)
        label.append(observable.value or observable.observable_key, style="cyan")
        table.add_row(
            label,
            _verdict_score(observable.expected_verdict, observable.expected_score),
            _verdict_score(observable.actual_verdict, observable.actual_score),
            "",
        )
        for signal_index, signal in enumerate(observable.signal_diffs):
            last_signal = signal_index == len(observable.signal_diffs) - 1
            source = Text(("    " if last_obs else pipe) + (elbow if last_signal else tee))
            source.append(signal.source, style="magenta")
            table.add_row(
                source,
                _verdict_score(signal.expected_verdict, signal.expected_score),
                _verdict_score(signal.actual_verdict, signal.actual_score),
                "",
            )


def _verdict_score(verdict: Verdict | None, score: float | None, score_rule: str | None = None) -> Text:
    """Verdict then magnitude, the way a band is read: what it means before how much."""
    text = Text()
    if verdict is not None:
        text.append(verdict.value, style=VERDICT_STYLES.get(verdict, "white"))
    tail = score_rule or (None if score is None else f"{score:.2f}")
    if tail:
        if len(text):
            text.append(" ")
        text.append(tail)
    return text if len(text) else Text("-", style="dim")


def _append_effect(text: Text, effect: Effect | None) -> None:
    if effect is not None:
        text.append(f" \u00b7 {effect.value.lower()}", style="dim")


def display_diff(
    diffs: Sequence[DiffItem],
    printer: Callable[[object], None] | None = None,
    *,
    title: str = "Investigation diff",
) -> None:
    """Print a diff, either to a console or through a caller-supplied printer (a logger, typically)."""
    emit(build_diff(diffs, title=title), printer)


def emit(renderable: object, printer: Callable[[object], None] | None = None) -> None:
    """Print through the active logurich logger, an explicit printer, or a console."""
    if printer is not None:
        printer(renderable)
    elif _logurich_logger is not None and _logurich_is_configured():
        _logurich_logger.rich("INFO", renderable, width=150)
    else:
        print_renderable(renderable)


def _logurich_is_configured() -> bool:
    """Use logurich only after the application has explicitly initialized it."""
    try:
        get_log_levels()
    except RuntimeError:
        return False
    return True


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
    "emit",
    "print_renderable",
    "verdict_text",
]
